import type { IDBPDatabase } from 'idb';
import type { LocalDbSchema, PendingOutboxRecord } from '../storage/schema';
import type { QueueMessageInput } from './engine';
import type { SendMessageRequest } from '../../shared/contracts/messages';
// Server-readable HTTPS/WSS transport; local outbox/cache remain encrypted.
import {loadSendKeyContext} from './send-context';
import {encryptRetryMaterial,decryptRetryMaterial} from '../storage/retry-material';
import {sealMessageCacheRecord,outgoingCacheKey,incomingCacheKey,putCursorInTransaction} from '../storage/message-cache';
import {frameAuthenticatedMessageContent,validateMessageSemantics} from '../chat/content';
import {parseSenderSequenceState,senderSequenceSettingKey} from '../storage/sender-sequence';
import {bytesToBase64Url,base64UrlToBytes} from './local-state/base64url';
import {openLocalDatabase} from '../storage/db';
const LOCAL='server-local-v1',WIRE='server-sqlite-v1';
const preparedWire=new Map<string, SendMessageRequest>();
export async function queueServerMessages(db: IDBPDatabase<LocalDbSchema>, userId: string, deviceId: string, inputs: QueueMessageInput[]): Promise<PendingOutboxRecord[]>{
 if(inputs.length===0)return [];
 if(inputs.some(input=>input.chat_id!==inputs[0]!.chat_id))throw Error('Mixed chat batch');
 const {masterKey}=await loadSendKeyContext(db,deviceId);
 const rows: {record:PendingOutboxRecord;cache?: Awaited<ReturnType<typeof sealMessageCacheRecord>>;wirePlain?: string}[]=await Promise.all(inputs.map(async input=>{
  if(!input.plaintext)throw Error('requires explicit payload');
  const existing=await db.get('pending_outbox',input.client_message_id);
  if(existing)return {record:existing};
  const plain=frameAuthenticatedMessageContent(input.plaintext,{...input,sender_user_id:userId,sender_device_id:deviceId});
  const now=new Date().toISOString();
  const [encrypted,cache]=await Promise.all([
   encryptRetryMaterial(masterKey,{chat_id:input.chat_id,sender_device_id:deviceId,client_message_id:input.client_message_id},plain),
   sealMessageCacheRecord(masterKey,input.chat_id,outgoingCacheKey(input.client_message_id),{direction:'OUTGOING',message_id:null,client_message_id:input.client_message_id,sender_user_id:userId,sender_device_id:deviceId,created_at:now,revision:0,mutation:input.mutation??null,reply_to_message_id:input.reply_to_message_id??null},plain)
  ]);
  return {cache,wirePlain:bytesToBase64Url(plain),record:{client_message_id:input.client_message_id,chat_id:input.chat_id,sender_device_id:deviceId,request:{client_message_id:input.client_message_id,envelopes:[{recipient_user_id:userId,recipient_device_id:deviceId,protocol:'secure-messaging',protocol_version:2,header:LOCAL,ciphertext:bytesToBase64Url(encrypted)}],recovery_envelopes:[],attachment_ids:input.attachment_ids??[],...(input.mutation?{mutation:input.mutation}:{}),...(input.reply_to_message_id?{reply_to_message_id:input.reply_to_message_id}:{})},encrypted_retry_material:encrypted,status:'PENDING',transport_state:'DURABLE_LOCAL',attempts:0,created_at:now,updated_at:now} satisfies PendingOutboxRecord};
 }));
 const tx=db.transaction(['settings','pending_outbox','encrypted_cache'],'readwrite');
 const key=senderSequenceSettingKey(inputs[0]!.chat_id,deviceId);
 const stored=await tx.objectStore('settings').get(key);
 const state=stored?.kind==='json'?parseSenderSequenceState(stored.value):null;
 if(!state){tx.abort();throw Error('sequence not seeded');}
 let last=state.last_allocated;
 for(const row of rows){
  if(!row.cache)continue;
  if(await tx.objectStore('pending_outbox').get(row.record.client_message_id)){tx.abort();throw Error('concurrent duplicate preparation');}
  row.record.request.sender_sequence=++last;
  await tx.objectStore('pending_outbox').put(row.record);
  await tx.objectStore('encrypted_cache').put(row.cache);
 }
 await tx.objectStore('settings').put({key,kind:'json',value:{version:1,last_allocated:last}});
 await tx.done;
 for(const row of rows)if(row.wirePlain)preparedWire.set(row.record.client_message_id,{...row.record.request,envelopes:[{...row.record.request.envelopes[0]!,header:WIRE,ciphertext:row.wirePlain}]});
 while(preparedWire.size>128)preparedWire.delete(preparedWire.keys().next().value!);
 return rows.map(row=>row.record);
}
export async function serverWireRequest(record: PendingOutboxRecord, providedDb?: IDBPDatabase<LocalDbSchema>): Promise<SendMessageRequest>{
 if(record.request.envelopes[0]?.header!==LOCAL)return record.request;
 const ready=preparedWire.get(record.client_message_id);
 if(ready){preparedWire.delete(record.client_message_id);return ready;}
 const db=providedDb??await openLocalDatabase();
 try{
  const {masterKey}=await loadSendKeyContext(db,record.sender_device_id);
  const plain=await decryptRetryMaterial(masterKey,{chat_id:record.chat_id,sender_device_id:record.sender_device_id,client_message_id:record.client_message_id},record.encrypted_retry_material!);
  return {...record.request,envelopes:[{...record.request.envelopes[0]!,header:WIRE,ciphertext:bytesToBase64Url(plain)}]};
 }finally{if(!providedDb)db.close();}
}
export async function receiveServerMessage(db: IDBPDatabase<LocalDbSchema>, masterKey: CryptoKey, input: import('./session-establishment/receive').ReceiveSecureEnvelopeInput){
 const plaintext=base64UrlToBytes(input.ciphertext);
 if(!input.delivery)throw Error('delivery metadata missing');
 const d=input.delivery;
 validateMessageSemantics(plaintext,{...d,chat_id:input.chat_id,sender_user_id:input.remote_user_id,sender_device_id:input.remote_device_id});
 const own=input.remote_user_id===input.local_user_id;
 const cache=await sealMessageCacheRecord(masterKey,input.chat_id,incomingCacheKey(d.message_id),{...d,direction:own?'OUTGOING':'INCOMING',sender_user_id:input.remote_user_id,sender_device_id:input.remote_device_id},plaintext);
 const tx=db.transaction(['encrypted_cache','settings'],'readwrite');
 await tx.objectStore('encrypted_cache').put(cache);
 if(own)await tx.objectStore('encrypted_cache').delete(outgoingCacheKey(d.client_message_id));
 await putCursorInTransaction(tx.objectStore('settings'),input.chat_id,d.revision);
 await tx.done;
 return plaintext;
}
