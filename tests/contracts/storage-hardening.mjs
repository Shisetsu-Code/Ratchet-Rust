import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,createECDH,randomBytes} from 'node:crypto';
import {readdir} from 'node:fs/promises';
import {join,resolve,dirname,basename} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {base,fixture,localSql,localRows,api,edgeHeaders} from './fixtures.mjs';

async function room(){const actor=await fixture(),chat=randomUUID(),now=new Date().toISOString();await localSql(`INSERT INTO chats(chat_id,workspace_id,created_by_user_id,owner_admin_user_id,created_at) VALUES('${chat}','${actor.workspace_id}','${actor.user_id}','${actor.user_id}','${now}');`);return{...actor,chat};}
async function seedFiles(actor,count,status,size){
  const rows=Array.from({length:count},()=>{const id=randomUUID();return `('${id}','test/${id}','${actor.user_id}','${actor.chat}','${status}',${size},'2026-01-01','2026-01-02')`;});
  await localSql('INSERT INTO attachment_uploads(file_id,object_key,owner_user_id,chat_id,status,size,created_at,expires_at) VALUES'+rows.join(',')+';');
}
async function roomDatabase(chat,operation){
  const state=resolve(process.env.RATCHET_TEST_STATE);
  assert.equal(dirname(state),resolve('.wrangler'));assert.match(basename(state),/^c-[a-f0-9]{8}$/);
  const directory=join(state,'v3','do','ratchet-rust-local-ChatRealtime'),matches=[];
  for(const name of(await readdir(directory)).filter(name=>name.endsWith('.sqlite'))){
    const path=join(directory,name),db=new DatabaseSync(path,{readOnly:true});
    try{if(db.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='chat_messages'").get()&&db.prepare('SELECT 1 FROM chat_messages WHERE chat_id=? LIMIT 1').get(chat))matches.push(path);}finally{db.close();}
  }
  assert.equal(matches.length,1,'one authoritative Durable Object belongs to the synthetic room');
  const db=new DatabaseSync(matches[0]);
  try{db.exec('PRAGMA busy_timeout=5000');return operation(db);}finally{db.close();}
}
test('attachment API counts confirmed bytes after reservation expiry',async()=>{
  const actor=await room();await seedFiles(actor,102,'COMMITTED',10*1024*1024);
  const response=await api(`/chats/${actor.chat}/attachments`,{cookie:actor.cookie,body:{file_id:randomUUID(),encrypted_size:10*1024*1024,encrypted_metadata:'opaque'}});
  assert.equal(response.status,409,JSON.stringify(response.value));assert.equal(response.value.type,'ATTACHMENT_QUOTA_EXCEEDED');
});
test('attachment API keeps aborted physical resources charged until cleanup',async()=>{
  const actor=await room();await seedFiles(actor,16,'ABORTED',32);
  const response=await api(`/chats/${actor.chat}/attachments`,{cookie:actor.cookie,body:{file_id:randomUUID(),encrypted_size:32,encrypted_metadata:'opaque'}});
  assert.equal(response.status,409,JSON.stringify(response.value));assert.equal(response.value.type,'ATTACHMENT_QUOTA_EXCEEDED');
});
test('multipart parts cannot exceed the bytes charged by their reservation',async()=>{
  const actor=await room(),id=randomUUID();
  const reserved=await api(`/chats/${actor.chat}/attachments`,{cookie:actor.cookie,body:{file_id:id,encrypted_size:32,encrypted_metadata:'opaque'}});
  assert.equal(reserved.status,201,JSON.stringify(reserved.value));
  async function part(number,size){return fetch(`${base}/api/v1/attachments/${id}/parts/${number}`,{method:'PUT',headers:{Origin:base,...edgeHeaders,Cookie:actor.cookie,'X-Encrypted-Part-Size':String(size)},body:randomBytes(size)});}
  const oversized=await part(1,64);assert.equal(oversized.status,409,await oversized.clone().text());assert.equal((await oversized.json()).type,'ATTACHMENT_PART_SIZE_INVALID');
  const unexpected=await part(2,32);assert.equal(unexpected.status,409,await unexpected.clone().text());
  const valid=await part(1,32);assert.equal(valid.status,200,await valid.clone().text());
  const stored=await localRows(`SELECT size FROM attachment_parts WHERE file_id='${id}'`);assert.deepEqual(stored.map(row=>row.size),[32]);
});
test('wallpaper upload admission counts retired versions awaiting deletion',async()=>{
  const actor=await room();
  const rows=Array.from({length:8},()=>{const id=randomUUID();return `('test/${id}','${actor.workspace_id}','${actor.user_id}','${id}','${actor.device_id}','hash','RETIRED','2026-01-02')`;});
  await localSql('INSERT INTO wallpaper_uploads(object_key,workspace_id,owner_admin_user_id,wallpaper_id,device_id,ciphertext_hash,state,expires_at) VALUES'+rows.join(',')+';');
  const response=await fetch(`${base}/api/v1/chats/${actor.chat}/wallpaper/uploads/${randomUUID()}/image`,{method:'PUT',headers:{Origin:base,...edgeHeaders,Cookie:actor.cookie},body:randomBytes(64)});
  assert.equal(response.status,409,await response.clone().text());assert.equal((await response.json()).type,'WALLPAPER_QUOTA_EXCEEDED');
});
test('push refresh replaces one durable endpoint slot while preserving ownership',async()=>{
  const actor=await fixture(),other=await fixture(),ecdh=createECDH('prime256v1');ecdh.generateKeys();
  const keys={p256dh:ecdh.getPublicKey().toString('base64url'),auth:randomBytes(16).toString('base64url')};
  let firstId,body;
  for(let i=0;i<5;i++){
    body={endpoint:`https://fcm.googleapis.com/fcm/send/${randomUUID()}`,expirationTime:null,keys};
    const result=await api('/push/subscriptions',{cookie:actor.cookie,body});
    assert.equal(result.status,201,JSON.stringify(result.value));
    firstId??=result.value.subscription_id;assert.equal(result.value.subscription_id,firstId);
  }
  assert.equal((await localRows(`SELECT COUNT(*) AS n FROM push_subscriptions WHERE device_id='${actor.device_id}'`))[0].n,1);
  const conflict=await api('/push/subscriptions',{cookie:other.cookie,body});assert.equal(conflict.status,409);assert.equal(conflict.value.type,'PUSH_ENDPOINT_CONFLICT');
});
test('receipt API rejects extension fields and preserves exact replay and READ terminal state',async()=>{
  const actor=await room(),client=randomUUID();
  const content={protocol:'secure-message-content',v:2,chat_id:actor.chat,client_message_id:client,sender_user_id:actor.user_id,sender_device_id:actor.device_id,message_type:'MESSAGE',text:'Receipt regression',attachments:[],mutation:null,reply_to_message_id:null};
  const sent=await api(`/chats/${actor.chat}/messages`,{cookie:actor.cookie,body:{client_message_id:client,sender_sequence:1,attachment_ids:[],envelopes:[{recipient_user_id:actor.user_id,recipient_device_id:actor.device_id,protocol:'secure-messaging',protocol_version:2,header:'server-sqlite-v1',ciphertext:Buffer.from(JSON.stringify(content)).toString('base64url')}]}});
  assert.equal(sent.status,201,JSON.stringify(sent.value));
  const message_id=sent.value.message_id,headers={'Idempotency-Key':randomUUID()};
  const extra=await api(`/chats/${actor.chat}/receipts`,{cookie:actor.cookie,headers,body:{message_id,state:'READ',padding:'unbounded'}});assert.equal(extra.status,422);
  const read=await api(`/chats/${actor.chat}/receipts`,{cookie:actor.cookie,headers,body:{message_id,state:'READ'}});assert.equal(read.status,200,JSON.stringify(read.value));
  const replay=await api(`/chats/${actor.chat}/receipts`,{cookie:actor.cookie,headers,body:{message_id,state:'READ'}});assert.equal(replay.status,200);assert.equal(replay.value.revision,read.value.revision);assert.equal(replay.value.duplicate,true);
  const conflict=await api(`/chats/${actor.chat}/receipts`,{cookie:actor.cookie,headers,body:{message_id,state:'DELIVERED'}});assert.equal(conflict.status,409);assert.equal(conflict.value.type,'IDEMPOTENCY_CONFLICT');
  const terminal=await api(`/chats/${actor.chat}/receipts`,{cookie:actor.cookie,headers:{'Idempotency-Key':randomUUID()},body:{message_id,state:'DELIVERED'}});assert.equal(terminal.status,200);assert.equal(terminal.value.state,'READ');assert.equal(terminal.value.revision,read.value.revision);
});
test('expired receipt responses free existing room credit before growth admission at aggregate capacity',async t=>{
  const actor=await room(),client=randomUUID(),freshId=randomUUID(),legacyId=randomUUID();
  const content={protocol:'secure-message-content',v:2,chat_id:actor.chat,client_message_id:client,sender_user_id:actor.user_id,sender_device_id:actor.device_id,message_type:'MESSAGE',text:'Retained history survives receipt cache maintenance',attachments:[],mutation:null,reply_to_message_id:null};
  const sent=await api(`/chats/${actor.chat}/messages`,{cookie:actor.cookie,body:{client_message_id:client,sender_sequence:1,attachment_ids:[],envelopes:[{recipient_user_id:actor.user_id,recipient_device_id:actor.device_id,protocol:'secure-messaging',protocol_version:2,header:'server-sqlite-v1',ciphertext:Buffer.from(JSON.stringify(content)).toString('base64url')}]}});
  assert.equal(sent.status,201,JSON.stringify(sent.value));
  const message_id=sent.value.message_id,receipt=(requestId,state='READ',cookie=actor.cookie)=>api(`/chats/${actor.chat}/receipts`,{cookie,headers:{'Idempotency-Key':requestId},body:{message_id,state}});
  const read=await receipt(freshId);assert.equal(read.status,200,JSON.stringify(read.value));
  const templateId=randomUUID();assert.equal((await receipt(templateId)).status,200);
  // Simulate aged, valid no-op replay responses using their real canonical
  // fingerprint/response. Keep the actual retained message/event rows unchanged.
  const fill=async includeLegacy=>roomDatabase(actor.chat,db=>{
    db.exec('BEGIN IMMEDIATE');
    try{
      const template=db.prepare('SELECT payload,response FROM receipt_requests WHERE user_id=? AND request_id=?').get(actor.user_id,templateId);
      const insert=db.prepare('INSERT INTO receipt_requests(user_id,request_id,payload,response,expires_at) VALUES(?,?,?,?,?)');
      if(includeLegacy)insert.run(actor.user_id,legacyId,JSON.stringify([{message_id,state:'READ'}]),template.response,null);
      const charge=256+Buffer.byteLength(actor.user_id)+36+Buffer.byteLength(template.payload)+Buffer.byteLength(template.response);
      let usage=db.prepare('SELECT * FROM storage_usage WHERE id=1').get(),lastExpired;
      const before={messages:db.prepare('SELECT COUNT(*) AS n FROM chat_messages').get().n,events:db.prepare('SELECT COUNT(*) AS n FROM events').get().n};
      let inserted=0;
      while(usage.bytes+charge<=usage.byte_limit&&usage.rows+1<usage.row_limit){
        lastExpired=randomUUID();insert.run(actor.user_id,lastExpired,template.payload,template.response,Date.now()-3600000);
        usage=db.prepare('SELECT * FROM storage_usage WHERE id=1').get();inserted++;
        assert.ok(inserted<4096,'fixture fill remains bounded');
      }
      if(includeLegacy)assert.ok(inserted>512);
      assert.ok(usage.byte_limit-usage.bytes<3072,'next receipt needs reclaimed bytes');
      const expired=db.prepare('SELECT COUNT(*) AS n FROM receipt_requests WHERE expires_at IS NOT NULL AND expires_at<=?').get(Date.now()).n;
      db.exec('COMMIT');return{lastExpired,expired,before,usage};
    }catch(error){db.exec('ROLLBACK');throw error;}
  });
  const seeded=await fill(true);
  // Fill aggregate reservations with otherwise idle synthetic rooms. Preserve
  // the configured 100GiB/256MiB limits and this room's real 1MiB allocation.
  const [capacity]=await localRows('SELECT bytes-(SELECT COALESCE(SUM(allocated_bytes),0) FROM chat_storage_capacity) AS free FROM chat_capacity_limits WHERE id=1');
  const fillerIds=[];let free=capacity.free;
  while(free>0){const id=randomUUID(),bytes=Math.min(free,256*1024*1024);fillerIds.push(id);free-=bytes;await localSql(`INSERT INTO chats(chat_id,workspace_id,created_by_user_id,owner_admin_user_id,created_at) VALUES('${id}','${actor.workspace_id}','${actor.user_id}','${actor.user_id}','2026-01-01'); UPDATE chat_storage_capacity SET allocated_bytes=${bytes} WHERE chat_id='${id}';`);}
  try{
    const stranger=await fixture(),unauthorized=await receipt(randomUUID(),'READ',stranger.cookie);assert.equal(unauthorized.status,403);
    await roomDatabase(actor.chat,db=>assert.equal(db.prepare('SELECT COUNT(*) AS n FROM receipt_requests WHERE expires_at IS NOT NULL AND expires_at<=?').get(Date.now()).n,seeded.expired));
    await t.test('a receipt reuses expired bytes while preserving READ and replay semantics',async()=>{
      const resumed=await receipt(seeded.lastExpired,'DELIVERED');
      assert.equal(resumed.status,200,JSON.stringify(resumed.value));assert.equal(resumed.value.state,'READ');assert.equal(resumed.value.revision,read.value.revision);
      await roomDatabase(actor.chat,db=>{
        const expired=db.prepare('SELECT COUNT(*) AS n FROM receipt_requests WHERE expires_at IS NOT NULL AND expires_at<=?').get(Date.now()).n;
        assert.ok(expired<seeded.expired);assert.ok(expired>=seeded.expired-513,'cleanup remains bounded');
        assert.deepEqual({messages:db.prepare('SELECT COUNT(*) AS n FROM chat_messages').get().n,events:db.prepare('SELECT COUNT(*) AS n FROM events').get().n},seeded.before);
        assert.equal(db.prepare('SELECT expires_at FROM receipt_requests WHERE user_id=? AND request_id=?').get(actor.user_id,legacyId).expires_at,null);
        assert.ok(db.prepare('SELECT expires_at FROM receipt_requests WHERE user_id=? AND request_id=?').get(actor.user_id,seeded.lastExpired).expires_at>Date.now()+29*86400000);
      });
      const legacy=await receipt(legacyId);assert.equal(legacy.status,200);assert.equal(legacy.value.revision,read.value.revision);
      const fresh=await receipt(freshId);assert.equal(fresh.status,200);assert.equal(fresh.value.revision,read.value.revision);
      const conflict=await receipt(freshId,'DELIVERED');assert.equal(conflict.status,409);assert.equal(conflict.value.type,'IDEMPOTENCY_CONFLICT');
    });
    await t.test('a new message independently reclaims expired replay cache before reservation',async()=>{
      const refilled=await fill(false),secondClient=randomUUID(),secondContent={...content,client_message_id:secondClient,text:'New message using reclaimed receipt-cache bytes'};
      const accepted=await api(`/chats/${actor.chat}/messages`,{cookie:actor.cookie,body:{client_message_id:secondClient,sender_sequence:2,attachment_ids:[],envelopes:[{recipient_user_id:actor.user_id,recipient_device_id:actor.device_id,protocol:'secure-messaging',protocol_version:2,header:'server-sqlite-v1',ciphertext:Buffer.from(JSON.stringify(secondContent)).toString('base64url')}]}});
      assert.equal(accepted.status,201,JSON.stringify(accepted.value));
      await roomDatabase(actor.chat,db=>{
        const expired=db.prepare('SELECT COUNT(*) AS n FROM receipt_requests WHERE expires_at IS NOT NULL AND expires_at<=?').get(Date.now()).n;
        assert.ok(expired<refilled.expired);assert.ok(expired>=refilled.expired-512,'message maintenance remains bounded');
        assert.equal(db.prepare('SELECT COUNT(*) AS n FROM chat_messages').get().n,refilled.before.messages+1);
        assert.equal(db.prepare('SELECT COUNT(*) AS n FROM events').get().n,refilled.before.events+1);
      });
      const history=await api(`/chats/${actor.chat}/sync?after_revision=0&limit=10`,{cookie:actor.cookie});assert.equal(history.status,200);
      assert.equal(JSON.parse(Buffer.from(history.value.changes.find(change=>change.message_id===message_id).envelope.ciphertext,'base64url').toString()).text,content.text);
    });
    const [retained]=await localRows('SELECT allocated_bytes FROM chat_storage_capacity WHERE chat_id=?',[actor.chat]);assert.equal(retained.allocated_bytes,seeded.usage.byte_limit);
  }finally{
    for(let offset=0;offset<fillerIds.length;offset+=100)await localSql(`UPDATE chat_storage_capacity SET allocated_bytes=0 WHERE chat_id IN (${fillerIds.slice(offset,offset+100).map(id=>`'${id}'`).join(',')});`);
  }
});
