import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {base,fixture,localSql,localRows,api} from './fixtures.mjs';
test('HTTP batch, chat detail and asynchronous list projection agree on revisions',async()=>{
 const a=await fixture(),chat=randomUUID(),now=new Date().toISOString(),cookie=a.cookie;
 await localSql(`INSERT INTO chats(chat_id,workspace_id,created_by_user_id,created_at) VALUES('${chat}','${a.workspace_id}','${a.user_id}','${now}'); INSERT INTO chat_revisions(chat_id) VALUES('${chat}');`);
 const messages=Array.from({length:10},(_,i)=>{const id=randomUUID();const content={protocol:'secure-message-content',v:2,chat_id:chat,client_message_id:id,sender_user_id:a.user_id,sender_device_id:a.device_id,message_type:'MESSAGE',text:'HTTP batch '+i,attachments:[],mutation:null,reply_to_message_id:null};return{client_message_id:id,sender_sequence:i+1,envelopes:[{recipient_user_id:a.user_id,recipient_device_id:a.device_id,protocol:'secure-messaging',protocol_version:2,header:'server-sqlite-v1',ciphertext:Buffer.from(JSON.stringify(content)).toString('base64url')}],attachment_ids:[]};});
 const sent=await api(`/chats/${chat}/messages/batch`,{cookie,body:{messages}});assert.equal(sent.status,200,JSON.stringify(sent.value));assert.equal(sent.value.messages.length,10);
 const retry=await api(`/chats/${chat}/messages/batch`,{cookie,body:{messages}});assert.ok(retry.value.messages.every(m=>m.duplicate));
 const duplicate=await api(`/chats/${chat}/messages/batch`,{cookie,body:{messages:[messages[0],messages[0]]}});assert.equal(duplicate.status,422);
 const detail=await api(`/chats/${chat}`,{cookie});assert.equal(detail.status,200);assert.equal(detail.value.revision,10);assert.equal(detail.value.participants[0].user_id,a.user_id);
 const deadline=Date.now()+10000;let revision=0;while(Date.now()<deadline&&revision!==10){const listed=await api('/chats',{cookie});revision=listed.value.chats.find(c=>c.chat_id===chat)?.revision; if(revision!==10)await new Promise(r=>setTimeout(r,100));}assert.equal(revision,10);
 const orphan=randomUUID();assert.equal((await api(`/chats/${chat}/attachments`,{cookie,body:{file_id:orphan,encrypted_size:32,encrypted_metadata:'orphan'}})).status,201);
 await localSql(`UPDATE attachment_uploads SET expires_at='${new Date(Date.now()-1000).toISOString()}' WHERE file_id='${orphan}';`);
 const cleanup=await fetch(base+'/cdn-cgi/local/scheduled');assert.equal(cleanup.status,200,await cleanup.text());
 assert.equal((await localRows('SELECT status FROM attachment_uploads WHERE file_id=?',[orphan]))[0].status,'EXPIRED');
});
