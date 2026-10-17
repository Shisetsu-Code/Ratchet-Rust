import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,createECDH,randomBytes,createHash} from 'node:crypto';
import {base,fixture,localSql,api,edgeHeaders} from './fixtures.mjs';
test('attachments wallpaper and push require an authenticated authorized device',async()=>{
  for(const path of ['/attachments/11111111-1111-4111-8111-111111111111','/chats/11111111-1111-4111-8111-111111111111/wallpaper','/push/config']){
    const response=await fetch(base+'/api/v1'+path,{headers:{...edgeHeaders}});
    assert.equal(response.status,401,path);
    assert.equal((await response.json()).type,'SESSION_REQUIRED',path);
  }
});

async function room(){const actor=await fixture(),chat=randomUUID(),now=new Date().toISOString();await localSql(`INSERT INTO chats(chat_id,workspace_id,created_by_user_id,owner_admin_user_id,created_at) VALUES('${chat}','${actor.workspace_id}','${actor.user_id}','${actor.user_id}','${now}');`);return{...actor,chat};}
async function binary(path,actor,bytes,headers={}){const response=await fetch(base+'/api/v1'+path,{method:'PUT',headers:{Origin:base,...edgeHeaders,Cookie:actor.cookie,...headers},body:bytes});const raw=await response.text();let value;try{value=JSON.parse(raw);}catch{value=raw;}return{status:response.status,value};}
test('pending devices cannot access file wallpaper or push metadata',async()=>{
  const a=await room();await localSql(`UPDATE devices SET authorized_at=NULL WHERE device_id='${a.device_id}';`);
  for(const path of [`/attachments/${randomUUID()}`,`/chats/${a.chat}/wallpaper`,'/push/config']){const result=await api(path,{cookie:a.cookie});assert.equal(result.status,403);assert.equal(result.value.type,'DEVICE_PENDING_APPROVAL');}
});
test('multipart upload enforces ownership, ETags, sizes, and uncommitted visibility',async()=>{
  const a=await room(),other=await fixture(),id=randomUUID(),cookie=a.cookie;
  const reserve=()=>api(`/chats/${a.chat}/attachments`,{cookie,body:{file_id:id,encrypted_size:32,encrypted_metadata:'opaque attachment metadata'}});
  const reserved=await reserve();assert.equal(reserved.status,201,JSON.stringify(reserved.value));assert.equal(reserved.value.status,'UPLOADING');
  const retry=await reserve();assert.equal(retry.value.upload_id,reserved.value.upload_id);
  const foreign=await api(`/attachments/${id}`,{cookie:other.cookie});assert.equal(foreign.status,404);
  const wrongSize=await api(`/chats/${a.chat}/attachments`,{cookie,body:{file_id:id,encrypted_size:33,encrypted_metadata:'opaque attachment metadata'}});assert.equal(wrongSize.status,409);
  const uploaded=await binary(`/attachments/${id}/parts/1`,a,Buffer.alloc(32,7),{'X-Encrypted-Part-Size':'32'});assert.equal(uploaded.status,200,JSON.stringify(uploaded.value));
  const stale=await api(`/attachments/${id}/complete`,{cookie,body:{parts:[{part_number:1,etag:'stale'}]}});assert.equal(stale.status,409);assert.equal(stale.value.type,'ATTACHMENT_PART_SET_STALE');
  const complete=await api(`/attachments/${id}/complete`,{cookie,body:{parts:[{part_number:1,etag:uploaded.value.etag}]}});assert.equal(complete.status,200,JSON.stringify(complete.value));assert.equal(complete.value.status,'READY');
  const content=await api(`/attachments/${id}/content`,{cookie});assert.equal(content.status,403);
  const abort=await api(`/attachments/${id}`,{cookie,method:'DELETE'});assert.equal(abort.status,204);
  assert.equal((await api(`/attachments/${id}`,{cookie})).value.status,'ABORTED');
});
test('multipart body mismatch aborts and protocol reservation caps reject oversized files',async()=>{
  const a=await room(),id=randomUUID(),cookie=a.cookie;
  assert.equal((await api(`/chats/${a.chat}/attachments`,{cookie,body:{file_id:id,encrypted_size:10*1024*1024+33,encrypted_metadata:'x'}})).status,422);
  assert.equal((await api(`/chats/${a.chat}/attachments`,{cookie,body:{file_id:id,encrypted_size:32,encrypted_metadata:'x'}})).status,201);
  assert.equal((await binary(`/attachments/${id}/parts/1`,a,Buffer.alloc(17),{'X-Encrypted-Part-Size':'32'})).status,422);
  assert.equal((await api(`/attachments/${id}`,{cookie})).value.status,'ABORTED');
});
test('message commit claims a ready file once and supports authenticated byte ranges',async()=>{
  const a=await room(),id=randomUUID(),cookie=a.cookie,bytes=Buffer.from(Array.from({length:64},(_,i)=>i));
  assert.equal((await api(`/chats/${a.chat}/attachments`,{cookie,body:{file_id:id,encrypted_size:bytes.length,encrypted_metadata:'opaque'}})).status,201);
  const part=await binary(`/attachments/${id}/parts/1`,a,bytes,{'X-Encrypted-Part-Size':String(bytes.length)});assert.equal(part.status,200);
  assert.equal((await api(`/attachments/${id}/complete`,{cookie,body:{parts:[{part_number:1,etag:part.value.etag}]}})).value.status,'READY');
  const make=(sequence,client=randomUUID())=>{const content={protocol:'secure-message-content',v:2,chat_id:a.chat,client_message_id:client,sender_user_id:a.user_id,sender_device_id:a.device_id,message_type:'MESSAGE',text:'File message',attachments:[{file_id:id}],mutation:null,reply_to_message_id:null};return{client_message_id:client,sender_sequence:sequence,attachment_ids:[id],envelopes:[{recipient_user_id:a.user_id,recipient_device_id:a.device_id,protocol:'secure-messaging',protocol_version:2,header:'server-sqlite-v1',ciphertext:Buffer.from(JSON.stringify(content)).toString('base64url')}]};};
  const body=make(1),commit=await api(`/chats/${a.chat}/messages`,{cookie,body});assert.equal(commit.status,201,JSON.stringify(commit.value));
  assert.equal((await api(`/chats/${a.chat}/messages`,{cookie,body})).value.duplicate,true);
  assert.equal((await api(`/attachments/${id}`,{cookie})).value.status,'COMMITTED');
  assert.equal((await api(`/attachments/${id}`,{cookie,method:'DELETE'})).status,409);
  const reused=await api(`/chats/${a.chat}/messages`,{cookie,body:make(2)});assert.equal(reused.status,409);assert.equal(reused.value.type,'ATTACHMENT_NOT_READY');
  const content=await fetch(base+`/api/v1/attachments/${id}/content`,{headers:{...edgeHeaders,Cookie:cookie,Range:'bytes=4-11'}});assert.equal(content.status,206);assert.equal(content.headers.get('Content-Range'),'bytes 4-11/64');assert.deepEqual(Buffer.from(await content.arrayBuffer()),bytes.subarray(4,12));
  const invalid=await api(`/attachments/${id}/content`,{cookie,headers:{Range:'bytes=90-'}});assert.equal(invalid.status,416);
  const foreign=await fixture();assert.equal((await api(`/attachments/${id}/content`,{cookie:foreign.cookie})).status,404);
});
test('wallpaper is shared by owner account, custom ciphertext requires the current device envelope',async()=>{
  const a=await room(),cookie=a.cookie,second=randomUUID(),id=randomUUID(),now=new Date().toISOString();
  await localSql(`INSERT INTO chats(chat_id,workspace_id,created_by_user_id,owner_admin_user_id,created_at) VALUES('${second}','${a.workspace_id}','${a.user_id}','${a.user_id}','${now}'); INSERT INTO device_prekey_bundles(device_id,identity_public_key,signed_prekey_id,signed_prekey,signed_prekey_signature,updated_at) VALUES('${a.device_id}','${'A'.repeat(43)}','fixture','x','x','${now}');`);
  const preset=await api(`/chats/${a.chat}/wallpaper`,{cookie,method:'PUT',body:{preset:'sage'}});assert.equal(preset.status,200,JSON.stringify(preset.value));assert.equal(preset.value.can_manage,true);
  assert.equal((await api(`/chats/${second}/wallpaper`,{cookie})).value.preset,'sage');
  const recipients=await api(`/chats/${a.chat}/wallpaper/recipients`,{cookie});assert.equal(recipients.value.devices.length,1);
  const ciphertext=randomBytes(64);assert.equal((await binary(`/chats/${a.chat}/wallpaper/uploads/${id}/image`,a,ciphertext)).status,204);
  const envelopes=[{recipient_user_id:a.user_id,recipient_device_id:a.device_id,ephemeral_public_key_b64url:'A'.repeat(43),nonce_b64url:'A'.repeat(32),wrapped_key_b64url:'A'.repeat(64)}];
  const body={manifest:{protocol:'ratchet-wallpaper-e2ee',version:1,wallpaper_id:id,workspace_id:a.workspace_id,owner_admin_user_id:a.user_id,signer_device_id:a.device_id,content_type:'image/png',image_nonce_b64url:'A'.repeat(32),ciphertext_sha256_b64url:createHash('sha256').update(ciphertext).digest('base64url')},signature_b64url:'A'.repeat(86),envelopes};
  const committed=await api(`/chats/${a.chat}/wallpaper/uploads/${id}/commit`,{cookie,body});assert.equal(committed.status,200,JSON.stringify(committed.value));assert.equal(committed.value.kind,'custom');
  const refreshed=await api(`/chats/${a.chat}/wallpaper/${id}/envelopes`,{cookie,body:{wallpaper_id:id,envelopes}});assert.equal(refreshed.status,204,JSON.stringify(refreshed.value));
  const downloaded=await fetch(base+`/api/v1/chats/${second}/wallpaper/image`,{headers:{...edgeHeaders,Cookie:cookie}});assert.equal(downloaded.status,200);assert.deepEqual(Buffer.from(await downloaded.arrayBuffer()),ciphertext);
  const wrong={...body,manifest:{...body.manifest,owner_admin_user_id:randomUUID()}};assert.equal((await api(`/chats/${a.chat}/wallpaper/uploads/${id}/commit`,{cookie,body:wrong})).status,422);
  assert.equal((await binary(`/chats/${a.chat}/wallpaper/uploads/${id}/image`,a,ciphertext)).status,409);
});
test('push registration binds public provider endpoint to one device and permits owned refresh',async()=>{
  const a=await fixture(),other=await fixture(),ecdh=createECDH('prime256v1');ecdh.generateKeys();
  const config=await api('/push/config',{cookie:a.cookie});assert.equal(config.status,200);assert.equal(typeof config.value.enabled,'boolean');
  const body={endpoint:`https://fcm.googleapis.com/fcm/send/${randomUUID()}`,expirationTime:null,keys:{p256dh:ecdh.getPublicKey().toString('base64url'),auth:randomBytes(16).toString('base64url')}};
  const registered=await api('/push/subscriptions',{cookie:a.cookie,body});assert.equal(registered.status,201,JSON.stringify(registered.value));
  assert.equal((await api('/push/subscriptions',{cookie:a.cookie,body})).value.subscription_id,registered.value.subscription_id);
  assert.equal((await api('/push/subscriptions',{cookie:other.cookie,body})).status,409);
  for(const endpoint of ['https://127.0.0.1/push','https://fcm.googleapis.com.evil.test/push','https://user@fcm.googleapis.com/push'])assert.equal((await api('/push/subscriptions',{cookie:a.cookie,body:{...body,endpoint}})).status,422);
  assert.equal((await api(`/push/subscriptions/${registered.value.subscription_id}`,{cookie:a.cookie,method:'DELETE'})).status,204);
});
