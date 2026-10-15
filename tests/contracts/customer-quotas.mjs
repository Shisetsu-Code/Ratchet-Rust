import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,randomBytes,createHash} from 'node:crypto';
import WebSocket from 'ws';
import {base,fixture,localSql,api} from './fixtures.mjs';

async function scenario(){
  const owner=await fixture(),chat=randomUUID(),actor={user_id:randomUUID(),device_id:randomUUID()},secret=randomBytes(32).toString('base64url');
  actor.cookie='__Host-session='+secret;
  const now=new Date().toISOString(),expires=new Date(Date.now()+86400000).toISOString(),hash=createHash('sha256').update(secret).digest('hex');
  await localSql(`INSERT INTO chats(chat_id,workspace_id,created_by_user_id,owner_admin_user_id,created_at) VALUES('${chat}','${owner.workspace_id}','${owner.user_id}','${owner.user_id}','${now}');
INSERT INTO users(user_id,role,status,created_at,activated_at) VALUES('${actor.user_id}','CUSTOMER','ACTIVE','${now}','${now}');
INSERT INTO customer_accounts(user_id,created_by_user_id,created_at) VALUES('${actor.user_id}','${owner.user_id}','${now}');
INSERT INTO workspace_memberships(workspace_id,user_id,role,status,created_at) VALUES('${owner.workspace_id}','${actor.user_id}','CUSTOMER','ACTIVE','${now}');
INSERT INTO devices(device_id,user_id,display_name,crypto_identity_public_key,created_at,authorized_at,last_seen_at) VALUES('${actor.device_id}','${actor.user_id}','Quota fixture','${'A'.repeat(43)}','${now}','${now}','${now}');
INSERT INTO sessions(session_id,secret_hash,user_id,device_id,created_at,last_seen_at,expires_at) VALUES('${randomUUID()}','${hash}','${actor.user_id}','${actor.device_id}','${now}','${now}','${expires}');
INSERT INTO chat_participants(chat_id,user_id,participant_role,joined_at) VALUES('${chat}','${actor.user_id}','CUSTOMER','${now}');`);
  return{chat,actor};
}
function request(s,sequence){
  const id=randomUUID(),content={protocol:'secure-message-content',v:2,chat_id:s.chat,client_message_id:id,sender_user_id:s.actor.user_id,sender_device_id:s.actor.device_id,message_type:'MESSAGE',text:`Customer quota ${sequence}`,attachments:[],mutation:null,reply_to_message_id:null};
  return{client_message_id:id,sender_sequence:sequence,attachment_ids:[],envelopes:[{recipient_user_id:s.actor.user_id,recipient_device_id:s.actor.device_id,protocol:'secure-messaging',protocol_version:2,header:'server-sqlite-v1',ciphertext:Buffer.from(JSON.stringify(content)).toString('base64url')}]};
}
async function wait(predicate,peer){
  const deadline=Date.now()+30000;
  while(!predicate()){
    if(peer.errors.length)throw peer.errors[0];
    assert.notEqual(peer.socket.readyState,WebSocket.CLOSED,'authorized customer socket remains connected');
    assert.ok(Date.now()<deadline,'customer quota frames settle within 30 seconds');
    await new Promise(resolve=>setTimeout(resolve,5));
  }
}

test('CUSTOMER burst quota is shared by WebSocket and HTTP, preserves retries and exact recovery',{timeout:45000},async t=>{
  const s=await scenario(),socket=new WebSocket(base.replace(/^http/,'ws')+`/api/v1/chats/${s.chat}/realtime`,{closeTimeout:1000,headers:{Cookie:s.actor.cookie,Origin:base}});
  const peer={socket,events:[],errors:[]};t.after(()=>socket.terminate());
  socket.on('error',error=>peer.errors.push(error));
  socket.on('message',raw=>{try{peer.events.push(JSON.parse(raw.toString()));}catch(error){peer.errors.push(error);}});
  await wait(()=>peer.events.some(e=>e.type==='realtime.ready'),peer);
  const bodies=Array.from({length:101},(_,i)=>request(s,i+1));
  const settled=()=>peer.events.filter(e=>e.type==='message.ack'||e.type==='message.nack');
  // Miniflare uses wall-clock aligned buckets, including for a fresh customer key.
  // Start near the beginning so a boundary cannot replenish the budget mid-probe.
  const bucketMs=10000,offset=Date.now()%bucketMs;
  if(offset>2000)await new Promise(resolve=>setTimeout(resolve,bucketMs-offset+100));
  const bucket=Math.floor(Date.now()/bucketMs);
  const started=performance.now();
  for(const body of bodies)socket.send(JSON.stringify({type:'message.send',request:body}));
  await wait(()=>settled().length===101,peer);
  assert.ok(performance.now()-started<10000,'entire burst settles before the 10-second quota window can reset');
  const acks=settled().filter(e=>e.type==='message.ack'),nacks=settled().filter(e=>e.type==='message.nack');
  assert.equal(acks.length,100);assert.equal(nacks.length,1);
  assert.equal(nacks[0].client_message_id,bodies[100].client_message_id);
  assert.equal(nacks[0].error_type,'CUSTOMER_MESSAGE_RATE_LIMITED','customer binding rejects the over-limit frame');assert.equal(nacks[0].retryable,true);
  assert.ok(acks.every(e=>e.duplicate===false));
  const fallback=request(s,101);
  const http=await api(`/chats/${s.chat}/messages`,{cookie:s.actor.cookie,headers:{'Idempotency-Key':fallback.client_message_id},body:fallback});
  assert.equal(http.status,429,JSON.stringify(http.value));assert.equal(http.value.type,'CUSTOMER_MESSAGE_RATE_LIMITED');
  socket.send(JSON.stringify({type:'message.send',request:bodies[0]}));
  await wait(()=>settled().length===102,peer);
  const retry=settled().at(-1),original=acks.find(e=>e.client_message_id===bodies[0].client_message_id);
  assert.equal(retry.type,'message.ack');assert.equal(retry.duplicate,true);assert.equal(retry.message_id,original.message_id);assert.equal(retry.revision,original.revision);
  assert.ok(performance.now()-started<10000,'fallback and duplicate retry run while the burst budget is exhausted');
  assert.equal(Math.floor(Date.now()/bucketMs),bucket,'burst, fallback and duplicate retry stay in one aligned quota bucket');
  const sync=await api(`/chats/${s.chat}/sync?after_revision=0&limit=200`,{cookie:s.actor.cookie});
  assert.equal(sync.status,200);assert.equal(sync.value.has_more,false);
  assert.deepEqual(sync.value.changes.map(e=>e.client_message_id),bodies.slice(0,100).map(e=>e.client_message_id),'rejected and retried frames add no durable messages');
  assert.deepEqual(sync.value.changes.map(e=>e.revision),Array.from({length:100},(_,i)=>i+1));
  for(const change of sync.value.changes){const ack=acks.find(e=>e.client_message_id===change.client_message_id);assert.equal(change.message_id,ack.message_id);assert.equal(change.revision,ack.revision);}
  const sequence=await api(`/chats/${s.chat}/messages/sender-sequence`,{cookie:s.actor.cookie});assert.equal(sequence.status,200);assert.equal(sequence.value.next_sequence,101);
  const unauthorized=await api(`/chats/${s.chat}/messages`,{headers:{'Idempotency-Key':fallback.client_message_id},body:fallback});assert.equal(unauthorized.status,401);assert.equal(unauthorized.value.type,'SESSION_REQUIRED');
});
