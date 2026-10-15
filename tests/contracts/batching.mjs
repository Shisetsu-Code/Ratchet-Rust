import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import WebSocket from 'ws';
import {base,fixture,localSql,api} from './fixtures.mjs';

async function scenario(t){
  const actor=await fixture(),chat=randomUUID(),now=new Date().toISOString();
  await localSql(`INSERT INTO chats(chat_id,workspace_id,created_by_user_id,owner_admin_user_id,created_at) VALUES('${chat}','${actor.workspace_id}','${actor.user_id}','${actor.user_id}','${now}');`);
  async function connect(){
    const socket=new WebSocket(base.replace(/^http/,'ws')+`/api/v1/chats/${chat}/realtime`,{closeTimeout:1000,headers:{Cookie:actor.cookie,Origin:base}});
    const peer={socket,events:[],errors:[]};t.after(()=>socket.terminate());
    socket.on('message',raw=>{try{peer.events.push(JSON.parse(raw.toString()));}catch(error){peer.errors.push(error);}});
    socket.on('error',error=>peer.errors.push(error));
    await wait(()=>peer.events.some(e=>e.type==='realtime.ready'),[peer]);return peer;
  }
  return{actor,chat,writer:await connect(),observer:await connect()};
}
function request(s,sequence,text='batch regression'){
  const id=randomUUID(),content={protocol:'secure-message-content',v:2,chat_id:s.chat,client_message_id:id,sender_user_id:s.actor.user_id,sender_device_id:s.actor.device_id,message_type:'MESSAGE',text,attachments:[],mutation:null,reply_to_message_id:null};
  return{client_message_id:id,sender_sequence:sequence,attachment_ids:[],envelopes:[{recipient_user_id:s.actor.user_id,recipient_device_id:s.actor.device_id,protocol:'secure-messaging',protocol_version:2,header:'server-sqlite-v1',ciphertext:Buffer.from(JSON.stringify(content)).toString('base64url')}]};
}
const send=(s,body)=>s.writer.socket.send(JSON.stringify({type:'message.send',request:body}));
const settled=s=>s.writer.events.filter(e=>e.type==='message.ack'||e.type==='message.nack');
const publications=s=>s.observer.events.filter(e=>e.type==='message.committed'||e.type==='receipt.committed');
async function wait(predicate,peers,ms=30000){
  const deadline=Date.now()+ms;
  while(!predicate()){
    for(const peer of peers){if(peer.errors.length)throw peer.errors[0];assert.notEqual(peer.socket.readyState,WebSocket.CLOSED,'authorized connection stays open');}
    assert.ok(Date.now()<deadline,'bounded batch settlement/publication wait');await new Promise(resolve=>setTimeout(resolve,10));
  }
}
async function recovered(s){
  const result=await api(`/chats/${s.chat}/sync?after_revision=0&limit=200`,{cookie:s.actor.cookie});
  assert.equal(result.status,200,JSON.stringify(result.value));assert.equal(result.value.has_more,false);return result.value.changes;
}

test('failed message in a ready burst does not consume sequence or stall following durable messages',{timeout:45000},async t=>{
  const s=await scenario(t),bad=request(s,99),good=Array.from({length:20},(_,i)=>request(s,i+1,`after error ${i+1}`));
  send(s,bad);for(const body of good)send(s,body);
  await wait(()=>settled(s).length===21&&publications(s).length===20,[s.writer,s.observer]);
  const failures=settled(s).filter(e=>e.type==='message.nack');assert.equal(failures.length,1);assert.equal(failures[0].client_message_id,bad.client_message_id);
  assert.equal(settled(s).filter(e=>e.type==='message.ack').length,20);
  const rows=await recovered(s);assert.deepEqual(rows.map(r=>r.client_message_id),good.map(r=>r.client_message_id));
  assert.deepEqual(rows.map(r=>r.revision),Array.from({length:20},(_,i)=>i+1));
  assert.deepEqual(publications(s).map(r=>r.revision),rows.map(r=>r.revision));
  const sequence=await api(`/chats/${s.chat}/messages/sender-sequence`,{cookie:s.actor.cookie});assert.equal(sequence.status,200);assert.equal(sequence.value.next_sequence,21);
});

test('identical retries within a burst acknowledge one durable message and publish it exactly once',{timeout:45000},async t=>{
  const s=await scenario(t),bodies=Array.from({length:20},(_,i)=>request(s,i+1,`retry ${i+1}`));
  for(const body of bodies){send(s,body);send(s,body);}
  await wait(()=>settled(s).length===40&&publications(s).length===20,[s.writer,s.observer]);
  assert.ok(settled(s).every(e=>e.type==='message.ack'),'all duplicate frames settle without NACK');
  for(const body of bodies){const acks=settled(s).filter(e=>e.client_message_id===body.client_message_id);assert.equal(acks.length,2);assert.equal(acks[0].message_id,acks[1].message_id);assert.equal(acks[0].revision,acks[1].revision);assert.deepEqual(acks.map(e=>e.duplicate).sort(),[false,true]);}
  const rows=await recovered(s);assert.equal(rows.length,20);assert.deepEqual(rows.map(r=>r.client_message_id),bodies.map(r=>r.client_message_id));
  assert.deepEqual(publications(s).map(e=>e.client_message_id),bodies.map(r=>r.client_message_id));
});

test('concurrent receipt and message burst publish revisions in durable recovery order',{timeout:45000},async t=>{
  const s=await scenario(t),seed=request(s,1);send(s,seed);
  await wait(()=>settled(s).length===1&&publications(s).length===1,[s.writer,s.observer]);
  const messageId=settled(s)[0].message_id;assert.ok(messageId);
  const bodies=Array.from({length:20},(_,i)=>request(s,i+2,`mixed ${i+2}`));
  const receipt=api(`/chats/${s.chat}/receipts`,{cookie:s.actor.cookie,headers:{'Idempotency-Key':randomUUID()},body:{message_id:messageId,state:'DELIVERED'}});
  for(const body of bodies)send(s,body);
  const result=await receipt;assert.equal(result.status,200,JSON.stringify(result.value));
  await wait(()=>settled(s).length===21&&publications(s).length===22,[s.writer,s.observer]);
  assert.ok(settled(s).every(e=>e.type==='message.ack'));
  const rows=await recovered(s);assert.equal(rows.length,22);assert.equal(rows.filter(r=>r.type==='receipt').length,1);
  assert.deepEqual(rows.map(r=>r.revision),Array.from({length:22},(_,i)=>i+1));
  assert.deepEqual(publications(s).map(r=>r.revision),rows.map(r=>r.revision),'live mixed publications retain the authoritative event order');
  assert.equal(publications(s).filter(r=>r.type==='receipt.committed')[0].revision,result.value.revision);
});
