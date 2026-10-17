import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,randomBytes,createHash} from 'node:crypto';
import WebSocket from 'ws';
import {base,fixture,localSql,api,edgeHeaders} from './fixtures.mjs';

const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function room(){
 const actor=await fixture(),chat=randomUUID();
 await localSql(`INSERT INTO chats(chat_id,workspace_id,created_by_user_id,owner_admin_user_id,created_at) VALUES('${chat}','${actor.workspace_id}','${actor.user_id}','${actor.user_id}','${new Date().toISOString()}');`);
 return{actor,chat};
}
async function connect(chat,actor){
 const socket=new WebSocket(base.replace(/^http/,'ws')+`/api/v1/chats/${chat}/realtime`,{closeTimeout:300,headers:{Cookie:actor.cookie,Origin:base,...edgeHeaders}});
 const peer={socket,events:[],closed:null};
 socket.on('close',code=>{peer.closed=code;});
 await new Promise((resolve,reject)=>{
  const timeout=setTimeout(()=>{socket.terminate();reject(new Error('WebSocket admission timed out'));},5000);
  socket.on('message',raw=>{const event=JSON.parse(raw.toString());peer.events.push(event);if(event.type==='realtime.ready'){clearTimeout(timeout);resolve();}});
  socket.once('error',error=>{clearTimeout(timeout);reject(error);});
  socket.once('unexpected-response',(_request,response)=>{clearTimeout(timeout);response.resume();socket.terminate();reject(Object.assign(new Error('Upgrade refused'),{status:response.statusCode}));});
 });
 return peer;
}
async function waitClosed(peer){
 const until=Date.now()+2000;
 while(peer.closed===null&&Date.now()<until)await pause(10);
 return peer.closed;
}

test('existing revision-carrying pings remain valid while unknown ping fields close',async()=>{
 const{actor,chat}=await room(),peer=await connect(chat,actor);
 try{
  peer.socket.send(JSON.stringify({type:'ping',after_revision:0}));
  const until=Date.now()+2000;
  while(!peer.events.some(event=>event.type==='pong')&&Date.now()<until)await pause(10);
  assert.equal(peer.events.filter(event=>event.type==='pong').length,1);
  peer.socket.send(JSON.stringify({type:'ping',padding:'unrecognized'}));
  assert.equal(await waitClosed(peer),1003);
 }finally{peer.socket.terminate();}
});

test('malformed typed message frames close instead of leaving an unlimited NACK loop',async()=>{
 const{actor,chat}=await room(),peer=await connect(chat,actor);
 try{
  peer.socket.send(JSON.stringify({type:'message.send',request:{client_message_id:randomUUID(),envelopes:'invalid'}}));
  assert.equal(await waitClosed(peer),1003);
 }finally{peer.socket.terminate();}
});

test('application ping floods are charged before processing and closed at the device frame budget',async()=>{
 const{actor,chat}=await room(),peer=await connect(chat,actor);
 try{
  for(let i=0;i<300;i++)peer.socket.send(JSON.stringify({type:'ping'}));
  assert.equal(await waitClosed(peer),1008);
  assert.ok(peer.events.filter(event=>event.type==='pong').length<=240,'only admitted frames produce a pong');
 }finally{peer.socket.terminate();}
});

test('frame budgets are shared between sockets and survive reconnects',async()=>{
 const{actor,chat}=await room(),first=await connect(chat,actor),second=await connect(chat,actor);
 const peers=[first,second];
 try{
  for(let i=0;i<120;i++)first.socket.send(JSON.stringify({type:'ping'}));
  const until=Date.now()+2000;
  while(first.events.filter(event=>event.type==='pong').length<120&&Date.now()<until)await pause(10);
  assert.equal(first.events.filter(event=>event.type==='pong').length,120);
  first.socket.terminate();
  for(let i=0;i<121;i++)second.socket.send(JSON.stringify({type:'ping'}));
  assert.equal(await waitClosed(second),1008);
  const third=await connect(chat,actor);peers.push(third);
  third.socket.send(JSON.stringify({type:'ping'}));
  assert.equal(await waitClosed(third),1008);
 }finally{for(const peer of peers)peer.socket.terminate();}
});

test('a device can keep four concurrent sockets and the next upgrade is rejected',async()=>{
 const{actor,chat}=await room(),peers=[];
 try{
  for(let i=0;i<4;i++)peers.push(await connect(chat,actor));
  await assert.rejects(async()=>{const excess=await connect(chat,actor);peers.push(excess);return excess;},error=>error.status===429);
  assert.ok(peers.every(peer=>peer.socket.readyState===WebSocket.OPEN));
 }finally{for(const peer of peers)peer.socket.terminate();}
});

test('a passive expired session does not receive a later presence broadcast',async()=>{
 const{actor,chat}=await room(),expires=Date.now()+2500;
 await localSql(`UPDATE sessions SET expires_at='${new Date(expires).toISOString()}' WHERE session_id='${actor.session_id}';`);
 const expired=await connect(chat,actor),peers=[expired];
 try{
  await pause(Math.max(0,expires-Date.now()+50));
  const before=expired.events.length,secret=randomBytes(32).toString('base64url'),hash=createHash('sha256').update(secret).digest('hex'),now=new Date().toISOString();
  await localSql(`INSERT INTO sessions(session_id,secret_hash,user_id,device_id,created_at,last_seen_at,expires_at) VALUES('${randomUUID()}','${hash}','${actor.user_id}','${actor.device_id}','${now}','${now}','${new Date(Date.now()+86400000).toISOString()}');`);
  peers.push(await connect(chat,{...actor,cookie:'__Host-session='+secret}));
  assert.equal(await waitClosed(expired),4001);
  assert.equal(expired.events.slice(before).filter(event=>event.type==='presence.changed').length,0);
 }finally{for(const peer of peers)peer.socket.terminate();}
});

test('receipt routes reject extra fields and oversized bodies while preserving valid receipts',async()=>{
 const{actor,chat}=await room(),client=randomUUID();
 const content={protocol:'secure-message-content',v:2,chat_id:chat,client_message_id:client,sender_user_id:actor.user_id,sender_device_id:actor.device_id,message_type:'MESSAGE',text:'receipt budget control',attachments:[],mutation:null,reply_to_message_id:null};
 const sent=await api(`/chats/${chat}/messages`,{cookie:actor.cookie,body:{client_message_id:client,sender_sequence:1,envelopes:[{recipient_user_id:actor.user_id,recipient_device_id:actor.device_id,protocol:'secure-messaging',protocol_version:2,header:'server-sqlite-v1',ciphertext:Buffer.from(JSON.stringify(content)).toString('base64url')}],attachment_ids:[]}});
 assert.equal(sent.status,201,JSON.stringify(sent.value));
 const receipt={message_id:sent.value.message_id,state:'READ'};
 const post=(suffix,body)=>api(`/chats/${chat}/${suffix}`,{cookie:actor.cookie,headers:{'Idempotency-Key':randomUUID()},body});
 assert.equal((await post('receipts',{...receipt,padding:'x'})).status,422);
 assert.equal((await post('receipts/batch',{receipts:[receipt],padding:'x'})).status,422);
 assert.equal((await post('receipts',{...receipt,padding:'x'.repeat(40*1024)})).status,413);
 assert.equal((await post('receipts',receipt)).status,200);
});
