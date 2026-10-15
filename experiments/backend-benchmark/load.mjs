import assert from 'node:assert/strict';
import {randomUUID,createHash,randomBytes} from 'node:crypto';
import {readFile,writeFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {monitorEventLoopDelay} from 'node:perf_hooks';
import WebSocket from 'ws';
import {timingProfile} from './timing-profile.mjs';
import {base,fixture,localSql,api} from '../../tests/contracts/fixtures.mjs';

const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const round=n=>Math.round(n*100)/100;
function stats(values){const a=[...values].sort((x,y)=>x-y);const at=p=>a[Math.max(0,Math.ceil(a.length*p)-1)]??null;return{count:a.length,mean_ms:a.length?round(a.reduce((x,y)=>x+y,0)/a.length):null,p50_ms:at(.5),p95_ms:at(.95),p99_ms:at(.99),max_ms:a.at(-1)??null};}
function serverSnapshot(){
 if(process.platform!=='win32')return null;
 const p=spawnSync('powershell',['-NoProfile','-File','experiments/backend-benchmark/process-snapshot.ps1','-RootProcess',process.env.RATCHET_BENCH_SERVER_PID],{encoding:'utf8',windowsHide:true,timeout:10000});
 if(p.status!==0)return null;try{return JSON.parse(p.stdout);}catch{return null;}
}
function aggregateCpu(before,after){if(!before||!after||before.length===0)return null;const ids=new Map(before.map(p=>[p.id,p]));if(after.length!==before.length||after.some(p=>!ids.has(p.id)))return null;return{workerd_processes:after.length,cpu_ms:round(after.reduce((n,p)=>n+p.cpu_ms-ids.get(p.id).cpu_ms,0)),rss_end_bytes:after.reduce((n,p)=>n+p.rss_bytes,0),process_peak_rss_bytes:after.reduce((n,p)=>n+p.peak_rss_bytes,0)};}

async function scenario(users,roomCount){
 const owner=await fixture(),now=new Date().toISOString(),expires=new Date(Date.now()+86400000).toISOString();
 const chats=Array.from({length:roomCount},()=>randomUUID());
 const senders=Array.from({length:users},(_,i)=>({user_id:randomUUID(),device_id:randomUUID(),session_id:randomUUID(),secret:randomBytes(32).toString('base64url'),chat:chats[i%roomCount]}));
 let sql=chats.map(chat=>`INSERT INTO chats(chat_id,workspace_id,created_by_user_id,owner_admin_user_id,created_at) VALUES('${chat}','${owner.workspace_id}','${owner.user_id}','${owner.user_id}','${now}'); INSERT INTO chat_revisions(chat_id) VALUES('${chat}');`).join('');
 for(const a of senders){a.cookie='__Host-session='+a.secret;const hash=createHash('sha256').update(a.secret).digest('hex');sql+=`
INSERT INTO users(user_id,role,status,created_at,activated_at) VALUES('${a.user_id}','CUSTOMER','ACTIVE','${now}','${now}');
INSERT INTO customer_accounts(user_id,created_by_user_id,created_at) VALUES('${a.user_id}','${owner.user_id}','${now}');
INSERT INTO workspace_memberships(workspace_id,user_id,role,status,created_at) VALUES('${owner.workspace_id}','${a.user_id}','CUSTOMER','ACTIVE','${now}');
INSERT INTO devices(device_id,user_id,display_name,crypto_identity_public_key,created_at,authorized_at,last_seen_at) VALUES('${a.device_id}','${a.user_id}','Benchmark','${'A'.repeat(43)}','${now}','${now}','${now}');
INSERT INTO sessions(session_id,secret_hash,user_id,device_id,created_at,last_seen_at,expires_at) VALUES('${a.session_id}','${hash}','${a.user_id}','${a.device_id}','${now}','${now}','${expires}');
INSERT INTO chat_participants(chat_id,user_id,participant_role,joined_at) VALUES('${a.chat}','${a.user_id}','CUSTOMER','${now}');`;}
 await localSql(sql);return{owner,chats,senders};
}
async function connect(chat,actor,observe){
 const socket=new WebSocket(base.replace(/^http/,'ws')+`/api/v1/chats/${chat}/realtime`,{closeTimeout:1000,headers:{Cookie:actor.cookie,Origin:base}});
 const peer={socket,chat,acks:new Map(),messages:new Map(),revisions:[],nacks:[],errors:[],closed:null};
 await new Promise((resolve,reject)=>{const timer=setTimeout(()=>{socket.terminate();reject(Error('Ready timeout'));},20000);
 socket.on('error',error=>{peer.errors.push(error.message);clearTimeout(timer);reject(error);});
 socket.on('close',code=>{peer.closed=code;});
 socket.on('message',raw=>{const time=performance.now();try{const e=JSON.parse(raw);if(e.type==='realtime.ready'){clearTimeout(timer);resolve();}if(e.type==='message.ack'){const a=peer.acks.get(e.client_message_id)??[];a.push({...e,time});peer.acks.set(e.client_message_id,a);peer.onAck?.(e);}if(e.type==='message.nack')peer.nacks.push(e);if(observe&&e.type==='message.committed'){const a=peer.messages.get(e.client_message_id)??[];a.push({...e,time});peer.messages.set(e.client_message_id,a);peer.revisions.push(e.revision);}}catch(error){peer.errors.push(error.message);}});
 });return peer;
}
function frame(actor,sequence,text){
 const id=randomUUID(),content={protocol:'secure-message-content',v:2,chat_id:actor.chat,client_message_id:id,sender_user_id:actor.user_id,sender_device_id:actor.device_id,message_type:'MESSAGE',text,attachments:[],mutation:null,reply_to_message_id:null};
 const request={client_message_id:id,sender_sequence:sequence,attachment_ids:[],recovery_envelopes:[],envelopes:[{recipient_user_id:actor.user_id,recipient_device_id:actor.device_id,protocol:'secure-messaging',protocol_version:2,header:'server-sqlite-v1',ciphertext:Buffer.from(JSON.stringify(content)).toString('base64url')}]};
 return{id,chat:actor.chat,text,sequence,actor,wire:JSON.stringify({type:'message.send',request}),queued:0};
}
async function settle(peers,writers,observers,count,timeout=120000){const deadline=Date.now()+timeout;while(writers.reduce((n,p)=>n+p.acks.size,0)<count||observers.reduce((n,p)=>n+p.messages.size,0)<count){
 const failures=peers.flatMap(p=>p.errors.concat(p.nacks.map(n=>n.error_type)));assert.equal(failures.length,0,failures.slice(0,5).join(', '));assert.ok(peers.every(p=>p.socket.readyState===WebSocket.OPEN),'unexpected disconnect');assert.ok(Date.now()<deadline,'Load timed out: '+JSON.stringify({acks:writers.reduce((n,p)=>n+p.acks.size,0),received:observers.reduce((n,p)=>n+p.messages.size,0)}));await sleep(5);
}}
async function runCase(definition){
 const {name,users,rooms,perUser,textBytes}=definition,s=await scenario(users,rooms),peers=[];
 try{
  const observers=[];for(const chat of s.chats){const p=await connect(chat,s.owner,true);observers.push(p);peers.push(p);}
  const writers=[];for(const actor of s.senders){const p=await connect(actor.chat,actor,false);writers.push(p);peers.push(p);}
  const records=new Map(),warmups=new Map();
  for(let i=0;i<writers.length;i++){const f=frame(s.senders[i],1,'warmup');warmups.set(f.id,f);writers[i].socket.send(f.wire);}
  await settle(peers,writers,observers,users);
  for(const p of peers){p.acks.clear();p.messages.clear();p.revisions=[];}
  const observerMap=new Map(observers.map(p=>[p.chat,p]));
  const prepared=[];for(let sequence=2;sequence<perUser+2;sequence++)for(let i=0;i<writers.length;i++){const f=frame(s.senders[i],sequence,'x'.repeat(textBytes));records.set(f.id,f);prepared.push({f,writer:writers[i]});}
  const before=serverSnapshot(),loop=monitorEventLoopDelay({resolution:10});loop.enable();const clientBefore=process.cpuUsage(),start=performance.now();
  const window=Number(process.env.RATCHET_BENCH_INFLIGHT??32);let next=0,inflight=0;const acknowledged=new Set();
  const pump=()=>{while(inflight<window&&next<prepared.length){const{f,writer}=prepared[next++];f.queued=performance.now();inflight++;writer.socket.send(f.wire);}};
  for(const writer of writers)writer.onAck=e=>{if(!records.has(e.client_message_id)||acknowledged.has(e.client_message_id))return;acknowledged.add(e.client_message_id);inflight--;pump();};
  pump();
  await settle(peers,writers,observers,records.size);const elapsed=performance.now()-start,clientCpu=process.cpuUsage(clientBefore);loop.disable();const after=serverSnapshot();
  const ackTimes=[],arrivalTimes=[],offeredCompletion=[],offeredArrival=[],clientQueue=[];let duplicates=0;
  for(const f of records.values()){
   const writer=writers[s.senders.indexOf(f.actor)],ack=writer.acks.get(f.id),received=observerMap.get(f.chat).messages.get(f.id);
   assert.equal(ack?.length,1,'exactly one ACK');assert.equal(received?.length,1,'exactly one recipient event');duplicates+=Math.max(0,received.length-1);assert.equal(ack[0].duplicate,false);assert.equal(ack[0].message_id,received[0].message_id);assert.equal(ack[0].revision,received[0].revision);assert.equal(received[0].sender_sequence,f.sequence);
   const content=JSON.parse(Buffer.from(received[0].envelope.ciphertext,'base64url'));assert.equal(content.text,f.text);assert.equal(content.sender_user_id,f.actor.user_id);assert.equal(content.sender_device_id,f.actor.device_id);ackTimes.push(ack[0].time-f.queued);arrivalTimes.push(received[0].time-f.queued);offeredCompletion.push(ack[0].time-start);offeredArrival.push(received[0].time-start);clientQueue.push(f.queued-start);
  }
  const all=new Map([...warmups,...records]);let recovered=0,pages=0;const recoveryStart=performance.now();
  for(const observer of observers){observer.socket.terminate();const reconnect=await connect(observer.chat,s.owner,false);peers.push(reconnect);let cursor=0,more=true;const seen=new Set();
   while(more){const r=await api(`/chats/${observer.chat}/sync?after_revision=${cursor}&limit=200`,{cookie:s.owner.cookie});assert.equal(r.status,200,JSON.stringify(r.value));pages++;assert.ok(pages<200);for(const e of r.value.changes){assert.equal(e.type,'message');const f=all.get(e.client_message_id);assert.ok(f);assert.equal(f.chat,observer.chat);assert.ok(!seen.has(e.client_message_id));seen.add(e.client_message_id);assert.equal(e.revision,++cursor);assert.equal(JSON.parse(Buffer.from(e.envelope.ciphertext,'base64url')).text,f.text);if(records.has(e.client_message_id))recovered++;}assert.equal(r.value.next_revision,cursor);more=r.value.has_more;}
   assert.equal(seen.size,[...all.values()].filter(f=>f.chat===observer.chat).length);
  }
  assert.equal(recovered,records.size);
  let timing_profile;
  if(process.env.RATCHET_BENCH_PROFILE==='1'){
   const samples=[...records.values()].map(f=>({id:f.id,chat:f.chat,sequence:f.sequence,ack_ms:writers[s.senders.indexOf(f.actor)].acks.get(f.id)[0].time-f.queued}));
   timing_profile=timingProfile(await readFile(process.env.RATCHET_BENCH_SERVER_LOG,'utf8'),samples,Math.floor(perUser/10)*users);
  }
  return{name,status:'passed',...(timing_profile?{timing_profile}:{}),users,rooms,per_user:perUser,text_bytes:textBytes,messages:records.size,max_global_inflight:window,fanout_sockets_per_room:1+users/rooms,elapsed_ms:round(elapsed),throughput_messages_s:round(records.size/(elapsed/1000)),ack:stats(ackTimes),recipient_arrival:stats(arrivalTimes),completion_from_offer:stats(offeredCompletion),recipient_from_offer:stats(offeredArrival),client_queue:stats(clientQueue),lost:0,duplicates,recovered,recovery_pages:pages,recovery_ms:round(performance.now()-recoveryStart),out_of_order_rooms:observers.filter(p=>p.revisions.some((v,i,a)=>i>0&&v<a[i-1])).length,server:aggregateCpu(before,after),load_generator:{cpu_ms:round((clientCpu.user+clientCpu.system)/1000),event_loop_p99_ms:round(loop.percentile(99)/1e6),event_loop_max_ms:round(loop.max/1e6)}};
 }catch(error){return{name,status:'failed',users,rooms,per_user:perUser,text_bytes:textBytes,error:error.message,acks:peers.reduce((n,p)=>n+p.acks.size,0),received:peers.reduce((n,p)=>n+p.messages.size,0),nacks:peers.flatMap(p=>p.nacks).map(e=>e.error_type),closed:peers.filter(p=>p.closed!==null).map(p=>p.closed)};}
 finally{for(const p of peers)p.socket.terminate();}
}
const smoke=process.env.RATCHET_BENCH_SMOKE==='1';
const smokeDefinition={name:'smoke30',users:1,rooms:1,perUser:30,textBytes:256};
const standardDefinitions=[
 {name:'1000-one-chat-256B',users:20,rooms:1,perUser:50,textBytes:256},
 {name:'1000-twenty-chats-256B',users:20,rooms:20,perUser:50,textBytes:256},
 {name:'2000-one-chat-256B',users:40,rooms:1,perUser:50,textBytes:256},
 {name:'1000-one-chat-4KiB',users:20,rooms:1,perUser:50,textBytes:4096},
];
const requestedCases=process.env.RATCHET_BENCH_CASES?.split(',').filter(Boolean);
const allDefinitions=[smokeDefinition,...standardDefinitions];
assert.ok(!requestedCases?.length||(new Set(requestedCases).size===requestedCases.length&&requestedCases.every(name=>allDefinitions.some(d=>d.name===name))),'Unknown or duplicate benchmark case');
const definitions=requestedCases?.length?requestedCases.map(name=>allDefinitions.find(d=>d.name===name)):smoke?[smokeDefinition]:standardDefinitions;
const results=[];for(const definition of definitions){const result=await runCase(definition);results.push(result);await writeFile(process.env.RATCHET_BENCH_OUTPUT,JSON.stringify(results,null,2));console.log('BENCH_CASE '+JSON.stringify(result));}
if(results.some(r=>r.status!=='passed'))process.exitCode=1;
