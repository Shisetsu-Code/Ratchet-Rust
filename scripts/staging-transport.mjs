import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import WebSocket from 'ws';

const state=JSON.parse(await readFile('.dev.vars.staging-accounts.json','utf8'));
const base='https://ratchet-rust-staging-20261015.braian-n-l.workers.dev';assert.equal(state.base,base);
const paced=process.env.RATCHET_TRANSPORT_PROFILE==='paced';
const spacing= paced ? Number(process.env.RATCHET_TRANSPORT_SPACING_MS??100) : 0;
assert.ok(Number.isFinite(spacing)&&(!paced||(spacing>=100&&spacing<=5000)),'paced spacing must be 100..5000 ms');
const count=Number(process.env.RATCHET_TRANSPORT_COUNT??30);
assert.ok(Number.isInteger(count)&&count>=1&&count<=300,'count must be 1..300');
const observations=[];
const network={health_roundtrips_ms:[],wss_ping_roundtrips_ms:[]};
for(let sample=0;sample<3;sample++){const started=performance.now();await fetch(base+'/api/v1/health',{signal:AbortSignal.timeout(15000)}).then(async response=>{assert.equal(response.status,200);await response.arrayBuffer();});network.health_roundtrips_ms.push(performance.now()-started);}
const cookie=result=>result.headers.get('set-cookie').split(';')[0];
async function api(path,{body,session='',method=body?'POST':'GET',status=200}={}){
 const response=await fetch(base+'/api/v1'+path,{method,headers:{Origin:base,...(body?{'Content-Type':'application/json'}:{}),...(session?{Cookie:session}:{})},body:body?JSON.stringify(body):undefined,signal:AbortSignal.timeout(60000)});
 const raw=await response.text();let value;try{value=JSON.parse(raw);}catch{value=raw;}
 assert.equal(response.status,status,path+' '+JSON.stringify(value));return{value,headers:response.headers};
}
const device=()=>({mode:'new',device_id:randomUUID(),display_name:'Rust staging transport test',crypto_identity_public_key:'A'.repeat(43)});
const adminDevice=device(),adminLogin=await api('/auth/password/login',{body:{login_name:state.admin.login,password:state.admin.password,device:adminDevice}}),adminCookie=cookie(adminLogin);
const admin=(await api('/sessions/current',{session:adminCookie})).value;
const push=(await api('/push/config',{session:adminCookie})).value;assert.equal(push.enabled,true);assert.equal(typeof push.application_server_key,'string');
const invitation=await api('/invitations',{session:adminCookie,body:{kind:'REFERRAL',workspace_id:admin.staff_memberships[0].workspace_id},status:201});
const customerDevice=device(),claim=await api('/lead-access/claim',{body:{invitation_token:invitation.value.token,device:customerDevice},status:201}),customerCookie=cookie(claim),chat=claim.value.chat_id;
const peers=[];
async function open(session){
 const socket=new WebSocket(base.replace(/^http/,'ws')+`/api/v1/chats/${chat}/realtime`,{closeTimeout:1000,headers:{Origin:base,Cookie:session}});
 const peer={socket,acks:[],messages:[],nacks:[]};peers.push(peer);
 await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('WSS ready timeout')),30000);socket.on('error',error=>{clearTimeout(timer);reject(error);});socket.on('unexpected-response',(_request,response)=>{let body='';response.on('data',chunk=>{body=(body+chunk).slice(0,1024);});response.on('end',()=>{clearTimeout(timer);let code='unparsed';try{const value=JSON.parse(body);code=value.error?.code??value.code??value.type??'unknown';}catch{}reject(Error('WSS handshake HTTP '+response.statusCode+' code='+code));});});socket.on('message',raw=>{const e=JSON.parse(raw);if(e.type==='realtime.ready'){clearTimeout(timer);resolve();}if(e.type==='message.ack')peer.acks.push({...e,time:performance.now()});if(e.type==='message.committed')peer.messages.push({...e,time:performance.now()});if(e.type==='message.nack')peer.nacks.push(e);});});return peer;
}
async function waitFor(predicate,timeout=60000){const deadline=Date.now()+timeout;while(!predicate()){assert.ok(Date.now()<deadline,'WSS bounded wait');for(const nack of peers.flatMap(p=>p.nacks))assert.ok(['MESSAGE_RATE_LIMITED','CUSTOMER_MESSAGE_RATE_LIMITED','SENDER_SEQUENCE_GAP'].includes(nack.error_type),'unexpected NACK '+nack.error_type);await new Promise(resolve=>setTimeout(resolve,10));}}
try{
 const receiver=await open(adminCookie),sender=await open(customerCookie),queued=new Map();
 for(let sample=0;sample<3;sample++){
  const elapsed=await new Promise(resolve=>{const started=performance.now(),token=randomUUID();const pong=data=>{if(data.toString()!==token)return;clearTimeout(timer);sender.socket.off('pong',pong);resolve(performance.now()-started);};const timer=setTimeout(()=>{sender.socket.off('pong',pong);resolve(null);},3000);sender.socket.on('pong',pong);sender.socket.ping(token);});
  network.wss_ping_roundtrips_ms.push(elapsed);
 }
 const start=performance.now();
 for(let sequence=1;sequence<=count;sequence++){
  if(sequence>1&&spacing)await new Promise(resolve=>setTimeout(resolve,spacing));
  const client=randomUUID(),text='Real staging burst '+sequence;
  const content={protocol:'secure-message-content',v:2,chat_id:chat,client_message_id:client,sender_user_id:claim.value.user_id,sender_device_id:customerDevice.device_id,message_type:'MESSAGE',text,attachments:[],mutation:null,reply_to_message_id:null};
  const frame=JSON.stringify({type:'message.send',request:{client_message_id:client,sender_sequence:sequence,attachment_ids:[],envelopes:[{recipient_user_id:admin.user_id,recipient_device_id:adminDevice.device_id,protocol:'secure-messaging',protocol_version:2,header:'server-sqlite-v1',ciphertext:Buffer.from(JSON.stringify(content)).toString('base64url')}]}});
  queued.set(client,{time:performance.now(),text,frame});sender.socket.send(frame);
 }
 // Resolve all original attempts before replaying missing IDs in sender order.
 await waitFor(()=>sender.acks.length+sender.nacks.length>=count);
 for(const [client,record] of queued){
  const deadline=Date.now()+60000;
  while(!sender.acks.some(e=>e.client_message_id===client)){
   assert.ok(Date.now()<deadline,'bounded ordered quota recovery');
   const rejected=sender.nacks.length;sender.socket.send(record.frame);
   await waitFor(()=>sender.acks.some(e=>e.client_message_id===client)||sender.nacks.length>rejected);
   if(!sender.acks.some(e=>e.client_message_id===client))await new Promise(resolve=>setTimeout(resolve,250));
  }
 }
 await waitFor(()=>sender.acks.length===count&&receiver.messages.length===count);
 assert.equal(new Set(sender.acks.map(e=>e.message_id)).size,count);assert.deepEqual(receiver.messages.map(e=>e.revision),Array.from({length:count},(_,i)=>i+1));
 for(const e of receiver.messages)assert.equal(JSON.parse(Buffer.from(e.envelope.ciphertext,'base64url')).text,queued.get(e.client_message_id).text);
 const times=receiver.messages.map(e=>e.time-queued.get(e.client_message_id).time).sort((a,b)=>a-b);
 const ackTimes=sender.acks.map(e=>e.time-queued.get(e.client_message_id).time).sort((a,b)=>a-b);
 const summary=values=>({min_ms:values[0],mean_ms:values.reduce((a,b)=>a+b,0)/values.length,p50_ms:values[Math.ceil(values.length*.5)-1],p95_ms:values[Math.ceil(values.length*.95)-1],max_ms:values.at(-1)});
 observations.push({profile:paced?`${1000/spacing}-per-second`:'burst',messages:count,nacks:sender.nacks.reduce((result,e)=>(result[e.error_type]=(result[e.error_type]??0)+1,result),{}),total_ms:performance.now()-start,recipient:summary(times),ack:summary(ackTimes),samples:receiver.messages.map(e=>({revision:e.revision,arrival_ms:e.time-queued.get(e.client_message_id).time})),measurement:'Node WSS arrival and durable ACK on one monotonic clock; includes network and any ordered retries; excludes browser render'});
 const {samples,...display}=observations[0];console.log('RUST_STAGING_WSS '+JSON.stringify(display));
 receiver.socket.terminate();const reconnected=await open(adminCookie);
 const recovered=[];let after=0;
 while(recovered.length<count){const page=await api(`/chats/${chat}/sync?after_revision=${after}&limit=100`,{session:adminCookie});assert.ok(page.value.changes.length>0,'sync makes progress');recovered.push(...page.value.changes);after=page.value.changes.at(-1).revision;}
 assert.equal(recovered.length,count);assert.equal(new Set(recovered.map(e=>e.message_id)).size,count);
 await api('/auth/password/reauth',{session:adminCookie,body:{password:state.admin.password}});
 const closed=new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('Revoked WSS remained active')),15000);reconnected.socket.once('close',code=>{clearTimeout(timer);resolve(code);});});
 await api('/auth/logout',{session:adminCookie,method:'POST',status:204});assert.equal(await closed,4001);
 await api('/sessions/current',{session:adminCookie,status:401});assert.equal(sender.socket.readyState,WebSocket.OPEN);
 console.log('Real Cloudflare '+count+' frames, exact HTTP recovery, reconnect, WSS revocation and unaffected customer: PASS');
 const native=spawnSync(process.env.RATCHET_PYTHON??'python',['tests/contracts/native-console.py'],{encoding:'utf8',windowsHide:true,env:{...process.env,RATCHET_TEST_BASE:base,RATCHET_TEST_OWNER_FILE:state.owner.keyPath,RATCHET_TEST_OWNER_PASSWORD:state.owner.keyPassword}});
 assert.equal(native.status,0,native.stderr);assert.equal(JSON.parse(native.stdout).native_console_verified,true);console.log('Native owner console using encrypted local key against Cloudflare: PASS');
 await mkdir('experiments/backend-benchmark/remote-results',{recursive:true});
 await writeFile('experiments/backend-benchmark/remote-results/'+new Date().toISOString().replaceAll(':','-')+'.json',JSON.stringify({base,network,network_caveat:'Control-frame ping may terminate at the edge; it does not locate the Durable Object or isolate server processing.',verified:{ordered_delivery:true,exact_http_recovery:true,reconnect:true,logout_revocation:true,owner_console:true},observations},null,2));
}finally{for(const peer of peers)peer.socket.terminate();}
