import assert from 'node:assert/strict';
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import WebSocket from 'ws';

const prototypeDirectory='.wrangler/prototype-comparison-20261016';
const provenance=JSON.parse(await readFile(prototypeDirectory+'/provenance.json','utf8'));
const sessions=JSON.parse(JSON.parse(await readFile(prototypeDirectory+'/private.json','utf8')).LAB_SESSIONS);
const state=JSON.parse(await readFile('.dev.vars.staging-accounts.json','utf8'));
const rust='https://ratchet-rust-staging-20261015.braian-n-l.workers.dev';assert.equal(state.base,rust);
assert.equal(provenance.base,'https://ratchet-prototype-compare-20261016.braian-n-l.workers.dev');
assert.ok(Date.parse(provenance.expires)>Date.now());
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const connections=[],runs=[],participants=[];
const stats=values=>{const sorted=[...values].sort((a,b)=>a-b);assert.ok(sorted.length);return{n:sorted.length,mean_ms:sorted.reduce((a,b)=>a+b,0)/sorted.length,p50_ms:sorted[Math.ceil(sorted.length*.5)-1],p95_ms:sorted[Math.ceil(sorted.length*.95)-1],min_ms:sorted[0],max_ms:sorted.at(-1)};};
async function api(path,{body,cookie='',status=200}={}){
 const response=await fetch(rust+'/api/v1'+path,{method:body?'POST':'GET',headers:{Origin:rust,...(body?{'Content-Type':'application/json'}:{}),...(cookie?{Cookie:cookie}:{})},body:body?JSON.stringify(body):undefined,signal:AbortSignal.timeout(30000)});
 assert.equal(response.status,status,'Rust API '+path+' status');return{value:await response.json(),cookie:response.headers.get('set-cookie')?.split(';')[0]};
}
const device=()=>({mode:'new',device_id:randomUUID(),display_name:'Paired remote comparison',crypto_identity_public_key:'A'.repeat(43)});
async function rustAdapter(){
 const adminDevice=device(),login=await api('/auth/password/login',{body:{login_name:state.admin.login,password:state.admin.password,device:adminDevice}});
 const admin=(await api('/sessions/current',{cookie:login.cookie})).value;
 const invitation=await api('/invitations',{cookie:login.cookie,status:201,body:{kind:'REFERRAL',workspace_id:admin.staff_memberships[0].workspace_id}});
 const customerDevice=device(),claim=await api('/lead-access/claim',{body:{invitation_token:invitation.value.token,device:customerDevice},status:201});
 const chat=claim.value.chat_id;
 return{label:'rust',base:rust,senderCookie:claim.cookie,receiverCookie:login.cookie,path:`/api/v1/chats/${chat}/realtime`,ready:'realtime.ready',ack:'message.ack',message:'message.committed',nack:'message.nack',
  packet(id,sequence,text){const content={protocol:'secure-message-content',v:2,chat_id:chat,client_message_id:id,sender_user_id:claim.value.user_id,sender_device_id:customerDevice.device_id,message_type:'MESSAGE',text,attachments:[],mutation:null,reply_to_message_id:null};return{type:'message.send',request:{client_message_id:id,sender_sequence:sequence,attachment_ids:[],envelopes:[{recipient_user_id:admin.user_id,recipient_device_id:adminDevice.device_id,protocol:'secure-messaging',protocol_version:2,header:'server-sqlite-v1',ciphertext:Buffer.from(JSON.stringify(content)).toString('base64url')}]}};},
  id:event=>event.client_message_id,text:event=>JSON.parse(Buffer.from(event.envelope.ciphertext,'base64url')).text,
  async recover(){const rows=[];let after=0;while(true){const result=await api(`/chats/${chat}/sync?after_revision=${after}&limit=100`,{cookie:login.cookie});const changes=result.value.changes;if(!changes.length)break;rows.push(...changes);const next=changes.at(-1).revision;assert.ok(next>after,'sync cursor advances');after=next;}return rows;}
 };
}
function prototypeAdapter(){const secret=user=>Object.entries(sessions).find(([,s])=>s.user===user)[0];return{label:'prototype',base:provenance.base,senderCookie:'session='+secret('sender'),receiverCookie:'session='+secret('receiver'),path:'/messages',ready:'ready',ack:'ack',message:'message',nack:'nack',packet:(id,seq,text)=>({type:'send',id,seq,text}),id:event=>event.id,text:event=>event.text};}
async function connect(adapter,cookie){
 const socket=new WebSocket(adapter.base.replace(/^http/,'ws')+adapter.path,{headers:{Origin:adapter.base,Cookie:cookie},closeTimeout:1000});connections.push(socket);
 const peer={socket,events:[]};
 await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error(adapter.label+' ready timeout')),30000);socket.on('error',error=>{clearTimeout(timer);reject(error);});socket.on('unexpected-response',(_r,response)=>{response.resume();clearTimeout(timer);reject(Error(adapter.label+' handshake '+response.statusCode));});socket.on('message',data=>{const event=JSON.parse(data);peer.events.push({event,time:performance.now()});if(event.type===adapter.ready){clearTimeout(timer);resolve();}});});return peer;
}
async function waitFor(check){const deadline=Date.now()+30000;while(!check()){for(const adapter of participants){const rejected=adapter.sender.events.find(x=>x.event.type===adapter.nack);assert.ok(!rejected,adapter.label+' NACK '+(rejected?.event.error_type??rejected?.event.error));}assert.ok(Date.now()<deadline,'bounded wait');await delay(5);}}
async function initialize(adapter){adapter.sender=await connect(adapter,adapter.senderCookie);adapter.receiver=await connect(adapter,adapter.receiverCookie);adapter.sequence=(adapter.sender.events.find(x=>x.event.type===adapter.ready)?.event.next??1)-1;adapter.measured=[];participants.push(adapter);return adapter;}
async function sendCase(adapter,round,mode,count){
 const expected=new Map(),start=performance.now();let bytes=0;
 for(let index=0;index<count;index++){
  if(mode==='paced'&&index>0)await delay(125);
  const id=randomUUID(),text=('SYNTHETIC-'+id).padEnd(256,'x');
  const packet=JSON.stringify(adapter.packet(id,++adapter.sequence,text));
  bytes+=Buffer.byteLength(packet);expected.set(id,{start:performance.now(),text});adapter.sender.socket.send(packet);
  if(mode==='individual')await waitFor(()=>adapter.sender.events.some(x=>x.event.type===adapter.ack&&adapter.id(x.event)===id)&&adapter.receiver.events.some(x=>x.event.type===adapter.message&&adapter.id(x.event)===id));
 }
 await waitFor(()=>[...expected.keys()].every(id=>adapter.sender.events.some(x=>x.event.type===adapter.ack&&adapter.id(x.event)===id)&&adapter.receiver.events.some(x=>x.event.type===adapter.message&&adapter.id(x.event)===id)));
 assert.equal(adapter.sender.events.filter(x=>x.event.type===adapter.nack).length,0,adapter.label+' no NACK');
 const rows=[...expected].map(([id,sent])=>{
  const arrivals=adapter.receiver.events.filter(x=>x.event.type===adapter.message&&adapter.id(x.event)===id),acks=adapter.sender.events.filter(x=>x.event.type===adapter.ack&&adapter.id(x.event)===id);
  assert.equal(arrivals.length,1);assert.equal(acks.length,1);assert.equal(adapter.text(arrivals[0].event),sent.text);
  return{id,arrival_ms:arrivals[0].time-sent.start,ack_ms:acks[0].time-sent.start,server_timing:acks[0].event.timing??null};
 });
 const actualOrder=adapter.receiver.events.filter(x=>x.event.type===adapter.message&&expected.has(adapter.id(x.event))).map(x=>adapter.id(x.event));assert.deepEqual(actualOrder,[...expected.keys()]);
 adapter.measured.push(...rows.map(row=>row.id));
 const result={label:adapter.label,round,mode,count,payload_text_bytes:256,wire_bytes:bytes,arrival:stats(rows.map(x=>x.arrival_ms)),ack:stats(rows.map(x=>x.ack_ms)),whole_case_ms:performance.now()-start,rows};
 if(round>=0){runs.push(result);await writeFile('.wrangler/paired-remote-partial.json',JSON.stringify({at:new Date().toISOString(),runs},null,2));console.log(JSON.stringify({...result,rows:undefined}));}
}
try{
 const adapters={prototype:await initialize(prototypeAdapter()),rust:await initialize(await rustAdapter())};
 for(const adapter of Object.values(adapters)){await sendCase(adapter,-1,'individual',1);await delay(1200);}
 for(let round=0;round<3;round++)for(const mode of ['individual','burst','paced']){
  const order=round%2?['rust','prototype']:['prototype','rust'];
  for(const label of order){await delay(1200);await sendCase(adapters[label],round,mode,mode==='individual'?10:mode==='burst'?8:30);}
 }
 const recovery={};
 for(const adapter of Object.values(adapters)){
  if(adapter.label==='rust'){
   const rows=await adapter.recover();assert.equal(rows.length,adapter.sequence);assert.equal(new Set(rows.map(x=>x.message_id)).size,adapter.sequence);recovery.rust=rows.length;
  }else{
   const peer=await connect(adapter,adapter.receiverCookie),seen=[];peer.socket.on('message',raw=>{const e=JSON.parse(raw);if(e.type==='message')seen.push(e);});peer.socket.send(JSON.stringify({type:'sync',after:0}));await waitFor(()=>peer.events.some(x=>x.event.type==='sync.done'));assert.equal(seen.length,adapter.sequence);assert.equal(new Set(seen.map(x=>x.id)).size,adapter.sequence);recovery.prototype=seen.length;
  }
 }
 const summary=[];for(const label of ['prototype','rust'])for(const mode of ['individual','burst','paced']){const rows=runs.filter(r=>r.label===label&&r.mode===mode).flatMap(r=>r.rows);summary.push({label,mode,arrival:stats(rows.map(r=>r.arrival_ms)),ack:stats(rows.map(r=>r.ack_ms))});}
 const result={at:new Date().toISOString(),measurement:'Single Node monotonic clock, WSS send to recipient callback; same connection and equal 256-byte text. Excludes both application UIs. Sequential individual messages, 8-message bursts, and 30 messages at target 8/s; same WSS connections reused; alternating order.',provenance,rust_base:rust,recovery,summary,runs};
 await mkdir('experiments/backend-benchmark/paired-remote-results',{recursive:true});await writeFile('experiments/backend-benchmark/paired-remote-results/'+Date.now()+'.json',JSON.stringify(result,null,2));console.log('PAIRED_SUMMARY '+JSON.stringify({summary,recovery}));
}finally{for(const socket of connections)socket.terminate();}
