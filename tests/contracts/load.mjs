import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,randomBytes,createHash} from 'node:crypto';
import WebSocket from 'ws';
import {base,fixture,localSql,api,edgeHeaders} from './fixtures.mjs';

const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const round=n=>Math.round(n*100)/100;
const percentile=(sorted,p)=>sorted[Math.min(sorted.length-1,Math.ceil(sorted.length*p)-1)];
function stats(values){const sorted=[...values].sort((a,b)=>a-b);return{count:sorted.length,mean_ms:round(sorted.reduce((a,b)=>a+b,0)/sorted.length),p50_ms:round(percentile(sorted,.5)),p95_ms:round(percentile(sorted,.95)),p99_ms:round(percentile(sorted,.99)),max_ms:round(sorted.at(-1))};}

async function scenario(senderCount){
  const owner=await fixture(),chat=randomUUID(),now=new Date().toISOString(),expires=new Date(Date.now()+86400000).toISOString();
  const senders=Array.from({length:senderCount},()=>({user_id:randomUUID(),device_id:randomUUID(),session_id:randomUUID(),secret:randomBytes(32).toString('base64url')}));
  let sql=`INSERT INTO chats(chat_id,workspace_id,created_by_user_id,owner_admin_user_id,created_at) VALUES('${chat}','${owner.workspace_id}','${owner.user_id}','${owner.user_id}','${now}');`;
  for(const a of senders){a.cookie='__Host-session='+a.secret;const hash=createHash('sha256').update(a.secret).digest('hex');sql+=`
INSERT INTO users(user_id,role,status,created_at,activated_at) VALUES('${a.user_id}','CUSTOMER','ACTIVE','${now}','${now}');
INSERT INTO customer_accounts(user_id,created_by_user_id,created_at) VALUES('${a.user_id}','${owner.user_id}','${now}');
INSERT INTO workspace_memberships(workspace_id,user_id,role,status,created_at) VALUES('${owner.workspace_id}','${a.user_id}','CUSTOMER','ACTIVE','${now}');
INSERT INTO devices(device_id,user_id,display_name,crypto_identity_public_key,created_at,authorized_at,last_seen_at) VALUES('${a.device_id}','${a.user_id}','Load fixture','${'A'.repeat(43)}','${now}','${now}','${now}');
INSERT INTO sessions(session_id,secret_hash,user_id,device_id,created_at,last_seen_at,expires_at) VALUES('${a.session_id}','${hash}','${a.user_id}','${a.device_id}','${now}','${now}','${expires}');
INSERT INTO chat_participants(chat_id,user_id,participant_role,joined_at) VALUES('${chat}','${a.user_id}','CUSTOMER','${now}');`;}
  await localSql(sql);return{owner,chat,senders};
}

async function open(chat,actor,{observe=false}={}){
  const socket=new WebSocket(base.replace(/^http/,'ws')+`/api/v1/chats/${chat}/realtime`,{closeTimeout:1000,headers:{Cookie:actor.cookie,Origin:base,...edgeHeaders}});
  const peer={socket,closed:null,acks:new Map(),nacks:new Map(),presented:new Map(),events:[],errors:[]};
  await new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{socket.terminate();reject(new Error('Local WebSocket ready timed out'));},15000);
    const fail=error=>{clearTimeout(timer);peer.errors.push(error);reject(error);};socket.on('error',fail);
    socket.on('message',raw=>{let e;try{e=JSON.parse(raw.toString());}catch(error){fail(error);return;}const received=performance.now();
      if(e.type==='realtime.ready'){clearTimeout(timer);resolve();}
      if(e.type==='message.ack'){assert.ok(!peer.acks.has(e.client_message_id),'one ACK per non-retried frame');peer.acks.set(e.client_message_id,{...e,received});}
      if(e.type==='message.nack')peer.nacks.set(e.client_message_id,{...e,received});
      if(observe&&e.type==='message.committed'){
        const content=JSON.parse(Buffer.from(e.envelope.ciphertext,'base64url').toString());
        const presented=performance.now();const list=peer.presented.get(e.client_message_id)??[];list.push({...e,content,received,presented});peer.presented.set(e.client_message_id,list);peer.events.push(e);
      }
    });
    socket.once('close',(code)=>{peer.closed=code;clearTimeout(timer);if(socket.readyState!==WebSocket.OPEN&&peer.events.length===0&&peer.acks.size===0)reject(new Error('Local WebSocket closed before messages: '+code));});
  });return peer;
}
function request(chat,actor,sequence,text){const client=randomUUID(),content={protocol:'secure-message-content',v:2,chat_id:chat,client_message_id:client,sender_user_id:actor.user_id,sender_device_id:actor.device_id,message_type:'MESSAGE',text,attachments:[],mutation:null,reply_to_message_id:null};return{client_message_id:client,sender_sequence:sequence,attachment_ids:[],envelopes:[{recipient_user_id:actor.user_id,recipient_device_id:actor.device_id,protocol:'secure-messaging',protocol_version:2,header:'server-sqlite-v1',ciphertext:Buffer.from(JSON.stringify(content)).toString('base64url')}]};}
function queue(peer,chat,actor,sequence,label,expected){const body=request(chat,actor,sequence,`${label}: sender ${actor.user_id} sequence ${sequence}`);const record={actor,sequence,text:JSON.parse(Buffer.from(body.envelopes[0].ciphertext,'base64url').toString()).text,queued:performance.now(),body};expected.set(body.client_message_id,record);peer.socket.send(JSON.stringify({type:'message.send',request:body}));return body;}
async function waitFor(predicate,peers,ms=60000){const until=Date.now()+ms;while(!predicate()){for(const p of peers){if(p.errors.length)throw p.errors[0];if(p.nacks.size)assert.fail('Unexpected local message NACK '+JSON.stringify([...p.nacks.values()].slice(0,3)));}assert.ok(Date.now()<until,'bounded local ACK/presentation wait; '+JSON.stringify(peers.map(p=>({acks:p.acks.size,shown:p.presented.size,nacks:p.nacks.size,state:p.socket.readyState,closed:p.closed}))));await sleep(10);}}
function validate(expected,peers,observer,label,start){const acks=new Map(peers.flatMap(p=>[...p.acks]));assert.equal(acks.size,expected.size);assert.equal(observer.presented.size,expected.size);const ackTimes=[],arrivalTimes=[],presentationTimes=[];
  for(const[id,want]of expected){const ack=acks.get(id);assert.ok(ack,id);assert.equal(ack.duplicate,false);const displayed=observer.presented.get(id);assert.equal(displayed.length,1,'no duplicate recipient presentation');const got=displayed[0];assert.equal(got.message_id,ack.message_id);assert.equal(got.revision,ack.revision);assert.equal(got.content.text,want.text);assert.equal(got.content.sender_user_id,want.actor.user_id);assert.equal(got.content.sender_device_id,want.actor.device_id);assert.equal(got.sender_sequence,want.sequence);ackTimes.push(ack.received-want.queued);arrivalTimes.push(got.received-want.queued);presentationTimes.push(got.presented-want.queued);}
  assert.deepEqual(observer.events.map(e=>e.revision),Array.from({length:expected.size},(_,i)=>i+1),'recipient revisions are contiguous and ordered');
  console.log('RUST_LOCAL_LOAD '+JSON.stringify({scenario:label,transport:new URL(base).protocol==='https:'?'wss':'ws',recipient:'Node network decode/presentation; no browser DOM',elapsed_ms:round(performance.now()-start),ack:stats(ackTimes),recipient_arrival:stats(arrivalTimes),recipient_presentation:stats(presentationTimes)}));return acks;
}
async function recover(chat,actor,expected,acks){let cursor=0,more=true;const changes=[];let pages=0;
  while(more){assert.ok(pages++<50,'finite HTTP recovery pagination');const page=await api(`/chats/${chat}/sync?after_revision=${cursor}&limit=200`,{cookie:actor.cookie});assert.equal(page.status,200,JSON.stringify(page.value));assert.ok(page.value.next_revision>=cursor);if(page.value.has_more)assert.ok(page.value.next_revision>cursor);changes.push(...page.value.changes);cursor=page.value.next_revision;more=page.value.has_more;}
  assert.equal(changes.length,expected.size,'every durable ACK is recoverable through authenticated HTTP');const seen=new Set();for(const change of changes){assert.equal(change.type,'message');const id=change.client_message_id,want=expected.get(id);assert.ok(want,'no foreign recovery ID');assert.ok(!seen.has(id),'one durable row per client ID');seen.add(id);assert.equal(change.message_id,acks.get(id).message_id);assert.equal(change.revision,acks.get(id).revision);assert.equal(JSON.parse(Buffer.from(change.envelope.ciphertext,'base64url').toString()).text,want.text);}assert.deepEqual(changes.map(c=>c.revision),Array.from({length:expected.size},(_,i)=>i+1));return pages;
}
async function burst(label,sendersCount,perSender){const s=await scenario(sendersCount),peers=[];let probe;try{const observer=await open(s.chat,s.owner,{observe:true});peers.push(observer);const writers=await Promise.all(s.senders.map(a=>open(s.chat,a)));peers.push(...writers);const expected=new Map(),start=performance.now();for(let sequence=1;sequence<=perSender;sequence++)for(let i=0;i<writers.length;i++)queue(writers[i],s.chat,s.senders[i],sequence,label,expected);
    if(process.env.RATCHET_LOAD_DIAGNOSTICS)probe=setInterval(async()=>{try{const r=await fetch(base+`/api/v1/chats/${s.chat}`,{headers:{Cookie:s.owner.cookie,...edgeHeaders},signal:AbortSignal.timeout(2000)});console.log('LOAD_PROGRESS',r.status,await r.text(),peers.map(p=>({state:p.socket.readyState,acks:p.acks.size,shown:p.presented.size,nacks:p.nacks.size})));}catch(e){console.log('LOAD_PROGRESS_FAILED',e.message);}},5000);
    await waitFor(()=>writers.reduce((n,p)=>n+p.acks.size,0)===expected.size&&observer.presented.size===expected.size,peers);const acks=validate(expected,writers,observer,label,start);
    observer.socket.terminate();const reconnect=await open(s.chat,s.owner);peers.push(reconnect);const pages=await recover(s.chat,s.owner,expected,acks);assert.equal(reconnect.socket.readyState,WebSocket.OPEN);
    for(let i=0;i<s.senders.length;i++){const sequence=await api(`/chats/${s.chat}/messages/sender-sequence`,{cookie:s.senders[i].cookie});assert.equal(sequence.status,200);assert.equal(sequence.value.next_sequence,perSender+1);}
    console.log('RUST_LOCAL_RECOVERY '+JSON.stringify({scenario:label,messages:expected.size,pages,unique_ids:expected.size,reconnected:true}));
  }finally{clearInterval(probe);for(const peer of peers)peer.socket.terminate();}}

test('local WebSocket burst 20: durable ACK, recipient presentation and recovery',{timeout:90000},()=>burst('burst20',1,20));
test('local WebSocket burst 30: durable ACK, recipient presentation and recovery',{timeout:90000},()=>burst('burst30',1,30));
test('three separate authorized customer accounts send 30 each to one chat concurrently',{timeout:90000},()=>burst('three-accounts-30-each',3,30));
test('1000 local WebSocket messages from 20 authorized accounts recover exactly once',{timeout:90000},()=>burst('1000-messages-20-accounts',20,50));
test('10 messages per second sustained for 120 messages preserve sequence and durable recovery',{timeout:90000},async()=>{
  const s=await scenario(1),peers=[];try{const observer=await open(s.chat,s.owner,{observe:true}),writer=await open(s.chat,s.senders[0]);peers.push(observer,writer);const expected=new Map(),start=performance.now();let nextSend=start;for(let i=0;i<120;i++){const delay=nextSend-performance.now();if(delay>0)await sleep(delay);queue(writer,s.chat,s.senders[0],i+1,'sustained-10-per-second',expected);nextSend=performance.now()+101;}assert.ok(performance.now()-start>=119*100,'actual paced send duration exceeds 11.9 seconds');await waitFor(()=>writer.acks.size===120&&observer.presented.size===120,peers);const acks=validate(expected,[writer],observer,'sustained-10-per-second',start);await recover(s.chat,s.owner,expected,acks);const sequence=await api(`/chats/${s.chat}/messages/sender-sequence`,{cookie:s.senders[0].cookie});assert.equal(sequence.value.next_sequence,121);
  }finally{for(const peer of peers)peer.socket.terminate();}
});
test('single administrator quota rejects the 101st burst frame with a retryable NACK',{timeout:90000},async()=>{
  const s=await scenario(0),peers=[];try{
    // A second authorized owner socket observes the same account independently.
    const observer=await open(s.chat,s.owner,{observe:true}),writer=await open(s.chat,s.owner);peers.push(observer,writer);
    const expected=new Map(),start=performance.now();for(let sequence=1;sequence<=101;sequence++)queue(writer,s.chat,s.owner,sequence,'administrator-user-quota',expected);
    const deadline=Date.now()+60000;while(writer.acks.size+writer.nacks.size<101){if(writer.errors.length)throw writer.errors[0];assert.ok(Date.now()<deadline,'quota frames settle within 60 seconds');await sleep(10);}
    assert.equal(writer.acks.size,100,'the rolling user quota admits 100 messages');assert.equal(writer.nacks.size,1,'one over-quota frame is rejected explicitly');const nack=[...writer.nacks.values()][0];assert.equal(nack.error_type,'MESSAGE_RATE_LIMITED');assert.equal(nack.retryable,true);
    const rejected=expected.get(nack.client_message_id);assert.equal(rejected.sequence,101);expected.delete(nack.client_message_id);
    await waitFor(()=>observer.presented.size===100,[observer]);const acks=validate(expected,[writer],observer,'administrator-user-quota-accepted',start);await recover(s.chat,s.owner,expected,acks);
    const sequence=await api(`/chats/${s.chat}/messages/sender-sequence`,{cookie:s.owner.cookie});assert.equal(sequence.status,200);assert.equal(sequence.value.next_sequence,101,'rejected frame does not consume a sender sequence');
    console.log('RUST_LOCAL_QUOTA '+JSON.stringify({attempted:101,acknowledged:100,rejected:1,error_type:nack.error_type,retryable:nack.retryable}));
  }finally{for(const peer of peers)peer.socket.terminate();}
});
