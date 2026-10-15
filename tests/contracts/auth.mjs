import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,randomUUID,sign,randomBytes,createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import WebSocket from 'ws';

const base=process.env.RATCHET_TEST_BASE??'http://localhost:8797';
const token=process.env.RATCHET_TEST_BOOTSTRAP_TOKEN;
let cookie='',ownerId='',workspaceId='';
const deviceId=randomUUID();
const password='Test-only strong password 2026!';

async function request(path,{body,method=body?'POST':'GET',origin=base,session=cookie,headers={}}={}){
  const result=await fetch(base+'/api/v1'+path,{method,headers:{...(body?{'Content-Type':'application/json'}:{}),...(origin?{Origin:origin}:{}),...(session?{Cookie:session}:{}),...headers},body:body?JSON.stringify(body):undefined,signal:AbortSignal.timeout(60000)});
  const text=await result.text();let value;try{value=JSON.parse(text);}catch{value=text;}
  return{status:result.status,headers:result.headers,value};
}

test('health and anonymous sessions return explicit states with no-cache headers',async()=>{
  const health=await request('/health');assert.equal(health.status,200);assert.equal(health.value.runtime,'rust-wasm');
  assert.match(health.headers.get('Cache-Control'),/no-store/);
  const session=await request('/sessions/current');assert.equal(session.status,401);assert.equal(session.value.type,'SESSION_REQUIRED');
});

test('owner bootstrap verifies its signed challenge without creating a browser session',async()=>{
  assert.ok(token,'runner supplies a synthetic bootstrap token');
  const before=await request('/bootstrap/status');assert.equal(before.status,200);assert.equal(before.value.available,true);
  const{publicKey,privateKey}=generateKeyPairSync('ed25519');const key_id=randomUUID();
  const prepared=await request('/bootstrap/portable-key/prepare',{body:{bootstrap_token:token,key_id,public_key:publicKey.export({format:'jwk'}).x}});
  assert.equal(prepared.status,200,JSON.stringify(prepared.value));const challenge=prepared.value;
  const message=['ratchet-portable-key-v1','BOOTSTRAP',challenge.challenge_id,challenge.challenge,challenge.origin,challenge.key_id].join('\n');
  const signature=sign(null,Buffer.from(message),privateKey).toString('base64url');
  const completed=await request('/bootstrap/portable-key/complete',{body:{bootstrap_token:token,challenge_id:challenge.challenge_id,signature,login_name:'owner-test',master_password:password}});
  assert.equal(completed.status,200,JSON.stringify(completed.value));assert.equal(completed.headers.get('Set-Cookie'),null);ownerId=completed.value.user_id;workspaceId=completed.value.workspace_id;
  const after=await request('/bootstrap/status');assert.equal(after.value.available,false);
  const replay=await request('/bootstrap/portable-key/complete',{body:{bootstrap_token:token,challenge_id:challenge.challenge_id,signature,login_name:'owner-test',master_password:password}});
  assert.equal(replay.status,410);
});

test('password login authorizes a new browser and returns an owner membership',async()=>{
  const result=await request('/auth/password/login',{body:{login_name:'OWNER-TEST',password,device:{mode:'new',device_id:deviceId,display_name:'Contract browser',crypto_identity_public_key:'A'.repeat(43)}}});
  assert.equal(result.status,200,JSON.stringify(result.value));assert.equal(result.value.device_state,'AUTHORIZED');
  const set=result.headers.get('Set-Cookie');assert.ok(set);assert.match(set,/Secure/);assert.match(set,/HttpOnly/);assert.match(set,/SameSite=Strict/);cookie=set.split(';')[0];
  const current=await request('/sessions/current');assert.equal(current.status,200);assert.equal(current.value.user_id,ownerId);assert.equal(current.value.device_authorized,true);assert.equal(current.value.staff_memberships[0].staff_role,'OWNER');
  const sessions=await request('/sessions');assert.equal(sessions.status,200);assert.equal(sessions.value.sessions.length,1);
});

test('authenticated writes reject foreign origins and wrong passwords',async()=>{
  const foreign=await request('/auth/password/reauth',{origin:'https://foreign.test',body:{password}});assert.equal(foreign.status,403);assert.equal(foreign.value.type,'ORIGIN_MISMATCH');
  const wrong=await request('/auth/password/login',{body:{login_name:'owner-test',password:'Wrong password with enough chars',device:{mode:'existing',device_id:deviceId}}});assert.equal(wrong.status,401);assert.equal(wrong.value.type,'AUTHENTICATION_FAILED');
});

test('reauthentication updates the session and oversized bodies are rejected before parsing',async()=>{
  const verified=await request('/auth/password/reauth',{body:{password}});assert.equal(verified.status,200,JSON.stringify(verified.value));assert.equal(verified.value.verified,true);
  const current=await request('/sessions/current');assert.ok(current.value.authenticator_verified_at);
  const oversized=await request('/auth/password/login',{body:{padding:'x'.repeat(70*1024)}});assert.equal(oversized.status,413);
});

test('SQLite commits, WSS bursts, deduplication, sync and receipt ordering work together',async()=>{
  const customer=randomUUID(),customerDevice=randomUUID(),customerSession=randomUUID(),chat=randomUUID();
  const secret=randomBytes(32).toString('base64url'),hash=createHash('sha256').update(secret).digest('hex');
  const now=new Date().toISOString(),expires=new Date(Date.now()+86400000).toISOString();
  const sql=`INSERT INTO users(user_id,role,status,created_at,activated_at) VALUES('${customer}','CUSTOMER','ACTIVE','${now}','${now}');
INSERT INTO workspace_memberships(workspace_id,user_id,role,status,created_at) VALUES('${workspaceId}','${customer}','CUSTOMER','ACTIVE','${now}');
INSERT INTO devices(device_id,user_id,display_name,crypto_identity_public_key,created_at,authorized_at,last_seen_at) VALUES('${customerDevice}','${customer}','Customer test','${'A'.repeat(43)}','${now}','${now}','${now}');
INSERT INTO sessions(session_id,secret_hash,user_id,device_id,created_at,last_seen_at,expires_at) VALUES('${customerSession}','${hash}','${customer}','${customerDevice}','${now}','${now}','${expires}');
INSERT INTO chats(chat_id,workspace_id,created_by_user_id,created_at) VALUES('${chat}','${workspaceId}','${ownerId}','${now}');
INSERT INTO chat_participants(chat_id,user_id,participant_role,joined_at) VALUES('${chat}','${customer}','CUSTOMER','${now}');
INSERT INTO chat_revisions(chat_id) VALUES('${chat}');`;
  const file=join(process.env.RATCHET_TEST_STATE,'fixture.sql');await writeFile(file,sql);
  const fixture=spawnSync(process.execPath,['node_modules/wrangler/bin/wrangler.js','d1','execute','DB','--local','--config','wrangler.local.jsonc','--persist-to',process.env.RATCHET_TEST_STATE,'--file',file],{encoding:'utf8',windowsHide:true,env:process.env});
  assert.equal(fixture.status,0,fixture.stderr+fixture.stdout);
  const make=(sequence,text,id=randomUUID())=>{
    const content={protocol:'secure-message-content',v:2,chat_id:chat,client_message_id:id,sender_user_id:ownerId,sender_device_id:deviceId,message_type:'MESSAGE',text,attachments:[],mutation:null,reply_to_message_id:null};
    return{client_message_id:id,sender_sequence:sequence,envelopes:[{recipient_user_id:customer,recipient_device_id:customerDevice,protocol:'secure-messaging',protocol_version:2,header:'server-sqlite-v1',ciphertext:Buffer.from(JSON.stringify(content)).toString('base64url')}],attachment_ids:[]};
  };
  const first=make(1,'Persisted message');
  const accepted=await request(`/chats/${chat}/messages`,{body:first});assert.equal(accepted.status,201,JSON.stringify(accepted.value));
  const duplicate=await request(`/chats/${chat}/messages`,{body:first});assert.equal(duplicate.status,200,JSON.stringify(duplicate.value));assert.equal(duplicate.value.message_id,accepted.value.message_id);assert.equal(duplicate.value.duplicate,true);
  const conflict=await request(`/chats/${chat}/messages`,{body:make(1,'Changed body',first.client_message_id)});assert.equal(conflict.status,409);assert.equal(conflict.value.type,'IDEMPOTENCY_CONFLICT');
  const gap=await request(`/chats/${chat}/messages`,{body:make(40,'Wrong sequence')});assert.equal(gap.status,409);assert.equal(gap.value.expected_sender_sequence,2);
  const customerCookie='__Host-session='+secret;
  const open=async session=>{
    const socket=new WebSocket(base.replace('http','ws')+`/api/v1/chats/${chat}/realtime`,{headers:{Cookie:session,Origin:base}});const events=[];
    socket.on('message',data=>events.push({...JSON.parse(data.toString()),received_ms:performance.now()}));
    await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('WebSocket ready timeout')),10000);socket.on('message',data=>{if(JSON.parse(data.toString()).type==='realtime.ready'){clearTimeout(timer);resolve();}});socket.once('error',reject);});
    return{socket,events};
  };
  const sender=await open(cookie),recipient=await open(customerCookie);
  try{
    const start=performance.now(),sentAt=new Map();for(let i=0;i<30;i++){const input=make(i+2,'Burst '+i);sentAt.set(input.client_message_id,performance.now());sender.socket.send(JSON.stringify({type:'message.send',request:input}));}
    const deadline=Date.now()+30000;
    while(Date.now()<deadline&&(recipient.events.filter(e=>e.type==='message.committed').length<30||sender.events.filter(e=>e.type==='message.ack').length<30)&&!sender.events.some(e=>e.type==='message.nack'))await new Promise(resolve=>setTimeout(resolve,20));
    const received=recipient.events.filter(e=>e.type==='message.committed'),acks=sender.events.filter(e=>e.type==='message.ack'),nacks=sender.events.filter(e=>e.type==='message.nack');
    assert.equal(nacks.length,0,JSON.stringify(nacks.slice(0,2)));assert.equal(received.length,30);assert.equal(acks.length,30);assert.equal(new Set(received.map(e=>e.message_id)).size,30);
    assert.deepEqual(received.map(e=>e.revision),Array.from({length:30},(_,i)=>i+2));
    const times=received.map(e=>e.received_ms-sentAt.get(e.client_message_id)).sort((a,b)=>a-b),round=n=>Math.round(n*10)/10;
    console.log('Rust local message delivery ms',{count:times.length,burst_total:round(Math.max(...received.map(e=>e.received_ms))-start),mean:round(times.reduce((a,b)=>a+b,0)/times.length),p50:round(times[Math.floor(times.length*.5)]),p95:round(times[Math.ceil(times.length*.95)-1]),max:round(times.at(-1))});
    const sync=await request(`/chats/${chat}/sync?after_revision=0&limit=200`,{session:customerCookie});assert.equal(sync.status,200,JSON.stringify(sync.value));assert.equal(sync.value.changes.length,31);
    assert.equal(JSON.parse(Buffer.from(sync.value.changes[0].envelope.ciphertext,'base64url').toString()).text,'Persisted message');
    const page=await request(`/chats/${chat}/sync?after_revision=0&limit=10`,{session:customerCookie});assert.equal(page.value.changes.length,10);assert.equal(page.value.has_more,true);assert.equal(page.value.next_revision,10);
    const id=accepted.value.message_id,key=randomUUID();
    const read=await request(`/chats/${chat}/receipts`,{session:customerCookie,headers:{'Idempotency-Key':key},body:{message_id:id,state:'READ'}});assert.equal(read.status,200,JSON.stringify(read.value));
    const repeated=await request(`/chats/${chat}/receipts`,{session:customerCookie,headers:{'Idempotency-Key':key},body:{message_id:id,state:'READ'}});assert.equal(repeated.value.duplicate,true);
    const delivered=await request(`/chats/${chat}/receipts`,{session:customerCookie,headers:{'Idempotency-Key':randomUUID()},body:{message_id:id,state:'DELIVERED'}});assert.equal(delivered.value.state,'READ');assert.equal(delivered.value.duplicate,true);
    const denied=await request(`/chats/${randomUUID()}/messages/sender-sequence`,{session:customerCookie});assert.equal(denied.status,403);
  }finally{sender.socket.terminate();recipient.socket.terminate();}
});
