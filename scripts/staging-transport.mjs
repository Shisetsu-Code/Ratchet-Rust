import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import WebSocket from 'ws';

const state=JSON.parse(await readFile('.dev.vars.staging-accounts.json','utf8'));
const base='https://ratchet-rust-staging-20261015.braian-n-l.workers.dev';assert.equal(state.base,base);
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
 await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('WSS ready timeout')),30000);socket.on('error',reject);socket.on('message',raw=>{const e=JSON.parse(raw);if(e.type==='realtime.ready'){clearTimeout(timer);resolve();}if(e.type==='message.ack')peer.acks.push({...e,time:performance.now()});if(e.type==='message.committed')peer.messages.push({...e,time:performance.now()});if(e.type==='message.nack')peer.nacks.push(e);});});return peer;
}
async function waitFor(predicate,timeout=60000){const deadline=Date.now()+timeout;while(!predicate()){assert.ok(Date.now()<deadline,'WSS bounded wait');assert.equal(peers.flatMap(p=>p.nacks).length,0,'no rejected frames');await new Promise(resolve=>setTimeout(resolve,10));}}
try{
 const receiver=await open(adminCookie),sender=await open(customerCookie),queued=new Map(),start=performance.now();
 for(let sequence=1;sequence<=30;sequence++){
  const client=randomUUID(),text='Real staging burst '+sequence;
  const content={protocol:'secure-message-content',v:2,chat_id:chat,client_message_id:client,sender_user_id:claim.value.user_id,sender_device_id:customerDevice.device_id,message_type:'MESSAGE',text,attachments:[],mutation:null,reply_to_message_id:null};
  queued.set(client,{time:performance.now(),text});sender.socket.send(JSON.stringify({type:'message.send',request:{client_message_id:client,sender_sequence:sequence,attachment_ids:[],envelopes:[{recipient_user_id:admin.user_id,recipient_device_id:adminDevice.device_id,protocol:'secure-messaging',protocol_version:2,header:'server-sqlite-v1',ciphertext:Buffer.from(JSON.stringify(content)).toString('base64url')}]}}));
 }
 await waitFor(()=>sender.acks.length===30&&receiver.messages.length===30);
 assert.equal(new Set(sender.acks.map(e=>e.message_id)).size,30);assert.deepEqual(receiver.messages.map(e=>e.revision),Array.from({length:30},(_,i)=>i+1));
 for(const e of receiver.messages)assert.equal(JSON.parse(Buffer.from(e.envelope.ciphertext,'base64url')).text,queued.get(e.client_message_id).text);
 const times=receiver.messages.map(e=>e.time-queued.get(e.client_message_id).time).sort((a,b)=>a-b);
 console.log('RUST_STAGING_WSS '+JSON.stringify({messages:30,total_ms:Math.round(performance.now()-start),recipient_mean_ms:Math.round(times.reduce((a,b)=>a+b,0)/30),recipient_p95_ms:Math.round(times[28]),measurement:'Node WSS arrival; includes network; no browser render'}));
 receiver.socket.terminate();const reconnected=await open(adminCookie);
 const recovered=await api(`/chats/${chat}/sync?after_revision=0&limit=100`,{session:adminCookie});assert.equal(recovered.value.changes.length,30);assert.equal(new Set(recovered.value.changes.map(e=>e.message_id)).size,30);
 await api('/auth/password/reauth',{session:adminCookie,body:{password:state.admin.password}});
 const closed=new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('Revoked WSS remained active')),15000);reconnected.socket.once('close',code=>{clearTimeout(timer);resolve(code);});});
 await api('/auth/logout',{session:adminCookie,method:'POST',status:204});assert.equal(await closed,4001);
 await api('/sessions/current',{session:adminCookie,status:401});assert.equal(sender.socket.readyState,WebSocket.OPEN);
 console.log('Real Cloudflare 30-frame burst, exact HTTP recovery, reconnect, WSS revocation and unaffected customer: PASS');
 const native=spawnSync(process.env.RATCHET_PYTHON??'python',['tests/contracts/native-console.py'],{encoding:'utf8',windowsHide:true,env:{...process.env,RATCHET_TEST_BASE:base,RATCHET_TEST_OWNER_FILE:state.owner.keyPath,RATCHET_TEST_OWNER_PASSWORD:state.owner.keyPassword}});
 assert.equal(native.status,0,native.stderr);assert.equal(JSON.parse(native.stdout).native_console_verified,true);console.log('Native owner console using encrypted local key against Cloudflare: PASS');
}finally{for(const peer of peers)peer.socket.terminate();}
