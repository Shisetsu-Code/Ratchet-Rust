import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import WebSocket from 'ws';
import {base,fixture,api,localSql} from './fixtures.mjs';

const device=()=>({device_id:randomUUID(),display_name:'Synthetic access browser',crypto_identity_public_key:'A'.repeat(43)});
const cookie=r=>r.headers.get('Set-Cookie')?.split(';')[0];
function ok(r,status=201){assert.equal(r.status,status,JSON.stringify(r.value));return r.value;}

test('operator grants enforce independent administrator boundaries, single claim, and revocation',async()=>{
 const a=await fixture(),b=await fixture();
 const operator=ok(await api('/operators',{cookie:a.cookie,body:{workspace_id:a.workspace_id,display_name:'Synthetic operator'}}));
 assert.equal(operator.access_mode,'LINK');assert.equal(operator.login_name,null);
 const denied=await api(`/operators/${operator.user_id}/access-grants?workspace_id=${a.workspace_id}`,{cookie:b.cookie,body:{}});assert.equal(denied.status,403);
 const now=new Date().toISOString();
 await localSql(`INSERT INTO workspace_memberships(workspace_id,user_id,role,status,created_at) VALUES('${a.workspace_id}','${b.user_id}','ADMIN','ACTIVE','${now}'); INSERT INTO workspace_staff(workspace_id,user_id,staff_role,display_name,created_at) VALUES('${a.workspace_id}','${b.user_id}','ADMIN','Independent admin','${now}');`);
 const unrelated=await api(`/operators/${operator.user_id}/access-grants?workspace_id=${a.workspace_id}`,{cookie:b.cookie,body:{}});assert.equal(unrelated.status,404);
 const independentList=ok(await api(`/operators?workspace_id=${a.workspace_id}`,{cookie:b.cookie}),200);assert.ok(!independentList.operators.some(r=>r.user_id===operator.user_id));
 const grant=ok(await api(`/operators/${operator.user_id}/access-grants?workspace_id=${a.workspace_id}`,{cookie:a.cookie,body:{}}));
 const grants=ok(await api(`/operators/${operator.user_id}/access-grants?workspace_id=${a.workspace_id}`,{cookie:a.cookie}),200);assert.ok(grants.grants.some(g=>g.grant_id===grant.grant_id));assert.ok(grants.grants.every(g=>!('token' in g)));
 const renamed=await api('/sessions/current/display-name',{cookie:a.cookie,method:'PATCH',body:{workspace_id:a.workspace_id,display_name:'Updated administrator'}});ok(renamed,200);assert.equal(renamed.value.display_name,'Updated administrator');
 const claims=await Promise.all([1,2].map(()=>api('/operator-access/claim',{body:{access_token:grant.token,device:device()}})));
 assert.equal(claims.filter(r=>r.status===201).length,1,JSON.stringify(claims.map(r=>r.value)));
 const active=claims.find(r=>r.status===201);assert.equal(active.value.user_id,operator.user_id);
 const current=await api('/sessions/current',{cookie:cookie(active)});ok(current,200);assert.equal(current.value.staff_memberships[0].staff_role,'OPERATOR');
 const list=ok(await api(`/operators?workspace_id=${a.workspace_id}`,{cookie:a.cookie}),200);assert.equal(list.operators.find(r=>r.user_id===operator.user_id).active_device_count,1);
 const used=await api(`/operators/${operator.user_id}/access-grants/${grant.grant_id}?workspace_id=${a.workspace_id}`,{cookie:a.cookie,method:'DELETE'});assert.equal(used.status,409);
 const pending=ok(await api(`/operators/${operator.user_id}/access-grants?workspace_id=${a.workspace_id}`,{cookie:a.cookie,body:{}}));
 ok(await api(`/operators/${operator.user_id}?workspace_id=${a.workspace_id}`,{cookie:a.cookie,method:'DELETE'}),204);
 const revoked=await api('/sessions/current',{cookie:cookie(active)});assert.ok([401,403].includes(revoked.status));
 const cannotClaim=await api('/operator-access/claim',{body:{access_token:pending.token,device:device()}});assert.notEqual(cannotClaim.status,201);
});

test('referral guests become accounts, access is single-use, and password reset invalidates sessions',async()=>{
 const a=await fixture(),b=await fixture();
 const invitation=ok(await api('/invitations',{cookie:a.cookie,body:{kind:'REFERRAL',workspace_id:a.workspace_id}}));
 const guest=await api('/lead-access/claim',{body:{invitation_token:invitation.token,device:device()}});ok(guest);const chat=guest.value.chat_id;
 const wrong=await api(`/leads/${chat}/account`,{cookie:b.cookie,body:{display_name:'Forbidden'}});assert.equal(wrong.status,403);
 const login='customer-'+randomUUID();
 const account=ok(await api(`/leads/${chat}/account`,{cookie:a.cookie,body:{display_name:'Synthetic customer',login_name:login,password:'Synthetic customer password 2026!'}}));
 assert.equal(account.customer_user_id,guest.value.user_id);
 const claimed=await api('/lead-access/customer/claim',{body:{access_token:account.token,device:device()}});ok(claimed);
 const replay=await api('/lead-access/customer/claim',{body:{access_token:account.token,device:device()}});assert.notEqual(replay.status,201);
 const duplicate=await api(`/leads/${chat}/account`,{cookie:a.cookie,body:{display_name:'Duplicate'}});assert.equal(duplicate.status,409);
 const renewed=ok(await api(`/leads/${chat}/access`,{cookie:a.cookie,body:{}}));assert.equal(renewed.customer_user_id,guest.value.user_id);
 ok(await api(`/leads/${chat}/account/password`,{cookie:a.cookie,method:'PUT',body:{login_name:login,password:'Replacement customer password 2026!'}}),200);
 assert.equal((await api('/sessions/current',{cookie:cookie(guest)})).status,401);
 assert.equal((await api('/sessions/current',{cookie:cookie(claimed)})).status,401);
 const loginResponse=await api('/auth/password/login',{body:{login_name:login,password:'Replacement customer password 2026!',device:{mode:'new',...device()}}});ok(loginResponse,200);
});

test('ACCESS invitations register customers; referral claims are idempotent and owners cannot administer operators',async()=>{
 const a=await fixture();
 const access=ok(await api('/invitations',{cookie:a.cookie,body:{kind:'ACCESS',workspace_id:a.workspace_id,login_name:'invited-'+randomUUID(),password:'Synthetic invitation password 2026!'}}));
 const customer=await api('/lead-access/customer/claim',{body:{access_token:access.token,device:device()}});ok(customer);
 const referral=ok(await api('/invitations',{cookie:a.cookie,body:{kind:'REFERRAL',workspace_id:a.workspace_id}}));
 const first=ok(await api(`/invitations/${referral.token}/claim`,{cookie:cookie(customer),body:{}}),200);
 const again=ok(await api(`/invitations/${referral.token}/claim`,{cookie:cookie(customer),body:{}}),200);assert.equal(first.chat_id,again.chat_id);assert.equal(again.duplicate,true);
 await localSql(`UPDATE workspace_staff SET staff_role='OWNER' WHERE workspace_id='${a.workspace_id}' AND user_id='${a.user_id}';`);
 const ownerDenied=await api('/operators',{cookie:a.cookie,body:{workspace_id:a.workspace_id,display_name:'Forbidden owner operator'}});assert.equal(ownerDenied.status,403);assert.equal(ownerDenied.value.type,'WORKSPACE_ADMIN_REQUIRED');
});

test('operator account creation cannot replace a preexisting customer password without an account marker',async()=>{
 const a=await fixture(),login='existing-'+randomUUID(),original='Existing customer password 2026!';
 const access=ok(await api('/invitations',{cookie:a.cookie,body:{kind:'ACCESS',workspace_id:a.workspace_id,login_name:login,password:original}}));
 // Model an active legacy customer whose password exists before customer_accounts.
 await localSql(`UPDATE users SET status='ACTIVE' WHERE user_id='${access.customer_user_id}'; UPDATE workspace_memberships SET status='ACTIVE' WHERE workspace_id='${a.workspace_id}' AND user_id='${access.customer_user_id}';`);
 const operator=ok(await api('/operators',{cookie:a.cookie,body:{workspace_id:a.workspace_id,display_name:'Account operator'}}));
 const grant=ok(await api(`/operators/${operator.user_id}/access-grants?workspace_id=${a.workspace_id}`,{cookie:a.cookie,body:{}}));
 const session=await api('/operator-access/claim',{body:{access_token:grant.token,device:device()}});ok(session);
 const attempted=await api(`/leads/${access.chat_id}/account`,{cookie:cookie(session),body:{display_name:'Attempted overwrite',login_name:login,password:'Unauthorized replacement password 2026!'}});
 assert.equal(attempted.status,409,JSON.stringify(attempted.value));assert.equal(attempted.value.type,'CUSTOMER_ACCOUNT_EXISTS');
 const originalLogin=await api('/auth/password/login',{body:{login_name:login,password:original,device:{mode:'new',...device()}}});ok(originalLogin,200);
 const replacementLogin=await api('/auth/password/login',{body:{login_name:login,password:'Unauthorized replacement password 2026!',device:{mode:'new',...device()}}});assert.equal(replacementLogin.status,401);
});

test('changing a staff display name refreshes an already open WebSocket lease',async()=>{
 const a=await fixture(),chat=randomUUID(),now=new Date().toISOString();
 await localSql(`INSERT INTO chats(chat_id,workspace_id,created_by_user_id,owner_admin_user_id,created_at) VALUES('${chat}','${a.workspace_id}','${a.user_id}','${a.user_id}','${now}');`);
 const events=[],socket=new WebSocket(base.replace(/^http/,'ws')+`/api/v1/chats/${chat}/realtime`,{closeTimeout:1000,headers:{Cookie:a.cookie,Origin:base}});
 try{
  await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('WSS ready timeout')),10000);socket.on('error',reject);socket.on('message',raw=>{const e=JSON.parse(raw);events.push(e);if(e.type==='realtime.ready'){clearTimeout(timer);resolve();}});});
  const send=async(sequence,expected)=>{
   const client=randomUUID(),content={protocol:'secure-message-content',v:2,chat_id:chat,client_message_id:client,sender_user_id:a.user_id,sender_device_id:a.device_id,message_type:'MESSAGE',text:'Name lease '+sequence,attachments:[],mutation:null,reply_to_message_id:null};
   socket.send(JSON.stringify({type:'message.send',request:{client_message_id:client,sender_sequence:sequence,attachment_ids:[],envelopes:[{recipient_user_id:a.user_id,recipient_device_id:a.device_id,protocol:'secure-messaging',protocol_version:2,header:'server-sqlite-v1',ciphertext:Buffer.from(JSON.stringify(content)).toString('base64url')}]}}));
   const deadline=Date.now()+10000;while(!events.some(e=>e.type==='message.committed'&&e.client_message_id===client)){assert.ok(Date.now()<deadline,'message after rename');await new Promise(r=>setTimeout(r,10));}
   assert.equal(events.find(e=>e.type==='message.committed'&&e.client_message_id===client).sender_display_name,expected);
  };
  await send(1,'Synthetic admin');ok(await api('/sessions/current/display-name',{cookie:a.cookie,method:'PATCH',body:{workspace_id:a.workspace_id,display_name:'Current staff name'}}),200);await send(2,'Current staff name');assert.equal(socket.readyState,WebSocket.OPEN);
 }finally{socket.terminate();}
});
