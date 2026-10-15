import assert from 'node:assert/strict';
import {randomUUID,randomBytes,createHash,generateKeyPairSync,sign,pbkdf2Sync} from 'node:crypto';
import {fixture,api,localSql,base} from './fixtures.mjs';
const f=await fixture(),cookie=f.cookie;
const b64=b=>Buffer.from(b).toString('base64url');
function cborHead(type,n){if(n<24)return Buffer.from([(type<<5)|n]);if(n<256)return Buffer.from([(type<<5)|24,n]);return Buffer.from([(type<<5)|25,n>>8,n&255]);}
function cbor(v){if(Buffer.isBuffer(v))return Buffer.concat([cborHead(2,v.length),v]);if(Number.isInteger(v))return cborHead(v<0?1:0,v<0?-1-v:v);if(v instanceof Map)return Buffer.concat([cborHead(5,v.size),...Array.from(v,([k,v])=>Buffer.concat([cbor(k),cbor(v)]))]);throw Error('CBOR fixture type');}
for(const route of ['/auth/passkey/register/options','/auth/passkey/register/verify']){const r=await api(route,{body:{}});assert.equal(r.status,410);assert.equal(r.value.type,'ACCESS_PASSKEY_ENROLLMENT_DISABLED');}
assert.equal((await api('/devices',{cookie})).status,200);
const pending=randomUUID(),now=new Date().toISOString(),identity='B'.repeat(43);
await localSql(`INSERT INTO devices(device_id,user_id,display_name,crypto_identity_public_key,created_at) VALUES('${pending}','${f.user_id}','Pending','${identity}','${now}');`);
assert.equal((await api(`/devices/${pending}/approve`,{cookie,body:{}})).value.type,'DEVICE_CRYPTO_NOT_READY');
function publication(){return{identity_public_key:identity,signed_prekey:{prekey_id:randomUUID(),public_key:'C'.repeat(43),signature:'S'.repeat(86)},pq_last_resort_prekey:{prekey_id:randomUUID(),public_key:'P'.repeat(64),signature:'S'.repeat(86)},ec_one_time_prekeys:[{prekey_id:randomUUID(),public_key:'E'.repeat(43)}],pq_one_time_prekeys:[{prekey_id:randomUUID(),public_key:'Q'.repeat(64),signature:'S'.repeat(86)}]};}
// The pending session may publish keys but cannot consume or authorize a device.
const pendingSecret=randomBytes(32).toString('base64url'),pendingSession=randomUUID(),expiry=new Date(Date.now()+86400000).toISOString();
await localSql(`INSERT INTO sessions(session_id,secret_hash,user_id,device_id,created_at,last_seen_at,expires_at) VALUES('${pendingSession}','${createHash('sha256').update(pendingSecret).digest('hex')}','${f.user_id}','${pending}','${now}','${now}','${expiry}');`);
const pendingCookie='__Host-session='+pendingSecret,pub=publication();
assert.equal((await api('/crypto/prekeys',{cookie:pendingCookie,body:pub})).status,204);
assert.equal((await api('/crypto/prekeys',{cookie:pendingCookie,body:pub})).status,204,'same key publication is idempotent');
let status=await api('/crypto/prekeys/status',{cookie:pendingCookie});assert.equal(status.status,200);assert.equal(status.value.ec_available,1);assert.equal(status.value.pq_available,1);
const bad=structuredClone(pub);bad.ec_one_time_prekeys[0].public_key='X'.repeat(43);assert.equal((await api('/crypto/prekeys',{cookie:pendingCookie,body:bad})).value.type,'PREKEY_CONFLICT');
assert.equal((await api(`/devices/${pending}/approve`,{cookie,body:{}})).value.type,'DEVICE_CERTIFICATE_REQUIRED');
const certificate=b64(JSON.stringify({payload:{protocol:'secure-device-certificate',version:1,user_id:f.user_id,device_id:pending,signer_device_id:f.device_id,crypto_identity_public_key:identity},signature:b64(Buffer.alloc(64,7))}));
assert.equal((await api(`/devices/${pending}/certificate`,{cookie,body:{certificate}})).status,200);
assert.equal((await api(`/devices/${pending}/approve`,{cookie,body:{}})).status,200);
const chat=randomUUID();await localSql(`INSERT INTO chats(chat_id,workspace_id,created_by_user_id,owner_admin_user_id,created_at) VALUES('${chat}','${f.workspace_id}','${f.user_id}','${f.user_id}','${now}');`);
const discovery=await api(`/crypto/devices/${f.user_id}/bundle?chat_id=${chat}`,{cookie});assert.equal(discovery.status,200);assert.equal(discovery.value.devices.length,1);assert.equal(discovery.value.devices[0].device_id,pending);
const consumptions=await Promise.all(Array.from({length:2},()=>api('/crypto/prekeys/consume',{cookie,body:{chat_id:chat,recipient_user_id:f.user_id,recipient_device_id:pending}})));for(const r of consumptions)assert.equal(r.status,200,JSON.stringify(r.value));assert.equal(consumptions.filter(r=>r.value.ec_one_time_prekey).length,1);assert.equal(consumptions.filter(r=>r.value.pq_one_time_prekey).length,1);
status=await api('/crypto/prekeys/status',{cookie:pendingCookie});assert.equal(status.value.ec_available,0);assert.equal(status.value.pq_available,0);

const customer=randomUUID(),invitation=randomUUID(),token=randomBytes(32).toString('base64url'),loginName='customer-'+customer,password='synthetic secure password 2026',salt=randomBytes(16),verifier=pbkdf2Sync(password,salt,600000,32,'sha256'),customerDevice=randomUUID();
await localSql(`INSERT INTO users(user_id,role,status,created_at) VALUES('${customer}','CUSTOMER','INVITED','${now}');
INSERT INTO workspace_memberships(workspace_id,user_id,role,status,created_at) VALUES('${f.workspace_id}','${customer}','CUSTOMER','PENDING','${now}');
INSERT INTO password_credentials(user_id,login_name,algorithm,iterations,salt,verifier,created_at,updated_at) VALUES('${customer}','${loginName}','PBKDF2-SHA256',600000,'${b64(salt)}','${b64(verifier)}','${now}','${now}');
INSERT INTO invitations(invitation_id,kind,workspace_id,chat_id,customer_user_id,token_hash,created_by_user_id,expires_at,status,created_at) VALUES('${invitation}','ACCESS','${f.workspace_id}','${chat}','${customer}','${createHash('sha256').update(token).digest('hex')}','${f.user_id}','${expiry}','ACTIVE','${now}');`);
const activation={access_token:token,login_name:loginName,password,device:{mode:'new',device_id:customerDevice,display_name:'Synthetic customer',crypto_identity_public_key:'Z'.repeat(43)}};
assert.equal((await api('/auth/password/activate',{body:{...activation,password:'incorrect synthetic password'}})).status,401);
const activated=await api('/auth/password/activate',{body:activation});assert.equal(activated.status,201,JSON.stringify(activated.value));assert.equal(activated.value.user_id,customer);assert.equal((await api('/auth/password/activate',{body:activation})).value.type,'INVITATION_USED');

const keys=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),jwk=keys.publicKey.export({format:'jwk'}),credential=b64(randomBytes(32));
const cose=cbor(new Map([[1,2],[3,-7],[-1,1],[-2,Buffer.from(jwk.x,'base64url')],[-3,Buffer.from(jwk.y,'base64url')]]));
await localSql(`INSERT INTO passkeys(credential_id,user_id,device_id,public_key,counter,created_at,webauthn_user_id) VALUES('${credential}','${f.user_id}','${f.device_id}',X'${cose.toString('hex')}',0,'${now}','${b64(f.user_id)}');`);
function assertion(options,count,changes={}){const clientDataJSON=b64(JSON.stringify({type:'webauthn.get',challenge:options.challenge,origin:base,crossOrigin:false,...changes}));const ad=Buffer.alloc(37);createHash('sha256').update('localhost').digest().copy(ad);ad[32]=5;ad.writeUInt32BE(count,33);const signature=sign('sha256',Buffer.concat([ad,createHash('sha256').update(Buffer.from(clientDataJSON,'base64url')).digest()]),keys.privateKey);return{id:credential,rawId:credential,type:'public-key',response:{clientDataJSON,authenticatorData:b64(ad),signature:b64(signature),userHandle:b64(f.user_id)}};}
const opts=(await api('/auth/passkey/login/options',{body:{}})).value;
let response=assertion(opts.options,1);
const verify={challenge_id:opts.challenge_id,response,device:{mode:'existing',device_id:f.device_id}};
let login=await api('/auth/passkey/login/verify',{body:verify});assert.equal(login.status,200,JSON.stringify(login.value));assert.equal(login.value.user_id,f.user_id);assert.ok(login.headers.get('set-cookie').includes('__Host-session='));
assert.equal((await api('/auth/passkey/login/verify',{body:verify})).value.type,'CHALLENGE_CONSUMED');
for(const changes of [{origin:'https://attacker.invalid'},{challenge:b64(randomBytes(32))},{crossOrigin:true}]){const o=(await api('/auth/passkey/login/options',{body:{}})).value;assert.equal((await api('/auth/passkey/login/verify',{body:{...verify,challenge_id:o.challenge_id,response:assertion(o.options,2,changes)}})).value.type,'WEBAUTHN_VERIFICATION_FAILED');}
const ro=(await api('/auth/passkey/reauth/options',{cookie,body:{}})).value;
const ra={challenge_id:ro.challenge_id,response:assertion(ro.options,2)};
let reauth=await api('/auth/passkey/reauth/verify',{cookie,body:ra});assert.equal(reauth.status,200,JSON.stringify(reauth.value));assert.equal(reauth.value.verified,true);
const clone=(await api('/auth/passkey/login/options',{body:{}})).value;assert.equal((await api('/auth/passkey/login/verify',{body:{...verify,challenge_id:clone.challenge_id,response:assertion(clone.options,2)}})).value.type,'WEBAUTHN_VERIFICATION_FAILED');
const tamper=(await api('/auth/passkey/login/options',{body:{}})).value;const altered=assertion(tamper.options,3);altered.response.signature=b64(randomBytes(70));assert.equal((await api('/auth/passkey/login/verify',{body:{...verify,challenge_id:tamper.challenge_id,response:altered}})).value.type,'WEBAUTHN_VERIFICATION_FAILED');
for(const [kind,algorithm] of [['rsa',-257],['ed25519',-8]]){
  const pair=generateKeyPairSync(kind,kind==='rsa'?{modulusLength:2048}:{}),j=pair.publicKey.export({format:'jwk'}),cred=b64(randomBytes(32));
  const publicCose=kind==='rsa'?cbor(new Map([[1,3],[3,algorithm],[-1,Buffer.from(j.n,'base64url')],[-2,Buffer.from(j.e,'base64url')]])):cbor(new Map([[1,1],[3,algorithm],[-1,6],[-2,Buffer.from(j.x,'base64url')]]));
  await localSql(`INSERT INTO passkeys(credential_id,user_id,device_id,public_key,counter,created_at) VALUES('${cred}','${f.user_id}','${f.device_id}',X'${publicCose.toString('hex')}',0,'${now}');`);
  const o=(await api('/auth/passkey/login/options',{body:{}})).value,clientDataJSON=b64(JSON.stringify({type:'webauthn.get',challenge:o.options.challenge,origin:base})),ad=Buffer.alloc(37);createHash('sha256').update('localhost').digest().copy(ad);ad[32]=5;ad.writeUInt32BE(1,33);
  const signature=sign(kind==='rsa'?'sha256':null,Buffer.concat([ad,createHash('sha256').update(Buffer.from(clientDataJSON,'base64url')).digest()]),pair.privateKey);
  const result=await api('/auth/passkey/login/verify',{body:{...verify,challenge_id:o.challenge_id,response:{id:cred,rawId:cred,type:'public-key',response:{clientDataJSON,authenticatorData:b64(ad),signature:b64(signature)}}}});assert.equal(result.status,200,kind+': '+JSON.stringify(result.value));
}
console.log('Identity contracts passed: pending device publication, certificate approval, real ES256 login/reauth, replay/counter/origin/challenge/signature rejection.');
