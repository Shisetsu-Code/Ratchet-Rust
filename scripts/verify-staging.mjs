import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import {generateKeyPairSync,randomBytes,randomUUID,sign,pbkdf2Sync,createCipheriv,createDecipheriv} from 'node:crypto';
import {spawn} from 'node:child_process';

// Dedicated Rust staging only. No SQL fixtures, access to old deployments, or secret output.
const base='https://ratchet-rust-staging-20261015.braian-n-l.workers.dev';
const secrets=JSON.parse(await readFile('.dev.vars.staging.json','utf8'));
const statePath='.dev.vars.staging-accounts.json';
const password=()=>randomBytes(24).toString('base64url')+'aA9!';
let state;
try{state=JSON.parse(await readFile(statePath,'utf8'));}catch(error){
 if(error.code!=='ENOENT')throw error;
 const keys=generateKeyPairSync('ed25519'),jwk=keys.privateKey.export({format:'jwk'}),keyPassword=password(),salt=randomBytes(16),iv=randomBytes(12),keyId=randomUUID();
 const metadata={format:'ratchet-portable-key',version:1,key_id:keyId,public_key:jwk.x,kdf:{name:'PBKDF2-SHA256',iterations:600000,salt:salt.toString('base64url')},cipher:{name:'AES-256-GCM',iv:iv.toString('base64url')}};
 const cipher=createCipheriv('aes-256-gcm',pbkdf2Sync(keyPassword,salt,600000,32,'sha256'),iv);cipher.setAAD(Buffer.from(JSON.stringify(metadata)));
 const bytes=Buffer.concat([cipher.update(JSON.stringify({private_seed:jwk.d,public_key:jwk.x})),cipher.final(),cipher.getAuthTag()]);
 const keyPath='.dev.vars.staging-owner.ratchet-key';
 await writeFile(keyPath,JSON.stringify({...metadata,cipher:{...metadata.cipher,ciphertext:bytes.toString('base64url')}}),{flag:'wx',mode:0o600});
 state={base,owner:{keyId,keyPath,keyPassword,publicKey:jwk.x,login:'rust-owner-'+randomUUID().slice(0,8),password:password()},admin:{login:'rust-admin-'+randomUUID().slice(0,8),password:password()}};
 await writeFile(statePath,JSON.stringify(state,null,2),{flag:'wx',mode:0o600});
}
assert.equal(state.base,base);
const ownerFile=JSON.parse(await readFile(state.owner.keyPath,'utf8'));
const aad={...ownerFile,cipher:{name:ownerFile.cipher.name,iv:ownerFile.cipher.iv}};
const encrypted=Buffer.from(ownerFile.cipher.ciphertext,'base64url');
const decipher=createDecipheriv('aes-256-gcm',pbkdf2Sync(state.owner.keyPassword,Buffer.from(ownerFile.kdf.salt,'base64url'),600000,32,'sha256'),Buffer.from(ownerFile.cipher.iv,'base64url'));decipher.setAAD(Buffer.from(JSON.stringify(aad)));decipher.setAuthTag(encrypted.subarray(-16));
const opened=JSON.parse(Buffer.concat([decipher.update(encrypted.subarray(0,-16)),decipher.final()]));
const {createPrivateKey}=await import('node:crypto');
const privateKey=createPrivateKey({key:{kty:'OKP',crv:'Ed25519',d:opened.private_seed,x:opened.public_key},format:'jwk'});
async function api(path,body){
 const response=await fetch(base+'/api/v1'+path,{method:body?'POST':'GET',headers:{Origin:base,...(body?{'Content-Type':'application/json'}:{})},body:body?JSON.stringify(body):undefined,signal:AbortSignal.timeout(60000)});
 const raw=await response.text();let value;try{value=JSON.parse(raw);}catch{value=raw;}
 assert.equal(response.status,200,path+' HTTP '+response.status+' '+JSON.stringify(value));return{response,value};
}
const signature=c=>sign(null,Buffer.from(['ratchet-portable-key-v1',c.purpose,c.challenge_id,c.challenge,c.origin,c.key_id].join('\n')),privateKey).toString('base64url');
const health=await api('/health');assert.equal(health.value.runtime,'rust-wasm');
if((await api('/bootstrap/status')).value.available){
 const {value:c}=await api('/bootstrap/portable-key/prepare',{bootstrap_token:secrets.BOOTSTRAP_TOKEN,key_id:state.owner.keyId,public_key:state.owner.publicKey});
 const result=await api('/bootstrap/portable-key/complete',{bootstrap_token:secrets.BOOTSTRAP_TOKEN,challenge_id:c.challenge_id,signature:signature(c),login_name:state.owner.login,master_password:state.owner.password});
 assert.equal(result.response.headers.get('Set-Cookie'),null);console.log('Remote owner bootstrap and encrypted console key: PASS');
}
// Each run uses an isolated administrator so previous test chats cannot satisfy UI assertions.
if(state.admin.provisioned)state.admin={login:'rust-admin-'+randomUUID().slice(0,8),password:password()};
if(!state.admin.provisioned){
 const {value:c}=await api('/admin-provisioning/portable-key/prepare',{bootstrap_token:secrets.BOOTSTRAP_TOKEN,owner_key_id:state.owner.keyId});
 const keys=generateKeyPairSync('ed25519');
 await api('/admin-provisioning/portable-key/complete',{bootstrap_token:secrets.BOOTSTRAP_TOKEN,challenge_id:c.challenge_id,signature:signature(c),key_id:randomUUID(),public_key:keys.publicKey.export({format:'jwk'}).x,login_name:state.admin.login,master_password:state.admin.password});
 state.admin.provisioned=true;await writeFile(statePath,JSON.stringify(state,null,2),{mode:0o600});console.log('Remote signed administrator provisioning: PASS');
}
console.log('Running real desktop/mobile browser flow against isolated Rust Cloudflare staging.');
const child=spawn(process.execPath,['--test','tests/contracts/browser.mjs'],{stdio:'inherit',windowsHide:true,env:{...process.env,RATCHET_TEST_BASE:base,RATCHET_BROWSER_LOGIN:state.admin.login,RATCHET_BROWSER_PASSWORD:state.admin.password}});
const code=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',resolve);});assert.equal(code,0,'Remote browser flow');
const transport=spawn(process.execPath,['scripts/staging-transport.mjs'],{stdio:'inherit',windowsHide:true,env:process.env});
const transportCode=await new Promise((resolve,reject)=>{transport.once('error',reject);transport.once('exit',resolve);});assert.equal(transportCode,0,'Remote transport flow');
console.log('Staging verification passed. Credentials and encrypted owner key remain in ignored local files.');
