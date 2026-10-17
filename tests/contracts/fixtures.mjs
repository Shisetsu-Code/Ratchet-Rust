import assert from 'node:assert/strict';
import {readdir} from 'node:fs/promises';
import {join,resolve,dirname,basename} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {randomUUID,randomBytes,createHash} from 'node:crypto';

export const base=process.env.RATCHET_TEST_BASE??'http://localhost:8797';
// Miniflare models the trusted edge header locally. Independent contract files
// represent distinct networks; every retry and identity in one file keeps the
// same address, including the desktop-console child process. Never send these
// synthetic headers to a deployed Worker.
export function contractOriginHeaders(file=process.argv[1]??'contract-fixtures',origin=base){
  const url=new URL(origin);
  if(!['http:','https:'].includes(url.protocol)||!['localhost','127.0.0.1','[::1]'].includes(url.hostname))throw new Error('Synthetic edge addresses require a local contract server');
  const hash=createHash('sha256').update('ratchet-contract-origin-v1:'+basename(file)).digest('hex').slice(0,24);
  return{'CF-Connecting-IP':'2001:db8:'+hash.match(/.{4}/g).join(':')};
}
export const edgeHeaders=Object.freeze(contractOriginHeaders());
async function databasePath(){
  const state=resolve(process.env.RATCHET_TEST_STATE);
  assert.equal(dirname(state),resolve('.wrangler'));assert.match(basename(state),/^c-[a-f0-9]{8}$/);
  const directory=join(state,'v3','d1','miniflare-D1DatabaseObject');const files=[];
  for(const name of(await readdir(directory)).filter(n=>n.endsWith('.sqlite'))){
    const db=new DatabaseSync(join(directory,name),{readOnly:true});
    try{if(db.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='users'").get())files.push(name);}finally{db.close();}
  }
  assert.equal(files.length,1,'one synthetic D1 database in this test run');
  return join(directory,files[0]);
}
export async function localSql(sql){
  const db=new DatabaseSync(await databasePath());
  try{db.exec('PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; BEGIN IMMEDIATE;'+sql+'COMMIT;');}finally{db.close();}
}
export async function localRows(sql,parameters=[]){const db=new DatabaseSync(await databasePath(),{readOnly:true});try{return db.prepare(sql).all(...parameters);}finally{db.close();}}
export async function fixture(){
  const workspace_id=randomUUID(),user_id=randomUUID(),device_id=randomUUID(),session_id=randomUUID(),secret=randomBytes(32).toString('base64url');
  const hash=createHash('sha256').update(secret).digest('hex'),now=new Date().toISOString(),expires=new Date(Date.now()+86400000).toISOString();
  await localSql(`INSERT INTO workspaces(workspace_id,name,created_at) VALUES('${workspace_id}','Synthetic workspace','${now}');
INSERT INTO users(user_id,role,status,created_at,activated_at) VALUES('${user_id}','ADMIN','ACTIVE','${now}','${now}');
INSERT INTO workspace_memberships(workspace_id,user_id,role,status,created_at) VALUES('${workspace_id}','${user_id}','ADMIN','ACTIVE','${now}');
INSERT INTO workspace_staff(workspace_id,user_id,staff_role,display_name,created_at) VALUES('${workspace_id}','${user_id}','ADMIN','Synthetic admin','${now}');
INSERT INTO devices(device_id,user_id,display_name,crypto_identity_public_key,created_at,authorized_at,last_seen_at) VALUES('${device_id}','${user_id}','Synthetic browser','${'A'.repeat(43)}','${now}','${now}','${now}');
INSERT INTO sessions(session_id,secret_hash,user_id,device_id,created_at,last_seen_at,expires_at,authenticator_verified_at) VALUES('${session_id}','${hash}','${user_id}','${device_id}','${now}','${now}','${expires}','${now}');`);
  return{workspace_id,user_id,device_id,session_id,cookie:'__Host-session='+secret};
}
export async function api(path,{body,method=body?'POST':'GET',cookie='',headers={}}={}){
  const response=await fetch(base+'/api/v1'+path,{method,headers:{Origin:base,...edgeHeaders,...(body?{'Content-Type':'application/json'}:{}),...(cookie?{Cookie:cookie}:{}),...headers},body:body?JSON.stringify(body):undefined,signal:AbortSignal.timeout(60000)});
  const raw=await response.text();let value;try{value=JSON.parse(raw);}catch{value=raw;}
  return{status:response.status,headers:response.headers,value};
}
