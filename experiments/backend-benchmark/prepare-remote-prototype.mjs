import {readFile,writeFile,mkdir,copyFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {randomBytes,randomUUID,createHash} from 'node:crypto';
const directory=resolve('.wrangler/prototype-comparison-20261016');
await mkdir(directory,{recursive:false});
const source=resolve('../sqlite-chat-poc'),hashes={};
for(const file of ['worker.mjs','core.mjs','client.html']){
 await copyFile(resolve(source,file),resolve(directory,file));
 hashes[file]=createHash('sha256').update(await readFile(resolve(directory,file))).digest('hex');
}
const expires=Date.now()+4*60*60*1000,sessions={};
for(const user of ['sender','receiver'])sessions[randomBytes(32).toString('base64url')]={user,sessionId:randomUUID(),expires,member:true,role:'admin'};
const config={name:'ratchet-prototype-compare-20261016',account_id:'3904fa9871c00ad145ed8f8f5404d1bd',main:'worker.mjs',compatibility_date:'2026-09-23',workers_dev:true,preview_urls:false,vars:{LAB_RUN:randomUUID(),LAB_EXPIRES:String(expires)},durable_objects:{bindings:[{name:'ROOM',class_name:'SqliteChat'}]},migrations:[{tag:'v1',new_sqlite_classes:['SqliteChat']}],rules:[{type:'Text',globs:['**/*.html'],fallthrough:true}]};
await writeFile(resolve(directory,'wrangler.jsonc'),JSON.stringify(config,null,2));
await writeFile(resolve(directory,'private.json'),JSON.stringify({LAB_SESSIONS:JSON.stringify(sessions),DATA_KEY:randomBytes(32).toString('base64')}),{mode:0o600});
await writeFile(resolve(directory,'provenance.json'),JSON.stringify({source:'../sqlite-chat-poc',hashes,code_changes:false,expires:new Date(expires).toISOString(),base:'https://'+config.name+'.braian-n-l.workers.dev'},null,2));
console.log('Temporary copy prepared; original code unchanged; secrets remain ignored.');
