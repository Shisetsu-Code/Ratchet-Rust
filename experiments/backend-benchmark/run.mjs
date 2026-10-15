import {spawn,spawnSync,execFileSync} from 'node:child_process';
import {readFile,writeFile,mkdir,rm,readdir} from 'node:fs/promises';
import {createWriteStream} from 'node:fs';
import {resolve,dirname,basename,join} from 'node:path';
import {randomUUID,randomBytes,createHash} from 'node:crypto';
import os from 'node:os';
import assert from 'node:assert/strict';

const root=process.cwd(),reference=resolve(process.env.RATCHET_TYPESCRIPT_SOURCE??'../Ratchet-SQLite');
const wrangler=resolve('node_modules/wrangler/bin/wrangler.js'),base='http://localhost:8797';
const profile=process.argv.includes('--profile');
const variantsIndex=process.argv.indexOf('--variants'),variants=variantsIndex>=0?process.argv[variantsIndex+1]?.split(','):['typescript','rust'];
assert.ok(variants?.length&&new Set(variants).size===variants.length&&variants.every(v=>['typescript','rust'].includes(v)),'--variants expects rust, typescript, or typescript,rust');
const caseNames=['smoke30','1000-one-chat-256B','1000-twenty-chats-256B','2000-one-chat-256B','1000-one-chat-4KiB'];
const casesIndex=process.argv.indexOf('--cases'),cases=casesIndex>=0?process.argv[casesIndex+1]?.split(','):null;
assert.ok(cases===null||(cases?.length&&new Set(cases).size===cases.length&&cases.every(name=>caseNames.includes(name))),'--cases expects comma-separated benchmark case names');
const smoke=process.argv.includes('--smoke'),roundIndex=process.argv.indexOf('--rounds'),rounds=roundIndex>=0?Number(process.argv[roundIndex+1]):3;
const windowIndex=process.argv.indexOf('--inflight'),window=windowIndex>=0?Number(process.argv[windowIndex+1]):32;
assert.ok(Number.isInteger(window)&&window>=1&&window<=5000);
assert.ok(Number.isInteger(rounds)&&rounds>=1&&rounds<=10);
const output=resolve('experiments/backend-benchmark/results',new Date().toISOString().replace(/[:.]/g,'-'));
await mkdir(output,{recursive:true});
const sha=b=>createHash('sha256').update(b).digest('hex');
const manifest=JSON.parse(await readFile('baseline/source-manifest.json','utf8'));
const entries=manifest.files.filter(f=>f.path.startsWith('src/worker/'));
const changed=[];const hashes=[];
for(const entry of entries){const hash=sha(await readFile(join(reference,entry.path)));hashes.push(entry.path+':'+hash);if(hash!==entry.sha256)changed.push(entry.path);}
const revision=directory=>execFileSync('git',['rev-parse','HEAD'],{cwd:directory,encoding:'utf8'}).trim();
const rustSourcePaths=(await readdir('crates',{recursive:true})).filter(path=>/^(core|worker)[\\/]src[\\/].*\.(rs|sql)$/.test(path)).sort();
const rustSourceHashes=await Promise.all(rustSourcePaths.map(async path=>[path.replaceAll('\\','/'),sha(await readFile(join('crates',path)))]));
const metadata={date:new Date().toISOString(),method:'Local workerd runs; same machine, runtime, compatibility date, limits, payload, WebSocket clients and verifier. Synthetic isolated state; no deployments.',rounds,smoke,profiling:profile,variants,cases,node:process.version,wrangler:JSON.parse(await readFile('node_modules/wrangler/package.json','utf8')).version,workerd:JSON.parse(await readFile('node_modules/workerd/package.json','utf8')).version,compatibility_date:'2026-10-15',cpu:os.cpus()[0].model,logical_cpus:os.cpus().length,total_memory_bytes:os.totalmem(),rust_commit:revision(root),rust_wasm_sha256:sha(await readFile('crates/worker/build/index_bg.wasm')),typescript_head:revision(reference),typescript_working_tree_matches_migration_baseline:changed.length===0,typescript_backend_source_sha256:sha(hashes.sort().join('\n')),typescript_changed_since_baseline:changed,limits_note:'Production message quotas preserved. Only WS connection admission is raised identically to 1000/min for fixture setup. No quota or authorization bypass in application code.',measurement:'Warm connections and one warmup per writer; prebuilt equal-sized frames; queue-to-durable-ACK and queue-to-recipient WS arrival, not DOM. CPU: workerd process tree before/after measured sends. Peak RSS is process lifetime peak, not per-case allocation.'};
await writeFile(join(output,'metadata.json'),JSON.stringify(metadata,null,2));
metadata.max_global_inflight=window;metadata.queue_accounting='All messages offered at t0; identical global sliding ACK window. Both wire RTT and full offered-to-completion/client-queue distributions recorded.';
metadata.rust_source_sha256=sha(JSON.stringify(rustSourceHashes));metadata.rust_source_files=Object.fromEntries(rustSourceHashes);
await writeFile(join(output,'metadata.json'),JSON.stringify(metadata,null,2));
try{await fetch(base+'/api/v1/health',{signal:AbortSignal.timeout(500)});throw Error('Port 8797 already in use; refusing to alter that instance.');}catch(error){if(error.message.includes('already in use'))throw error;}
const secret=randomBytes(32).toString('base64url'),token=randomBytes(32).toString('hex');
const all=[];
const env={...process.env,CLOUDFLARE_SEND_METRICS:'false',WRANGLER_SEND_METRICS:'false',NO_COLOR:'1'};
function command(args){const p=spawnSync(process.execPath,[wrangler,...args],{encoding:'utf8',windowsHide:true,env,maxBuffer:5000000});if(p.status!==0)throw Error('Wrangler failed: '+p.stdout+p.stderr);return p;}
async function run(variant,round){
 const state=resolve('.wrangler','c-'+randomUUID().slice(0,8));await mkdir(state,{recursive:true});
 const config=JSON.parse(await readFile('wrangler.local.jsonc','utf8'));delete config.assets;delete config.triggers;delete config.$schema;
 config.name='ratchet-backend-benchmark';config.main=variant==='rust'?resolve('crates/worker/build/index.js'):join(reference,'src/worker/index.ts');
 config.vars={...config.vars,GIT_COMMIT:'local-benchmark',APP_VERSION:'local-benchmark',DB_SCHEMA_VERSION:'26',CRYPTO_PROTOCOL_VERSION:'2'};
 delete config.vars.RATCHET_TIMING_PROBE;
 if(profile&&variant==='rust')config.vars.RATCHET_TIMING_PROBE='sample10';
 config.d1_databases[0].database_name='ratchet-benchmark';config.d1_databases[0].migrations_dir=variant==='rust'?resolve('db/migrations'):join(reference,'migrations');
 config.r2_buckets[0].bucket_name='ratchet-benchmark-files';config.ratelimits.find(v=>v.name==='WS_RATE_LIMITER').simple.limit=1000;
 const configPath=join(state,'config.json');await writeFile(configPath,JSON.stringify(config,null,2));
 await writeFile(join(state,'.dev.vars'),`BOOTSTRAP_TOKEN=${token}\nMESSAGE_STORAGE_KEY=${secret}\n`,{mode:0o600});
 const label=`${round}-${variant}`,serverLog=join(output,label+'-server.log'),log=createWriteStream(serverLog);
 let child,success=false;
 try{
  command(['d1','migrations','apply','DB','--local','--config',configPath,'--persist-to',state]);
  child=spawn(process.execPath,[wrangler,'dev','--config',configPath,'--local','--port','8797','--persist-to',state,'--log-level',profile&&variant==='rust'?'log':'error'],{cwd:root,env,windowsHide:true,stdio:['ignore','pipe','pipe']});
  let tail='';const collect=bytes=>{log.write(bytes);tail=(tail+bytes.toString()).slice(-12000);};child.stdout.on('data',collect);child.stderr.on('data',collect);
  let ready=false;for(let attempt=0;attempt<150;attempt++){if(child.exitCode!==null)throw Error('Worker startup failed: '+tail);try{const r=await fetch(base+'/api/v1/health',{signal:AbortSignal.timeout(700)});if(r.ok){ready=true;break;}}catch{}await new Promise(resolve=>setTimeout(resolve,200));}assert.ok(ready,'Worker ready timeout: '+tail);
  console.log('BENCH_START '+label);
  const resultPath=join(output,label+'.json');
  const load=spawn(process.execPath,['experiments/backend-benchmark/load.mjs'],{cwd:root,env:{...env,RATCHET_TEST_BASE:base,RATCHET_TEST_STATE:state,RATCHET_BENCH_SMOKE:smoke?'1':'0',RATCHET_BENCH_CASES:cases?.join(',')??'',RATCHET_BENCH_SERVER_PID:String(child.pid),RATCHET_BENCH_OUTPUT:resultPath,RATCHET_BENCH_INFLIGHT:String(window),RATCHET_BENCH_PROFILE:profile&&variant==='rust'?'1':'0',RATCHET_BENCH_SERVER_LOG:profile&&variant==='rust'?serverLog:''},windowsHide:true,stdio:'inherit'});
  const exit=await new Promise((resolve,reject)=>{load.once('error',reject);load.once('exit',resolve);});
  const results=JSON.parse(await readFile(resultPath,'utf8'));all.push({round,variant,exit,results});await writeFile(join(output,'results.json'),JSON.stringify(all,null,2));success=exit===0;
 }catch(error){all.push({round,variant,error:error.message});await writeFile(join(output,'results.json'),JSON.stringify(all,null,2));console.log('BENCH_RUN_ERROR '+label+' '+error.message);}
 finally{
  if(child?.pid&&child.exitCode===null){if(process.platform==='win32')spawnSync('taskkill',['/PID',String(child.pid),'/T','/F'],{windowsHide:true,stdio:'ignore'});else child.kill('SIGTERM');}
  await new Promise(resolve=>log.end(resolve));
  if(success&&dirname(state)===resolve('.wrangler')&&/^c-[a-f0-9]{8}$/.test(basename(state)))await rm(state,{recursive:true,force:true,maxRetries:8,retryDelay:150});
 }
}
for(let round=1;round<=rounds;round++){const order=round%2===1?['typescript','rust']:['rust','typescript'];for(const variant of order.filter(v=>variants.includes(v)))await run(variant,round);}
console.log('BENCH_OUTPUT '+output);
if(all.some(r=>r.error||r.exit!==0))process.exitCode=1;
