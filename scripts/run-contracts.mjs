import {spawn,spawnSync} from 'node:child_process';
import {createWriteStream} from 'node:fs';
import {readFile,writeFile,unlink,mkdir,rm,readdir} from 'node:fs/promises';
import {resolve,dirname,basename} from 'node:path';
import {randomBytes,randomUUID} from 'node:crypto';

const root=process.cwd();
// Keep SQLite paths below Windows' path limits after workerd appends its hashes.
const state=resolve('.wrangler',`c-${randomUUID().slice(0,8)}`);
const secrets=resolve('.dev.vars');
const wrangler=resolve('node_modules/wrangler/bin/wrangler.js');
const base='http://localhost:8797';
const env={...process.env,CLOUDFLARE_SEND_METRICS:'false',WRANGLER_SEND_METRICS:'false',NO_COLOR:'1'};
const token=randomBytes(32).toString('hex');
let previous=null,child=null,logs='',passed=false,secretsChanged=false;
let serverLog;
try {
  try{await fetch(base+'/api/v1/health',{signal:AbortSignal.timeout(500)});throw new Error('Port 8797 is already in use; stop that test instance first.');}
  catch(error){if(error.message.includes('already in use'))throw error;}
  try{previous=await readFile(secrets);}catch(error){if(error.code!=='ENOENT')throw error;}
  await writeFile(secrets,`BOOTSTRAP_TOKEN=${token}\nMESSAGE_STORAGE_KEY=${randomBytes(32).toString('base64url')}\n`);
  secretsChanged=true;
  await mkdir(state,{recursive:true});
  serverLog=createWriteStream(resolve(state,'server.log'));
  const migration=spawnSync(process.execPath,[wrangler,'d1','migrations','apply','DB','--local','--config','wrangler.local.jsonc','--persist-to',state],{cwd:root,env,encoding:'utf8',windowsHide:true});
  if(migration.status!==0)throw new Error('Local migrations failed:\n'+migration.stdout+'\n'+migration.stderr);
  child=spawn(process.execPath,[wrangler,'dev','--config','wrangler.local.jsonc','--local','--port','8797','--persist-to',state],{cwd:root,env,stdio:['ignore','pipe','pipe'],windowsHide:true});
  const collect=data=>{logs=(logs+data.toString()).slice(-30000);serverLog.write(data);};child.stdout.on('data',collect);child.stderr.on('data',collect);
  let ready=false;
  for(let attempt=0;attempt<150;attempt++){
    if(child.exitCode!==null)throw new Error('Local Worker exited:\n'+logs);
    try{const result=await fetch(base+'/api/v1/health',{signal:AbortSignal.timeout(800)});if(result.ok){ready=true;break;}}catch{}
    await new Promise(resolve=>setTimeout(resolve,200));
  }
  if(!ready)throw new Error('Local Worker did not become ready:\n'+logs);
  const targets=process.argv.slice(2).length?process.argv.slice(2):(await readdir('tests/contracts')).filter(name=>name.endsWith('.mjs')&&name!=='fixtures.mjs').sort().map(name=>'tests/contracts/'+name);
  const tests=spawn(process.execPath,['--test','--test-concurrency=1',...targets],{cwd:root,env:{...env,RATCHET_TEST_BASE:base,RATCHET_TEST_BOOTSTRAP_TOKEN:token,RATCHET_TEST_STATE:state},stdio:'inherit',windowsHide:true});
  const exit=await new Promise(resolve=>tests.on('exit',resolve));
  passed=exit===0;process.exitCode=typeof exit==='number'?exit:1;
  if(!passed)console.error(logs);
}catch(error){console.error(error.message);process.exitCode=1;}
finally{
  if(child?.pid&&child.exitCode===null){
    if(process.platform==='win32')spawnSync('taskkill',['/PID',String(child.pid),'/T','/F'],{windowsHide:true,stdio:'ignore'});
    else child.kill('SIGTERM');
  }
  if(secretsChanged){if(previous!==null)await writeFile(secrets,previous);else await unlink(secrets).catch(error=>{if(error.code!=='ENOENT')throw error;});}
  if(serverLog)await new Promise(resolve=>serverLog.end(resolve));
  if(passed&&dirname(state)===resolve('.wrangler')&&/^c-[a-f0-9]{8}$/.test(basename(state)))await rm(state,{recursive:true,force:true,maxRetries:8,retryDelay:150});
}
