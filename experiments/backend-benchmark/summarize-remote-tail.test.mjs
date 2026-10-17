import {test} from 'node:test';
import assert from 'node:assert/strict';
import {parseTail} from './summarize-remote-tail.mjs';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
test('parses concatenated multiline records and braces inside escaped strings',()=>{
 const event={cpuTime:2,wallTime:4,outcome:'ok',event:{request:{url:'https://example.test/api?secret=hidden'}},logs:[{message:['quoted " } { \\ string']}]};
 const parsed=parseTail(JSON.stringify(event,null,2)+'\n'+JSON.stringify(event));assert.equal(parsed.length,2);assert.equal(parsed[0].cpu_ms,2);assert.equal(parsed[0].path,'/api');assert.ok(!JSON.stringify(parsed).includes('hidden'));
});
test('ignores an incomplete final record while tail is still writing',()=>{assert.equal(parseTail('{"cpuTime":1}\n{"cpuTime":').length,1);});

test('reports route templates without bearer tokens or arbitrary path segments',()=>{
 const cases=[
  ['https://example.test/api/v1/invitations/bearer-secret_ABC-123/claim','/api/v1/invitations/:token/claim'],
  ['https://example.test/api/v1/invitations/%62earer%2Fsecret/claim?token=another-secret','/api/v1/invitations/:token/claim'],
  ['https://example.test/api/v1/chats/0a1b2c3d-1111-4222-8333-123456789abc/messages','/api/v1/chats/:chat_id/messages'],
  ['https://example.test/unrecognized/bearer-secret_ABC-123','/:unrecognized'],
  ['https://example.test/api/v1/invitations/bearer-secret_ABC-123/claim/extra','/:unrecognized'],
  ['not a valid URL: bearer-secret_ABC-123','/:unrecognized'],
 ];
 for(const[url,want]of cases){
  const parsed=parseTail(JSON.stringify({outcome:'ok',event:{request:{url}}}));
  assert.equal(parsed[0].path,want);
  assert.ok(!JSON.stringify(parsed).includes('bearer-secret'));
  assert.ok(!JSON.stringify(parsed).includes('another-secret'));
 }
});

test('CLI emits aggregate data by default and only sanitized events on explicit request',async()=>{
 const directory=await mkdtemp(join(tmpdir(),'ratchet-tail-'));
 try{
  const path=join(directory,'input.json');
  await writeFile(path,JSON.stringify({cpuTime:2,wallTime:4,outcome:'ok',executionModel:'stateless',event:{request:{url:'https://example.test/api/v1/invitations/bearer-secret/claim'},response:{status:200}}}));
  const run=args=>{
   const result=spawnSync(process.execPath,[resolve('experiments/backend-benchmark/summarize-remote-tail.mjs'),path,...args],{encoding:'utf8'});
   assert.equal(result.status,0,result.stderr);assert.ok(!result.stdout.includes('bearer-secret'));
   return JSON.parse(result.stdout);
  };
  assert.equal(run([]).events,undefined);
  assert.equal(run(['--events']).events[0].path,'/api/v1/invitations/:token/claim');
  assert.equal(run(['--summary']).events,undefined);
 }finally{await rm(directory,{recursive:true,force:true});}
});
