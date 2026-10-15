import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,rm} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {spawnSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';

test('a refused test startup preserves existing local secrets',async()=>{
  const root=await mkdtemp(join(tmpdir(),'ratchet-runner-'));
  try{
    const vars=join(root,'.dev.vars');await writeFile(vars,'LOCAL_TEST_SENTINEL=preserve-me\n');
    const mock=join(root,'mock-fetch.mjs');await writeFile(mock,'globalThis.fetch=async()=>new Response("{}");');
    const result=spawnSync(process.execPath,['--import',pathToFileURL(mock).href,resolve('scripts/run-contracts.mjs')],{cwd:root,encoding:'utf8',windowsHide:true});
    assert.equal(result.status,1);assert.match(result.stderr,/already in use/);
    assert.equal(await readFile(vars,'utf8'),'LOCAL_TEST_SENTINEL=preserve-me\n');
  }finally{await rm(root,{recursive:true,force:true});}
});
