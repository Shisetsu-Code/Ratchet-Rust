import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {DatabaseSync} from 'node:sqlite';
import {assertLocalMigrations} from '../../scripts/contract-migrations.mjs';

const expected=['0001_ratchet_rust.sql','0002_auth_admission.sql','0003_storage_quotas.sql'];
async function fixture(t,names){
  const state=await mkdtemp(join(tmpdir(),'ratchet-contract-migrations-'));
  t.after(()=>rm(state,{recursive:true,force:true}));
  const directory=join(state,'v3','d1','miniflare-D1DatabaseObject');
  await mkdir(directory,{recursive:true});
  const db=new DatabaseSync(join(directory,'database.sqlite'));
  try{
    db.exec('CREATE TABLE d1_migrations(id INTEGER PRIMARY KEY,name TEXT NOT NULL)');
    const insert=db.prepare('INSERT INTO d1_migrations(name) VALUES(?)');
    for(const name of names)insert.run(name);
  }finally{db.close();}
  return state;
}
test('contract runner rejects a missing final migration even after reported CLI success',async t=>{
  const state=await fixture(t,expected.slice(0,2));
  await assert.rejects(assertLocalMigrations(state,expected),/postcondition failed: missing \[0003_storage_quotas\.sql\]/);
});
test('contract runner accepts all expected persisted migrations',async t=>{
  const state=await fixture(t,expected);
  assert.deepEqual(await assertLocalMigrations(state,expected),expected);
});
