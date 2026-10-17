import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {DatabaseSync} from 'node:sqlite';

async function database(seed=()=>{}) {
  const db=new DatabaseSync(':memory:');
  const source=await readFile('crates/worker/src/chat/storage.rs','utf8');
  for(const match of source.matchAll(/"(CREATE TABLE IF NOT EXISTS (?:events|chat_messages|receipts|receipt_requests)[^"]+)"/g)) db.exec(match[1]);
  seed(db);
  try {
    db.exec(await readFile('crates/worker/src/chat/storage-quota.sql','utf8'));
    db.exec('UPDATE storage_usage SET byte_limit=4096,row_limit=4 WHERE id=1');
  } catch(error) {if(error.code!=='ENOENT')throw error;}
  return db;
}
test('durable event growth rolls back atomically at retained row budget',async()=>{
  const db=await database();
  try {
    for(let i=0;i<4;i++)db.exec("INSERT INTO events(kind,payload) VALUES('receipt','{}')");
    assert.throws(()=>db.exec("INSERT INTO events(kind,payload) VALUES('receipt','{}')"),/CHAT_STORAGE_QUOTA_EXCEEDED/);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM events').get().n,4);
  }finally{db.close();}
});
test('existing durable rows are charged during additive initialization',async()=>{
  const db=await database(db=>{for(let i=0;i<4;i++)db.exec("INSERT INTO events(kind,payload) VALUES('receipt','{}')");});
  try {assert.throws(()=>db.exec("INSERT INTO events(kind,payload) VALUES('receipt','{}')"),/CHAT_STORAGE_QUOTA_EXCEEDED/);}finally{db.close();}
});
test('receipt dedup responses consume the same durable byte budget',async()=>{
  const db=await database();
  try {assert.throws(()=>db.prepare('INSERT INTO receipt_requests(user_id,request_id,payload,response) VALUES(?,?,?,?)').run('user','request','hash','x'.repeat(4096)),/CHAT_STORAGE_QUOTA_EXCEEDED/);}finally{db.close();}
});
