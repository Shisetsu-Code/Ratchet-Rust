import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {DatabaseSync} from 'node:sqlite';

test('fresh schema boots without historical message tables and maintains foreign keys',async()=>{
  const db=new DatabaseSync(':memory:');
  try{
    db.exec(await readFile('db/migrations/0001_ratchet_rust.sql','utf8'));
    const tables=db.prepare("SELECT name FROM sqlite_schema WHERE type='table'").all().map(r=>r.name);
    for(const retired of ['messages','message_device_envelopes','message_recovery_envelopes','account_recovery_keys','bootstrap_webauthn_challenges'])assert.ok(!tables.includes(retired),retired);
    for(const required of ['users','sessions','devices','workspace_staff','owner_console_challenges','auth_commit_guards'])assert.ok(tables.includes(required),required);
    assert.deepEqual(db.prepare('PRAGMA foreign_key_check').all(),[]);
    db.exec("INSERT INTO users(user_id,role,status,created_at) VALUES('owner','ADMIN','ACTIVE','2026-10-15T00:00:00.000Z')");
    db.exec("INSERT INTO workspaces(workspace_id,name,created_at) VALUES('workspace','Ratchet','2026-10-15T00:00:00.000Z')");
    db.exec("INSERT INTO workspace_memberships(workspace_id,user_id,role,status,created_at) VALUES('workspace','owner','ADMIN','ACTIVE','2026-10-15T00:00:00.000Z')");
    assert.throws(()=>db.exec("INSERT INTO auth_commit_guards(assertion_id,valid) VALUES('invalid',0)"));
    assert.deepEqual(db.prepare('PRAGMA foreign_key_check').all(),[]);
  }finally{db.close();}
});
