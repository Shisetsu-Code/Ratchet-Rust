import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile,readdir} from 'node:fs/promises';
import {DatabaseSync} from 'node:sqlite';

test('fresh schema boots without historical message tables and maintains foreign keys',async()=>{
  const db=new DatabaseSync(':memory:');
  try{
    for(const migration of (await readdir('db/migrations')).filter(name=>name.endsWith('.sql')).sort()){
      db.exec(await readFile('db/migrations/'+migration,'utf8'));
    }
    const tables=db.prepare("SELECT name FROM sqlite_schema WHERE type='table'").all().map(r=>r.name);
    for(const retired of ['messages','message_device_envelopes','message_recovery_envelopes','account_recovery_keys','bootstrap_webauthn_challenges'])assert.ok(!tables.includes(retired),retired);
    for(const required of ['users','sessions','devices','workspace_staff','owner_console_challenges','auth_commit_guards','auth_admission_permits','object_storage_usage','chat_storage_capacity'])assert.ok(tables.includes(required),required);
    assert.deepEqual(db.prepare('PRAGMA foreign_key_check').all(),[]);
    db.exec("INSERT INTO users(user_id,role,status,created_at) VALUES('owner','ADMIN','ACTIVE','2026-10-15T00:00:00.000Z')");
    db.exec("INSERT INTO workspaces(workspace_id,name,created_at) VALUES('workspace','Ratchet','2026-10-15T00:00:00.000Z')");
    db.exec("INSERT INTO workspace_memberships(workspace_id,user_id,role,status,created_at) VALUES('workspace','owner','ADMIN','ACTIVE','2026-10-15T00:00:00.000Z')");
    assert.throws(()=>db.exec("INSERT INTO auth_commit_guards(assertion_id,valid) VALUES('invalid',0)"));
    assert.deepEqual(db.prepare('PRAGMA foreign_key_check').all(),[]);
  }finally{db.close();}
});

test('the complete migration sequence preserves populated credentials, consumed challenges and committed files',async()=>{
  const db=new DatabaseSync(':memory:');
  try{
    db.exec(await readFile('db/migrations/0001_ratchet_rust.sql','utf8'));
    db.exec(`
      INSERT INTO users(user_id,role,status,created_at) VALUES('owner','ADMIN','ACTIVE','2026-10-15');
      INSERT INTO workspaces(workspace_id,name,created_at) VALUES('workspace','Ratchet','2026-10-15');
      INSERT INTO workspace_memberships(workspace_id,user_id,role,status,created_at) VALUES('workspace','owner','ADMIN','ACTIVE','2026-10-15');
      INSERT INTO workspace_staff(workspace_id,user_id,staff_role,display_name,created_at) VALUES('workspace','owner','ADMIN','Administrador','2026-10-15');
      INSERT INTO chats(chat_id,workspace_id,created_by_user_id,owner_admin_user_id,created_at) VALUES('old-chat','workspace','owner','owner','2026-10-15');
      INSERT INTO password_credentials(user_id,login_name,algorithm,iterations,salt,verifier,failed_attempts,next_allowed_at,created_at,updated_at) VALUES('owner','retained-owner','PBKDF2-SHA256',100000,'retained-salt','retained-verifier',4,'2026-10-16','2026-10-15','2026-10-15');
      INSERT INTO portable_key_challenges(challenge_id,kind,challenge,key_id,created_at,expires_at) VALUES('used-challenge','AUTHENTICATION','nonce','key','2026-10-15','2026-10-16');
      INSERT INTO portable_key_challenge_consumptions(challenge_id,consumed_at) VALUES('used-challenge','2026-10-15');
      INSERT INTO attachment_uploads(file_id,object_key,owner_user_id,chat_id,status,size,created_at,expires_at) VALUES('committed','retained-object','owner','old-chat','COMMITTED',512,'2026-10-15','2026-10-16');
      INSERT INTO attachments(file_id,message_id,encrypted_metadata,created_at) VALUES('committed','retained-message','opaque','2026-10-15');
    `);
    const before=db.prepare('SELECT * FROM password_credentials').all();
    for(const migration of (await readdir('db/migrations')).filter(name=>name.endsWith('.sql')&&!name.startsWith('0001_')).sort()){
      db.exec(await readFile('db/migrations/'+migration,'utf8'));
    }
    const after=db.prepare('SELECT * FROM password_credentials').all();
    assert.equal(after[0].next_allowed_at,null,'the retired account-wide backoff is intentionally cleared');
    assert.deepEqual(after.map(row=>({...row,next_allowed_at:null})),before.map(row=>({...row,next_allowed_at:null})));
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM portable_key_challenge_consumptions').get().n,1);
    assert.equal(db.prepare("SELECT bytes FROM object_storage_usage WHERE kind='attachment' AND owner_id='owner'").get().bytes,512);
    assert.equal(db.prepare("SELECT status FROM attachment_uploads WHERE file_id='committed'").get().status,'COMMITTED');
    assert.equal(db.prepare("SELECT message_id FROM attachments WHERE file_id='committed'").get().message_id,'retained-message');
    assert.equal(db.prepare("SELECT reconciled FROM chat_storage_capacity WHERE chat_id='old-chat'").get().reconciled,0);
    db.exec("INSERT INTO chats(chat_id,workspace_id,created_by_user_id,owner_admin_user_id,created_at) VALUES('new-chat','workspace','owner','owner','2026-10-17')");
    assert.equal(db.prepare("SELECT reconciled FROM chat_storage_capacity WHERE chat_id='new-chat'").get().reconciled,1);
    assert.deepEqual(db.prepare('PRAGMA foreign_key_check').all(),[]);
  }finally{db.close();}
});
