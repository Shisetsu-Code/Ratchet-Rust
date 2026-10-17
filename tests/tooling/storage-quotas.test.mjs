import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {DatabaseSync} from 'node:sqlite';

async function database(beforeMigration=()=>{}) {
  const db = new DatabaseSync(':memory:');
  db.exec(await readFile('db/migrations/0001_ratchet_rust.sql','utf8'));
  db.exec("INSERT INTO users(user_id,role,status,created_at) VALUES('owner','ADMIN','ACTIVE','2026-01-01'); INSERT INTO workspaces(workspace_id,name,created_at) VALUES('workspace','test','2026-01-01'); INSERT INTO workspace_memberships(workspace_id,user_id,role,status,created_at) VALUES('workspace','owner','ADMIN','ACTIVE','2026-01-01'); INSERT INTO workspace_staff(workspace_id,user_id,staff_role,display_name,created_at) VALUES('workspace','owner','ADMIN','owner','2026-01-01'); INSERT INTO chats(chat_id,workspace_id,created_by_user_id,owner_admin_user_id,created_at) VALUES('chat','workspace','owner','owner','2026-01-01'); INSERT INTO devices(device_id,user_id,display_name,crypto_identity_public_key,created_at) VALUES('device','owner','test','key','2026-01-01');");
  beforeMigration(db);
  try { db.exec(await readFile('db/migrations/0003_storage_quotas.sql','utf8')); }
  catch(error) { if(error.code!=='ENOENT') throw error; }
  return db;
}
function attachment(db,id,status='COMMITTED',size=10*1024*1024) {
  db.prepare("INSERT INTO attachment_uploads(file_id,object_key,owner_user_id,chat_id,status,size,created_at,expires_at) VALUES(?,?, 'owner','chat',?,?, '2026-01-01','2026-01-02')").run(id,id,status,size);
}
function wallpaper(db,id,state='RETIRED') {
  db.prepare("INSERT INTO wallpaper_uploads(object_key,workspace_id,owner_admin_user_id,wallpaper_id,device_id,ciphertext_hash,state,expires_at) VALUES(?,'workspace','owner',?,'device','hash',?,'2026-01-02')").run(id,id,state);
}
test('confirmed attachments continue consuming durable capacity after reservation expiry',async()=>{
  const db=await database();
  try {for(let i=0;i<102;i++)attachment(db,'file'+i); assert.throws(()=>attachment(db,'overflow'),/ATTACHMENT_QUOTA_EXCEEDED/);}finally{db.close();}
});
test('migration charges previously confirmed files before admitting new growth',async()=>{
  const db=await database(db=>{for(let i=0;i<102;i++)attachment(db,'legacy'+i);});
  try {assert.throws(()=>attachment(db,'new-file'),/ATTACHMENT_QUOTA_EXCEEDED/);}finally{db.close();}
});
test('migration conservatively charges legacy multipart bytes until verified completion or cleanup',async()=>{
  const maximum=2*(5*1024*1024+16);
  const db=await database(db=>{attachment(db,'unfinished','UPLOADING',32);attachment(db,'aborted','ABORTED',32);attachment(db,'ready','READY',64);attachment(db,'committed','COMMITTED',96);});
  try {
    const usage=()=>db.prepare("SELECT bytes FROM object_storage_usage WHERE kind='attachment' AND owner_id='owner'").get().bytes;
    assert.equal(usage(),2*maximum+64+96);
    assert.equal(db.prepare("SELECT size FROM attachment_uploads WHERE file_id='unfinished'").get().size,32);
    db.exec("UPDATE attachment_uploads SET expires_at='2020-01-01',status='EXPIRED' WHERE file_id='aborted'");
    assert.equal(usage(),2*maximum+64+96);
    assert.throws(()=>db.exec("UPDATE attachment_uploads SET quota_size=NULL WHERE file_id='unfinished'"),/ATTACHMENT_QUOTA_RESERVATION_IMMUTABLE/);
    db.exec("UPDATE attachment_uploads SET write_token='complete:verified' WHERE file_id='unfinished'");
    db.exec("UPDATE attachment_uploads SET status='READY',quota_size=NULL WHERE file_id='unfinished'");
    assert.equal(usage(),maximum+32+64+96);
    db.exec("UPDATE attachment_uploads SET status='ABORTED',write_token=NULL WHERE file_id='unfinished'");
    assert.equal(usage(),maximum+32+64+96);
    db.exec("UPDATE attachment_uploads SET cleaned_at='2026-02-01' WHERE file_id='aborted'");
    assert.equal(usage(),32+64+96);
    attachment(db,'fresh','UPLOADING',32);
    assert.equal(usage(),32+32+64+96);
  }finally{db.close();}
});
test('expired and aborted files keep their charge until safe deletion',async()=>{
  const db=await database();
  try {for(let i=0;i<16;i++)attachment(db,'pending'+i,'ABORTED',32); assert.throws(()=>attachment(db,'overflow','RESERVED',32),/ATTACHMENT_QUOTA_EXCEEDED/);}finally{db.close();}
});
test('retired wallpapers cannot accumulate outside the upload quota',async()=>{
  const db=await database();
  try {for(let i=0;i<8;i++)wallpaper(db,'wall'+i); assert.throws(()=>wallpaper(db,'overflow','UPLOADING'),/WALLPAPER_QUOTA_EXCEEDED/);}finally{db.close();}
});
test('one device cannot register unbounded push subscriptions',async()=>{
  const db=await database();
  try {
    const add=db.prepare("INSERT INTO push_subscriptions(subscription_id,user_id,device_id,endpoint_hash,subscription_json,created_at) VALUES(?,'owner','device',?,'{}','2026-01-01')");
    add.run('one','one');assert.throws(()=>add.run('two','two'),/UNIQUE|PUSH_SUBSCRIPTION_QUOTA_EXCEEDED/);
  }finally{db.close();}
});

test('cleanup cannot release a live writer and repeated cleanup releases once',async()=>{
  const db=await database();
  try {
    for(let i=0;i<16;i++)attachment(db,'pending'+i,'ABORTED',32);
    db.exec("UPDATE attachment_uploads SET write_token='complete:test' WHERE file_id='pending0'");
    assert.throws(()=>db.exec("UPDATE attachment_uploads SET status='EXPIRED',cleaned_at='2026-02-01' WHERE file_id='pending0'"),/ATTACHMENT_WRITE_IN_PROGRESS/);
    assert.equal(db.prepare("SELECT bytes FROM object_storage_usage WHERE kind='attachment' AND owner_id='owner'").get().bytes,512);
    db.exec("UPDATE attachment_uploads SET write_token=NULL,status='EXPIRED',cleaned_at='2026-02-01' WHERE file_id='pending0'");
    db.exec("UPDATE attachment_uploads SET status='EXPIRED',cleaned_at='2026-02-01' WHERE file_id='pending0'");
    attachment(db,'replacement','RESERVED',32);
    assert.deepEqual({...db.prepare("SELECT bytes,objects,pending FROM object_storage_usage WHERE kind='attachment' AND owner_id='owner'").get()},{bytes:512,objects:16,pending:16});
  }finally{db.close();}
});
test('claim compensation changes pending count without changing stored bytes',async()=>{
  const db=await database();
  try {
    attachment(db,'file','READY',64);
    db.exec("UPDATE attachment_uploads SET status='COMMITTED' WHERE file_id='file'");
    assert.deepEqual({...db.prepare("SELECT bytes,objects,pending FROM object_storage_usage WHERE kind='attachment' AND owner_id='owner'").get()},{bytes:64,objects:1,pending:0});
    db.exec("UPDATE attachment_uploads SET status='READY' WHERE file_id='file'");
    assert.deepEqual({...db.prepare("SELECT bytes,objects,pending FROM object_storage_usage WHERE kind='attachment' AND owner_id='owner'").get()},{bytes:64,objects:1,pending:1});
  }finally{db.close();}
});
test('wallpaper cleanup cannot race a PUT and terminal rows are not scheduled again',async()=>{
  const db=await database();
  try {
    wallpaper(db,'wall','ABORTED');
    db.exec("UPDATE wallpaper_uploads SET write_token='write' WHERE object_key='wall'");
    assert.throws(()=>db.exec("UPDATE wallpaper_uploads SET cleaned_at='2026-02-01' WHERE object_key='wall'"),/WALLPAPER_WRITE_IN_PROGRESS/);
    db.exec("UPDATE wallpaper_uploads SET write_token=NULL,cleaned_at='2026-02-01' WHERE object_key='wall'");
    const source=await readFile('crates/worker/src/files.rs','utf8');
    const sql=source.match(/db\.all\("(SELECT object_key,upload_id,cleanup_attempts FROM wallpaper_uploads[^"]+)"/)[1];
    assert.deepEqual(db.prepare(sql).all({'?1':'2027-01-01'}),[]);
    assert.equal(db.prepare("SELECT bytes FROM object_storage_usage WHERE kind='wallpaper' AND owner_id='owner'").get().bytes,0);
  }finally{db.close();}
});
test('aggregate credits do not treat unreconciled historical rooms as empty',async()=>{
  const db=await database();
  try {
    db.exec("INSERT INTO chats(chat_id,workspace_id,created_by_user_id,owner_admin_user_id,created_at) VALUES('new-chat','workspace','owner','owner','2026-01-01')");
    const source=await readFile('crates/worker/src/chat/capacity.rs','utf8');
    const queries=[...source.matchAll(/db\.run\("([^"]+)"/g)].map(m=>m[1]);
    const reconcile=db.prepare(queries[0]),grant=db.prepare(queries[1]);
    reconcile.run({'?1':'new-chat','?2':0,'?3':0});
    grant.run({'?1':'new-chat','?2':1024,'?3':10});
    assert.equal(db.prepare("SELECT allocated_bytes FROM chat_storage_capacity WHERE chat_id='new-chat'").get().allocated_bytes,0);
    reconcile.run({'?1':'chat','?2':1024,'?3':10});
    db.exec('UPDATE chat_capacity_limits SET bytes=2048,rows=20');
    grant.run({'?1':'new-chat','?2':1024,'?3':10});
    assert.equal(db.prepare("SELECT SUM(allocated_bytes) AS n FROM chat_storage_capacity").get().n,2048);
    grant.run({'?1':'new-chat','?2':2048,'?3':20});
    assert.equal(db.prepare("SELECT SUM(allocated_bytes) AS n FROM chat_storage_capacity").get().n,2048);
  }finally{db.close();}
});
test('cleaned wallpaper tombstones do not consume the active upload slots',async()=>{
  const db=await database();
  try {
    for(let i=0;i<8;i++)wallpaper(db,'old'+i,'ABORTED');
    db.exec("UPDATE wallpaper_uploads SET cleaned_at='2026-02-01' WHERE state='ABORTED'");
    wallpaper(db,'fresh','UPLOADING');
    assert.equal(db.prepare("SELECT objects FROM object_storage_usage WHERE kind='wallpaper' AND owner_id='owner'").get().objects,1);
  }finally{db.close();}
});
test('push dispatch is fair across users and takes at most eight global leases',async()=>{
  const db=await database();
  try {
    db.exec("INSERT INTO users(user_id,role,status,created_at) VALUES('other','ADMIN','ACTIVE','2026-01-01')");
    for(const user of ['owner','other']) for(let i=0;i<16;i++) {
      const id=user+i;
      db.prepare("INSERT INTO devices(device_id,user_id,display_name,crypto_identity_public_key,created_at,authorized_at) VALUES(?,?,'test','key','2026-01-01','2026-01-01')").run(id,user);
      db.prepare("INSERT INTO push_subscriptions(subscription_id,user_id,device_id,endpoint_hash,subscription_json,created_at) VALUES(?,?,?,?,?,'2026-01-01')").run(id,user,id,id,'{}');
      db.prepare('INSERT INTO push_wakeups(subscription_id,requested_at) VALUES(?,1)').run(id);
    }
    const source=await readFile('crates/worker/src/files/push.rs','utf8');
    const select=source.match(/db\.all\("(SELECT \* FROM \(SELECT q[^"]+)"/)[1];
    const claim=source.match(/changed\(&?db,"(UPDATE push_wakeups SET lease_token=\?2[^"]+)"/)[1];
    const rows=db.prepare(select).all({'?1':100});
    assert.equal(rows.length,32);
    assert.deepEqual(new Set(rows.slice(0,2).map(row=>row.subscription_id.replace(/\d+$/,''))),new Set(['owner','other']));
    let leased=0;
    for(const row of rows) leased+=db.prepare(claim).run({'?1':row.subscription_id,'?2':'lease-'+row.subscription_id,'?3':30100,'?4':100}).changes;
    assert.equal(leased,8);
  }finally{db.close();}
});
test('unleased push hints coalesce without moving a waiting recipient to the back',async()=>{
  const db=await database();
  try {
    db.exec("UPDATE devices SET authorized_at='2026-01-01' WHERE device_id='device'; INSERT INTO push_subscriptions(subscription_id,user_id,device_id,endpoint_hash,subscription_json,created_at) VALUES('subscription','owner','device','endpoint','{}','2026-01-01')");
    const source=await readFile('crates/worker/src/files/push.rs','utf8');
    const enqueue=source.match(/db\.run\("(INSERT INTO push_wakeups[^"]+)"/)[1];
    const request=db.prepare(enqueue);
    request.run({'?1':'chat','?2':'sender-device','?3':100});
    request.run({'?1':'chat','?2':'sender-device','?3':200});
    assert.deepEqual({...db.prepare('SELECT requested_at,generation FROM push_wakeups').get()},{requested_at:100,generation:1});
    db.exec("UPDATE push_wakeups SET lease_token='in-flight',lease_until=30000");
    request.run({'?1':'chat','?2':'sender-device','?3':300});
    assert.equal(db.prepare('SELECT generation FROM push_wakeups').get().generation,2);
  }finally{db.close();}
});
