import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile, readdir} from 'node:fs/promises';
import {DatabaseSync} from 'node:sqlite';
import {createHash, randomUUID} from 'node:crypto';

const hash = value => createHash('sha256').update(value).digest('hex');
async function database() {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys=ON');
  for (const name of (await readdir('db/migrations')).filter(name => name.endsWith('.sql')).sort())
    db.exec(await readFile('db/migrations/' + name, 'utf8'));
  assert.ok(db.prepare("SELECT 1 FROM sqlite_schema WHERE name='auth_admission_permits'").get(), 'authentication has a persistent atomic admission boundary');
  return db;
}
function admit(db, {scope='password_login', origin='network-a', principal='account-a', now=1000, proof=null, active=true}={}) {
  const id = randomUUID();
  db.prepare('INSERT INTO auth_admission_permits(permit_id,scope,origin_hash,principal_hash,issued_at,leased_until,released_at,proof_id) VALUES(?,?,?,?,?,?,?,?)')
    .run(id,scope,hash(origin),hash(principal),now,active ? now+120 : now,active ? null : now,proof);
  return id;
}

test('additive auth migration preserves existing consumed challenges and accepts old Worker fields during rollout', async () => {
  const db=new DatabaseSync(':memory:');
  try {
    db.exec(await readFile('db/migrations/0001_ratchet_rust.sql','utf8'));
    const legacy="INSERT INTO portable_key_challenges(challenge_id,kind,challenge,key_id,created_at,expires_at) VALUES(?,'AUTHENTICATION','nonce','key','2026-10-17T00:00:00.000Z','2026-10-17T00:05:00.000Z')";
    db.prepare(legacy).run('already-consumed');
    db.exec("INSERT INTO portable_key_challenge_consumptions(challenge_id,consumed_at) VALUES('already-consumed','2026-10-17T00:01:00.000Z')");
    db.exec(await readFile('db/migrations/0002_auth_admission.sql','utf8'));
    assert.ok(db.prepare("SELECT 1 FROM portable_key_challenge_consumptions WHERE challenge_id='already-consumed'").get());
    assert.doesNotThrow(()=>db.prepare(legacy).run('old-worker-during-upgrade'));
    assert.deepEqual(db.prepare('PRAGMA foreign_key_check').all(),[]);
  } finally {db.close();}
});

test('another origin can still authenticate when one origin exhausts its account attempts', async () => {
  const db=await database();
  try {
    db.exec("UPDATE auth_admission_policy SET max_pair_requests=2, free_principal_requests=100 WHERE scope='password_login'");
    admit(db,{active:false}); admit(db,{active:false});
    assert.throws(()=>admit(db,{active:false}),/auth_rate_limited/);
    assert.doesNotThrow(()=>admit(db,{origin:'network-b',active:false}));
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM auth_admission_permits').get().n,3);
  } finally { db.close(); }
});

test('released KDF capacity preserves the rate budget and validated-session reauth has its own pool', async () => {
  const db=await database();
  try {
    db.exec("UPDATE auth_admission_policy SET max_requests=2,max_active=1 WHERE scope='password_login'");
    const first=admit(db);
    assert.throws(()=>admit(db,{origin:'network-b'}),/auth_rate_limited/);
    assert.doesNotThrow(()=>admit(db,{scope:'password_reauth'}));
    db.prepare('UPDATE auth_admission_permits SET released_at=1000 WHERE permit_id=?').run(first);
    admit(db,{origin:'network-b',active:false});
    assert.throws(()=>admit(db,{origin:'network-c',active:false}),/auth_rate_limited/);
    assert.doesNotThrow(()=>admit(db,{origin:'network-c',now:1061,active:false}));
  } finally { db.close(); }
});

test('account risk requires a one-use proof but does not create an account-wide lockout', async () => {
  const db=await database();
  try {
    db.exec("UPDATE auth_admission_policy SET free_principal_requests=1 WHERE scope='password_login'");
    admit(db,{active:false});
    assert.throws(()=>admit(db,{origin:'network-b',active:false}),/auth_proof_required/);
    const proof=randomUUID();
    db.prepare('INSERT INTO auth_password_proofs(challenge_id,challenge,origin_hash,principal_hash,difficulty,created_at,expires_at) VALUES(?,?,?,?,?,?,?)')
      .run(proof,'A'.repeat(43),hash('network-b'),hash('account-a'),20,1000,1120);
    assert.throws(()=>admit(db,{origin:'network-c',proof,active:false}),/auth_proof_required/);
    assert.doesNotThrow(()=>admit(db,{origin:'network-b',proof,active:false}));
    assert.throws(()=>admit(db,{origin:'network-b',proof,active:false}),/auth_proof_required/);
    assert.ok(db.prepare('SELECT consumed_at FROM auth_password_proofs WHERE challenge_id=?').get(proof).consumed_at);
  } finally { db.close(); }
});

test('challenge admission caps stored rows atomically across portable and passkey login', async () => {
  const db=await database();
  try {
    db.exec("UPDATE auth_challenge_policy SET max_pending=2,max_origin_pending=2 WHERE kind='AUTHENTICATION'");
    const base=['AUTHENTICATION','A'.repeat(43),'2026-10-17T00:00:00.000Z','2026-10-17T00:05:00.000Z',hash('network-a')];
    const add=()=>db.prepare('INSERT INTO webauthn_challenges(challenge_id,kind,challenge,created_at,expires_at,admission_origin) VALUES(?,?,?,?,?,?)').run(randomUUID(),...base);
    add(); add();
    assert.throws(add,/auth_challenge_capacity/);
    assert.throws(()=>db.prepare('INSERT INTO portable_key_challenges(challenge_id,kind,challenge,key_id,created_at,expires_at,admission_origin) VALUES(?,?,?,?,?,?,?)')
      .run(randomUUID(),base[0],base[1],randomUUID(),base[2],base[3],base[4]),/auth_challenge_capacity/);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM webauthn_challenges').get().n,2);
  } finally { db.close(); }
});

test('solved account proof cannot bypass a hard budget and is not spent by rejected admission', async () => {
  const db=await database();
  try {
    db.exec("UPDATE auth_admission_policy SET max_requests=1 WHERE scope='password_login'");
    admit(db,{active:false});
    const proof=randomUUID();
    db.prepare('INSERT INTO auth_password_proofs(challenge_id,challenge,origin_hash,principal_hash,difficulty,created_at,expires_at) VALUES(?,?,?,?,?,?,?)')
      .run(proof,'A'.repeat(43),hash('network-b'),hash('account-a'),20,1000,1120);
    assert.throws(()=>admit(db,{origin:'network-b',proof,active:false}),/auth_rate_limited/);
    assert.equal(db.prepare('SELECT consumed_at FROM auth_password_proofs WHERE challenge_id=?').get(proof).consumed_at,null);
    assert.doesNotThrow(()=>admit(db,{origin:'network-b',proof,active:false,now:1061}));
  } finally { db.close(); }
});

test('origin pending cap applies to public bootstrap and owner-console challenge rows', async () => {
  const db=await database();
  try {
    const now='2026-10-17T00:00:00.000Z',expires='2026-10-17T00:05:00.000Z',origin=hash('network-a');
    const bootstrap=db.prepare("INSERT INTO portable_key_challenges(challenge_id,kind,challenge,key_id,created_at,expires_at,admission_origin) VALUES(?,'BOOTSTRAP',?,?,?,?,?)");
    for(let n=0;n<16;n++) bootstrap.run(randomUUID(),'A'.repeat(43),randomUUID(),now,expires,origin);
    assert.throws(()=>bootstrap.run(randomUUID(),'A'.repeat(43),randomUUID(),now,expires,origin),/auth_challenge_capacity/);
    assert.doesNotThrow(()=>bootstrap.run(randomUUID(),'A'.repeat(43),randomUUID(),now,expires,hash('network-b')));
    db.prepare("INSERT INTO users(user_id,role,status,created_at) VALUES('owner','ADMIN','ACTIVE',?)").run(now);
    db.prepare("INSERT INTO workspaces(workspace_id,name,created_at) VALUES('workspace','test',?)").run(now);
    const owner=db.prepare("INSERT INTO owner_console_challenges(challenge_id,challenge,owner_key_id,owner_user_id,workspace_id,origin,operation_digest,operation_type,created_at,expires_at,admission_origin) VALUES(?,'nonce','key','owner','workspace','https://ratchet.test','digest','accounts.list',?,?,?)");
    for(let n=0;n<40;n++) owner.run(randomUUID(),now,expires,origin);
    assert.throws(()=>owner.run(randomUUID(),now,expires,origin),/auth_challenge_capacity/);
    assert.doesNotThrow(()=>owner.run(randomUUID(),now,expires,hash('network-b')));
    assert.deepEqual(db.prepare('PRAGMA foreign_key_check').all(),[]);
  } finally { db.close(); }
});

test('bounded challenge cleanup removes parents with consumptions and never reopens a live challenge', async () => {
  const db=await database();
  try {
    for(const [id,expires] of [['expired-1','2026-10-17T00:00:00.000Z'],['expired-2','2026-10-17T00:00:00.000Z'],['live','2026-10-18T00:00:00.000Z']]) {
      db.prepare('INSERT INTO portable_key_challenges(challenge_id,kind,challenge,key_id,created_at,expires_at,admission_origin) VALUES(?,?,?,?,?,?,?)').run(id,'AUTHENTICATION','A'.repeat(43),'key','2026-10-16T00:00:00.000Z',expires,hash('network-a'));
      db.prepare('INSERT INTO portable_key_challenge_consumptions(challenge_id,consumed_at) VALUES(?,?)').run(id,'2026-10-16T00:01:00.000Z');
    }
    const statements=(await readFile('crates/worker/src/auth-challenges-cleanup.sql','utf8')).split(';').filter(sql=>sql.trim());
    db.exec('BEGIN');
    for (const sql of statements) db.prepare(sql).run('2026-10-17T12:00:00.000Z',1);
    db.exec('COMMIT');
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM portable_key_challenges').get().n,2,'one expired parent per batch');
    assert.ok(db.prepare("SELECT 1 FROM portable_key_challenge_consumptions WHERE challenge_id='live'").get(),'live single-use assertion remains consumed');
    assert.deepEqual(db.prepare('PRAGMA foreign_key_check').all(),[]);
  } finally { db.close(); }
});
