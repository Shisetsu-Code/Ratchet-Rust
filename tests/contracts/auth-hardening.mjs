import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes, randomUUID, pbkdf2Sync, createHash} from 'node:crypto';
import {api, fixture, localSql, localRows} from './fixtures.mjs';
import {solvePasswordChallenge} from '../../src/client/auth/admission-proof.ts';

test('password admission survives legacy lockout state, charges only admitted work, and keeps reauth available', async () => {
  const actor=await fixture(), login='auth-admission-'+randomUUID(), password='Synthetic admission password 2026!';
  const salt=randomBytes(16), verifier=pbkdf2Sync(password,salt,600000,32,'sha256');
  const now=new Date().toISOString();
  await localSql(`INSERT INTO password_credentials(user_id,login_name,algorithm,iterations,salt,verifier,failed_attempts,next_allowed_at,created_at,updated_at) VALUES('${actor.user_id}','${login}','PBKDF2-SHA256',600000,'${salt.toString('base64url')}','${verifier.toString('base64url')}',20,'2099-01-01T00:00:00.000Z','${now}','${now}');`);
  const body={login_name:login,password,device:{mode:'existing',device_id:actor.device_id}};
  const first=await api('/auth/password/login',{body});
  assert.equal(first.status,200,JSON.stringify(first.value));
  let row=(await localRows('SELECT failed_attempts,next_allowed_at FROM password_credentials WHERE user_id=?',[actor.user_id]))[0];
  assert.equal(row.failed_attempts,0);assert.equal(row.next_allowed_at,null);
  const bad=await api('/auth/password/login',{body:{...body,password:'An incorrect synthetic password'}});
  assert.equal(bad.status,401);
  row=(await localRows('SELECT failed_attempts,next_allowed_at FROM password_credentials WHERE user_id=?',[actor.user_id]))[0];
  assert.equal(row.failed_attempts,1,'only an actual failed verification increments failure observation');
  assert.equal(row.next_allowed_at,null);
  const hash=createHash('sha256').update('auth-principal-v1:'+login).digest('hex');
  const before=(await localRows('SELECT COUNT(*) AS n FROM auth_admission_permits WHERE principal_hash=?',[hash]))[0].n;
  const original=(await localRows("SELECT * FROM auth_admission_policy WHERE scope='password_login'"))[0];
  try {
    await localSql("UPDATE auth_admission_policy SET free_principal_requests=1 WHERE scope='password_login';");
    const required=await api('/auth/password/login',{body});
    assert.equal(required.status,429);assert.equal(required.value.type,'AUTHENTICATION_PROOF_REQUIRED');
    assert.equal((await localRows('SELECT COUNT(*) AS n FROM auth_admission_permits WHERE principal_hash=?',[hash]))[0].n,before,'a proof-required response performs no password admission');
    const challenge=await api('/auth/password/challenge',{body:{login_name:login}});
    assert.equal(challenge.status,200,JSON.stringify(challenge.value));
    const proof=await solvePasswordChallenge(challenge.value,AbortSignal.timeout(20000));
    const admitted=await api('/auth/password/login',{body:{...body,proof}});
    assert.equal(admitted.status,200,JSON.stringify(admitted.value));
    const replay=await api('/auth/password/login',{body:{...body,proof}});
    assert.equal(replay.status,429);assert.equal(replay.value.type,'AUTHENTICATION_PROOF_REQUIRED');
    const admissions=await localRows('SELECT released_at FROM auth_admission_permits WHERE scope=\'password_login\' AND principal_hash=?',[hash]);
    assert.equal(admissions.length,before+1);assert.ok(admissions.every(row=>row.released_at!==null),'completed password work releases concurrency but retains rate charges');
    const total=(await localRows("SELECT COUNT(*) AS n FROM auth_admission_permits WHERE scope='password_login' AND issued_at>strftime('%s','now')-60"))[0].n;
    await localSql(`UPDATE auth_admission_policy SET max_requests=${Math.max(1,total)} WHERE scope='password_login';`);
    assert.equal((await api('/auth/password/login',{body})).value.type,'RATE_LIMITED');
    const reauth=await api('/auth/password/reauth',{cookie:actor.cookie,body:{password}});
    assert.equal(reauth.status,200,JSON.stringify(reauth.value));
    const reauthCount=(await localRows("SELECT COUNT(*) AS n FROM auth_admission_permits WHERE scope='password_reauth'"))[0].n;
    const forged=await api('/auth/password/reauth',{cookie:'__Host-session='+randomBytes(32).toString('base64url'),body:{password}});
    assert.equal(forged.status,401);
    assert.equal((await localRows("SELECT COUNT(*) AS n FROM auth_admission_permits WHERE scope='password_reauth'"))[0].n,reauthCount,'forged cookies do not reserve privileged KDF capacity');
  } finally {
    await localSql(`UPDATE auth_admission_policy SET max_requests=${original.max_requests},free_principal_requests=${original.free_principal_requests} WHERE scope='password_login';`);
  }
});

test('public passkey and portable prepare enforce one shared retained-row cap and validate real reauth sessions', async () => {
  const original=(await localRows("SELECT * FROM auth_challenge_policy WHERE kind='AUTHENTICATION'"))[0];
  const current=(await localRows("SELECT (SELECT COUNT(*) FROM portable_key_challenges WHERE kind='AUTHENTICATION')+(SELECT COUNT(*) FROM webauthn_challenges WHERE kind='AUTHENTICATION') AS n"))[0].n;
  try {
    await localSql(`UPDATE auth_challenge_policy SET max_pending=${current+1} WHERE kind='AUTHENTICATION';`);
    const first=await api('/auth/passkey/login/options',{body:{}});
    assert.equal(first.status,200,JSON.stringify(first.value));
    const other=await api('/auth/portable-key/login/prepare',{body:{key_id:randomUUID(),device:{mode:'existing',device_id:randomUUID()}}});
    assert.equal(other.status,429);assert.equal(other.value.type,'RATE_LIMITED');
    const actor=await fixture();
    const reauth=await api('/auth/passkey/reauth/options',{cookie:actor.cookie,body:{}});
    assert.equal(reauth.status,200,JSON.stringify(reauth.value));
    const forged=await api('/auth/passkey/reauth/options',{cookie:'__Host-session='+randomBytes(32).toString('base64url'),body:{}});
    assert.equal(forged.status,401);
  } finally {
    await localSql(`UPDATE auth_challenge_policy SET max_pending=${original.max_pending} WHERE kind='AUTHENTICATION';`);
  }
});
