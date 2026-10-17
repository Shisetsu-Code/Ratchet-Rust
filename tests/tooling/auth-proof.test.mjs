import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash, randomUUID} from 'node:crypto';

test('password admission proof solves the server hash contract within a bounded task', async () => {
  const {solvePasswordChallenge}=await import('../../src/client/auth/admission-proof.ts');
  const challenge={protocol:'ratchet-auth-work-v1',challenge_id:randomUUID(),challenge:'A'.repeat(43),difficulty:18,expires_at:Math.floor(Date.now()/1000)+120};
  const proof=await solvePasswordChallenge(challenge,AbortSignal.timeout(15000));
  assert.equal(proof.challenge_id,challenge.challenge_id);
  const digest=createHash('sha256').update(`ratchet-auth-work-v1\n${challenge.challenge}\n${proof.solution}`).digest();
  assert.equal(digest[0],0);assert.equal(digest[1],0);assert.equal(digest[2]>>6,0);
});

test('password work refuses unsupported cost and cancellation before hashing', async () => {
  const {solvePasswordChallenge}=await import('../../src/client/auth/admission-proof.ts');
  const challenge={protocol:'ratchet-auth-work-v1',challenge_id:randomUUID(),challenge:'A'.repeat(43),difficulty:32,expires_at:Math.floor(Date.now()/1000)+120};
  await assert.rejects(solvePasswordChallenge(challenge),/desafío/);
  const abort=new AbortController();abort.abort(new Error('User cancelled'));
  await assert.rejects(solvePasswordChallenge({...challenge,difficulty:18},abort.signal),/User cancelled/);
  await assert.rejects(solvePasswordChallenge({...challenge,difficulty:18,expires_at:1}),/desafío/);
});
