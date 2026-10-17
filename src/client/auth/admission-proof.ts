import { sha256 } from '@noble/hashes/sha2.js';

export type PasswordChallenge = {
  protocol: 'ratchet-auth-work-v1'; challenge_id: string; challenge: string;
  difficulty: number; expires_at: number;
};
export type PasswordProof = { challenge_id: string; solution: number };

export async function solvePasswordChallenge(challenge: PasswordChallenge, signal?: AbortSignal): Promise<PasswordProof> {
  const now = Math.floor(Date.now() / 1000);
  if (challenge.protocol !== 'ratchet-auth-work-v1'
    || !/^[0-9a-f-]{36}$/i.test(challenge.challenge_id)
    || !/^[A-Za-z0-9_-]{43}$/.test(challenge.challenge)
    || !Number.isInteger(challenge.difficulty) || challenge.difficulty < 18 || challenge.difficulty > 22
    || !Number.isSafeInteger(challenge.expires_at) || challenge.expires_at <= now || challenge.expires_at > now + 120) {
    throw new Error('El servidor devolvió un desafío de acceso inválido.');
  }
  const encoder = new TextEncoder();
  const prefix = `ratchet-auth-work-v1\n${challenge.challenge}\n`;
  const bytes = Math.floor(challenge.difficulty / 8), bits = challenge.difficulty % 8;
  const deadline = Math.min(Date.now() + 20_000, challenge.expires_at * 1000);
  for (let solution = 0; solution <= 0xffff_ffff; solution += 1) {
    if ((solution & 255) === 0) {
      signal?.throwIfAborted();
      if (Date.now() >= deadline) throw new Error('La comprobación de acceso venció. Volvé a intentar.');
    }
    const digest = sha256(encoder.encode(prefix + solution));
    let matches = true;
    for (let at = 0; at < bytes; at += 1) matches &&= digest[at] === 0;
    if (matches && (bits === 0 || digest[bytes]! >>> (8 - bits) === 0)) return { challenge_id: challenge.challenge_id, solution };
    // A bounded batch yields to input/paint and cancellation on mobile devices.
    if ((solution & 4095) === 4095) await new Promise<void>(resolve => setTimeout(resolve, 0));
  }
  throw new Error('No se pudo completar la comprobación de acceso.');
}
