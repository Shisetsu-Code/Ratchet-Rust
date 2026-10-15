import { CRYPTO_PROFILE_V1 } from '../profile';
import { randomBytes, wipe, x25519PublicKey } from '../primitives';
import type { DhKeyPair, DoubleRatchetState, RatchetDependencies } from './types';

export function defaultRatchetDependencies(): RatchetDependencies {
  return {
    generateDh: generateDhKeyPair,
    nonce: () => randomBytes(CRYPTO_PROFILE_V1.nonceLength),
  };
}

export function generateDhKeyPair(): DhKeyPair {
  const privateKey = randomBytes(32);
  return { privateKey, publicKey: x25519PublicKey(privateKey) };
}

export function cloneRatchetState(state: DoubleRatchetState): DoubleRatchetState {
  return {
    dhs: {
      privateKey: state.dhs.privateKey.slice(),
      publicKey: state.dhs.publicKey.slice(),
    },
    dhr: state.dhr?.slice() ?? null,
    rk: state.rk.slice(),
    cks: state.cks?.slice() ?? null,
    ckr: state.ckr?.slice() ?? null,
    ns: state.ns,
    nr: state.nr,
    pn: state.pn,
    skipped: state.skipped.map((entry) => ({
      dh: entry.dh.slice(),
      n: entry.n,
      messageKey: entry.messageKey.slice(),
    })),
  };
}

export function wipeRatchetState(state: DoubleRatchetState): void {
  wipe(state.dhs.privateKey, state.dhs.publicKey, state.rk);
  if (state.dhr) wipe(state.dhr);
  if (state.cks) wipe(state.cks);
  if (state.ckr) wipe(state.ckr);
  for (const entry of state.skipped) wipe(entry.dh, entry.messageKey);
  state.skipped.length = 0;
}

export function equalPublicKeys(a: Uint8Array | null, b: Uint8Array | null): boolean {
  if (a === null || b === null) return a === b;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
