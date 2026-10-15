import { bytesToHex } from '@noble/hashes/utils.js';
import { CRYPTO_PROFILE_V1 } from '../profile';
import { kdfChain, kdfRoot } from '../ratchet-kdf';
import { wipe, x25519SharedSecret } from '../primitives';
import { openRatchetPayload, ratchetAssociatedData, sealRatchetPayload, validateRatchetHeader } from './codec';
import { cloneRatchetState, defaultRatchetDependencies, equalPublicKeys } from './state';
import type {
  DhKeyPair,
  DoubleRatchetState,
  RatchetCiphertext,
  RatchetDecryptResult,
  RatchetDependencies,
  RatchetEncryptResult,
  RatchetHeader,
} from './types';

export type DoubleRatchetErrorType =
  | 'INVALID_STATE'
  | 'MAX_SKIP_EXCEEDED'
  | 'REPLAY_OR_TOO_OLD'
  | 'AUTHENTICATION_FAILED';

export class DoubleRatchetError extends Error {
  constructor(readonly type: DoubleRatchetErrorType, message: string, readonly source?: unknown) {
    super(message);
  }
}

export function initAlice(
  sharedSecret: Uint8Array,
  bobRatchetPublicKey: Uint8Array,
  deps: RatchetDependencies = defaultRatchetDependencies(),
): DoubleRatchetState {
  require32(sharedSecret, 'initial shared secret');
  require32(bobRatchetPublicKey, 'Bob ratchet public key');
  const dhs = deps.generateDh();
  validateDhPair(dhs);
  const shared = x25519SharedSecret(dhs.privateKey, bobRatchetPublicKey);
  const derived = kdfRoot(sharedSecret, shared);
  wipe(shared);
  return {
    dhs,
    dhr: bobRatchetPublicKey.slice(),
    rk: derived.rootKey,
    cks: derived.chainKey,
    ckr: null,
    ns: 0,
    nr: 0,
    pn: 0,
    skipped: [],
  };
}

export function initBob(sharedSecret: Uint8Array, bobRatchetKeyPair: DhKeyPair): DoubleRatchetState {
  require32(sharedSecret, 'initial shared secret');
  validateDhPair(bobRatchetKeyPair);
  return {
    dhs: {
      privateKey: bobRatchetKeyPair.privateKey.slice(),
      publicKey: bobRatchetKeyPair.publicKey.slice(),
    },
    dhr: null,
    rk: sharedSecret.slice(),
    cks: null,
    ckr: null,
    ns: 0,
    nr: 0,
    pn: 0,
    skipped: [],
  };
}

export function ratchetEncrypt(
  state: DoubleRatchetState,
  plaintext: Uint8Array,
  externalAd: Uint8Array,
  deps: RatchetDependencies = defaultRatchetDependencies(),
): RatchetEncryptResult {
  const next = cloneRatchetState(state);
  if (!next.cks) throw new DoubleRatchetError('INVALID_STATE', 'Sending chain is not initialized');
  const derived = kdfChain(next.cks);
  const messageNumber = next.ns;
  next.cks = derived.nextChainKey;
  next.ns += 1;
  const header: RatchetHeader = { dh: next.dhs.publicKey.slice(), pn: next.pn, n: messageNumber };
  const aad = ratchetAssociatedData(externalAd, header);
  const nonce = deps.nonce();
  let ciphertext: Uint8Array;
  try {
    ciphertext = sealRatchetPayload(derived.messageKey, plaintext, aad, nonce);
  } finally {
    wipe(derived.messageKey);
  }
  return { state: next, message: { header, ciphertext } };
}

export function ratchetDecrypt(
  state: DoubleRatchetState,
  message: RatchetCiphertext,
  externalAd: Uint8Array,
  deps: RatchetDependencies = defaultRatchetDependencies(),
): RatchetDecryptResult {
  validateRatchetHeader(message.header);
  const next = cloneRatchetState(state);
  const skippedIndex = findSkipped(next, message.header);
  if (skippedIndex >= 0) {
    const skipped = next.skipped[skippedIndex]!;
    const aad = ratchetAssociatedData(externalAd, message.header);
    try {
      const plaintext = authenticate(skipped.messageKey, message.ciphertext, aad);
      next.skipped.splice(skippedIndex, 1);
      return { state: next, plaintext };
    } finally {
      wipe(skipped.messageKey);
    }
  }

  if (equalPublicKeys(next.dhr, message.header.dh) && message.header.n < next.nr) {
    throw new DoubleRatchetError('REPLAY_OR_TOO_OLD', 'Message key is no longer available');
  }

  if (!equalPublicKeys(next.dhr, message.header.dh)) {
    skipMessageKeys(next, message.header.pn);
    dhRatchet(next, message.header, deps);
  }
  skipMessageKeys(next, message.header.n);
  if (!next.ckr) throw new DoubleRatchetError('INVALID_STATE', 'Receiving chain is not initialized');
  const derived = kdfChain(next.ckr);
  next.ckr = derived.nextChainKey;
  next.nr += 1;
  const aad = ratchetAssociatedData(externalAd, message.header);
  try {
    const plaintext = authenticate(derived.messageKey, message.ciphertext, aad);
    return { state: next, plaintext };
  } finally {
    wipe(derived.messageKey);
  }
}

function authenticate(messageKey: Uint8Array, ciphertext: Uint8Array, aad: Uint8Array): Uint8Array {
  try {
    return openRatchetPayload(messageKey, ciphertext, aad);
  } catch (error) {
    throw new DoubleRatchetError('AUTHENTICATION_FAILED', 'Ratchet ciphertext authentication failed', error);
  }
}

function skipMessageKeys(state: DoubleRatchetState, until: number): void {
  if (state.nr + CRYPTO_PROFILE_V1.maxSkip < until) {
    throw new DoubleRatchetError('MAX_SKIP_EXCEEDED', 'Message gap exceeds MAX_SKIP');
  }
  if (!state.ckr) return;
  if (!state.dhr) throw new DoubleRatchetError('INVALID_STATE', 'Receiving ratchet key is missing');
  while (state.nr < until) {
    if (state.skipped.length >= CRYPTO_PROFILE_V1.maxSkip) {
      throw new DoubleRatchetError('MAX_SKIP_EXCEEDED', 'Skipped message-key storage limit reached');
    }
    const derived = kdfChain(state.ckr);
    state.ckr = derived.nextChainKey;
    state.skipped.push({
      dh: state.dhr.slice(),
      n: state.nr,
      messageKey: derived.messageKey,
    });
    state.nr += 1;
  }
}

function dhRatchet(state: DoubleRatchetState, header: RatchetHeader, deps: RatchetDependencies): void {
  state.pn = state.ns;
  state.ns = 0;
  state.nr = 0;
  state.dhr = header.dh.slice();

  const receiveDh = x25519SharedSecret(state.dhs.privateKey, state.dhr);
  const receiveRoot = kdfRoot(state.rk, receiveDh);
  wipe(receiveDh, state.rk);
  state.rk = receiveRoot.rootKey;
  state.ckr = receiveRoot.chainKey;

  const nextDh = deps.generateDh();
  validateDhPair(nextDh);
  state.dhs = nextDh;
  const sendDh = x25519SharedSecret(state.dhs.privateKey, state.dhr);
  const sendRoot = kdfRoot(state.rk, sendDh);
  wipe(sendDh, state.rk);
  state.rk = sendRoot.rootKey;
  state.cks = sendRoot.chainKey;
}

function findSkipped(state: DoubleRatchetState, header: RatchetHeader): number {
  const dh = bytesToHex(header.dh);
  return state.skipped.findIndex((entry) => entry.n === header.n && bytesToHex(entry.dh) === dh);
}

function validateDhPair(pair: DhKeyPair): void {
  require32(pair.privateKey, 'ratchet private key');
  require32(pair.publicKey, 'ratchet public key');
}

function require32(value: Uint8Array, label: string): void {
  if (value.length !== 32) throw new DoubleRatchetError('INVALID_STATE', `${label} must be 32 bytes`);
}
