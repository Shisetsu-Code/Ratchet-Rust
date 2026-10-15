import { encodeMlKem1024PublicKey, encodeX25519PublicKey, concatBytes } from '../encoding';
import { mlKem1024Decapsulate, mlKem1024Encapsulate, wipe, x25519SharedSecret } from '../primitives';
import { generateDhKeyPair } from '../double-ratchet/state';
import { xed25519Verify } from '../xeddsa';
import { derivePqXdhSharedSecret, pqXdhAssociatedData } from './kdf';
import type {
  PqXdhInitiatorDependencies,
  PqXdhInitiatorResult,
  PqXdhPublicBundle,
  PqXdhResponderDependencies,
  PqXdhResponderPrivateBundle,
  PqXdhResponderResult,
  PqXdhInitiationHeader,
  X25519KeyPair,
} from './types';

export type PqXdhErrorType =
  | 'INVALID_KEY_MATERIAL'
  | 'INVALID_SIGNED_PREKEY_SIGNATURE'
  | 'INVALID_PQ_PREKEY_SIGNATURE'
  | 'PREKEY_ID_MISMATCH';

export class PqXdhError extends Error {
  constructor(readonly type: PqXdhErrorType, message: string) {
    super(message);
  }
}

const DEFAULT_INITIATOR_DEPS: PqXdhInitiatorDependencies = {
  verifySignature: xed25519Verify,
  generateEphemeral: generateDhKeyPair,
  encapsulate: mlKem1024Encapsulate,
};

const DEFAULT_RESPONDER_DEPS: PqXdhResponderDependencies = {
  decapsulate: mlKem1024Decapsulate,
};

export async function initiatePqXdh(
  initiatorIdentity: X25519KeyPair,
  bundle: PqXdhPublicBundle,
  deps: PqXdhInitiatorDependencies = DEFAULT_INITIATOR_DEPS,
): Promise<PqXdhInitiatorResult> {
  validateX25519Pair(initiatorIdentity, 'initiator identity');
  validateBundle(bundle);

  const signedPrekeyOk = await deps.verifySignature(
    bundle.identityPublicKey,
    encodeX25519PublicKey(bundle.signedPrekey.publicKey),
    bundle.signedPrekey.signature,
  );
  if (!signedPrekeyOk) {
    throw new PqXdhError('INVALID_SIGNED_PREKEY_SIGNATURE', 'Signed EC prekey signature verification failed');
  }

  const pqPrekeyOk = await deps.verifySignature(
    bundle.identityPublicKey,
    encodeMlKem1024PublicKey(bundle.pqPrekey.publicKey),
    bundle.pqPrekey.signature,
  );
  if (!pqPrekeyOk) {
    throw new PqXdhError('INVALID_PQ_PREKEY_SIGNATURE', 'Signed PQ prekey signature verification failed');
  }

  const ephemeral = deps.generateEphemeral();
  validateX25519Pair(ephemeral, 'initiator ephemeral');
  const kem = deps.encapsulate(bundle.pqPrekey.publicKey);

  const dh1 = x25519SharedSecret(initiatorIdentity.privateKey, bundle.signedPrekey.publicKey);
  const dh2 = x25519SharedSecret(ephemeral.privateKey, bundle.identityPublicKey);
  const dh3 = x25519SharedSecret(ephemeral.privateKey, bundle.signedPrekey.publicKey);
  const dh4 = bundle.ecOneTimePrekey
    ? x25519SharedSecret(ephemeral.privateKey, bundle.ecOneTimePrekey.publicKey)
    : null;
  const keyMaterial = concatBytes(dh1, dh2, dh3, ...(dh4 ? [dh4] : []), kem.sharedSecret);
  try {
    return {
      sharedSecret: derivePqXdhSharedSecret(keyMaterial),
      associatedData: pqXdhAssociatedData(initiatorIdentity.publicKey, bundle.identityPublicKey),
      header: {
        identityPublicKey: initiatorIdentity.publicKey.slice(),
        ephemeralPublicKey: ephemeral.publicKey.slice(),
        kemCiphertext: kem.cipherText.slice(),
        signedPrekeyId: bundle.signedPrekey.prekeyId,
        pqPrekeyId: bundle.pqPrekey.prekeyId,
        pqPrekeyKind: bundle.pqPrekey.kind,
        ecOneTimePrekeyId: bundle.ecOneTimePrekey?.prekeyId ?? null,
      },
    };
  } finally {
    wipe(dh1, dh2, dh3, keyMaterial, kem.sharedSecret, ephemeral.privateKey);
    if (dh4) wipe(dh4);
  }
}

export function respondPqXdh(
  header: PqXdhInitiationHeader,
  responder: PqXdhResponderPrivateBundle,
  deps: PqXdhResponderDependencies = DEFAULT_RESPONDER_DEPS,
): PqXdhResponderResult {
  validateX25519Pair(responder.identityKeyPair, 'responder identity');
  validateX25519Pair(responder.signedPrekey, 'responder signed prekey');
  exact(header.identityPublicKey, 32, 'initiator identity public key');
  exact(header.ephemeralPublicKey, 32, 'initiator ephemeral public key');

  if (header.signedPrekeyId !== responder.signedPrekey.prekeyId) {
    throw new PqXdhError('PREKEY_ID_MISMATCH', 'Signed EC prekey ID does not match local private material');
  }
  if (header.pqPrekeyId !== responder.pqPrekey.prekeyId || header.pqPrekeyKind !== responder.pqPrekey.kind) {
    throw new PqXdhError('PREKEY_ID_MISMATCH', 'PQ prekey ID or kind does not match local private material');
  }
  if ((header.ecOneTimePrekeyId ?? null) !== (responder.ecOneTimePrekey?.prekeyId ?? null)) {
    throw new PqXdhError('PREKEY_ID_MISMATCH', 'EC one-time prekey ID does not match local private material');
  }

  const dh1 = x25519SharedSecret(responder.signedPrekey.privateKey, header.identityPublicKey);
  const dh2 = x25519SharedSecret(responder.identityKeyPair.privateKey, header.ephemeralPublicKey);
  const dh3 = x25519SharedSecret(responder.signedPrekey.privateKey, header.ephemeralPublicKey);
  const dh4 = responder.ecOneTimePrekey
    ? x25519SharedSecret(responder.ecOneTimePrekey.privateKey, header.ephemeralPublicKey)
    : null;
  const kemSecret = deps.decapsulate(header.kemCiphertext, responder.pqPrekey.secretKey);
  const keyMaterial = concatBytes(dh1, dh2, dh3, ...(dh4 ? [dh4] : []), kemSecret);
  try {
    return {
      sharedSecret: derivePqXdhSharedSecret(keyMaterial),
      associatedData: pqXdhAssociatedData(header.identityPublicKey, responder.identityKeyPair.publicKey),
      usedEcOneTimePrekeyId: responder.ecOneTimePrekey?.prekeyId ?? null,
      usedPqOneTimePrekeyId: responder.pqPrekey.kind === 'ONE_TIME' ? responder.pqPrekey.prekeyId : null,
    };
  } finally {
    wipe(dh1, dh2, dh3, kemSecret, keyMaterial);
    if (dh4) wipe(dh4);
  }
}

function validateBundle(bundle: PqXdhPublicBundle): void {
  exact(bundle.identityPublicKey, 32, 'responder identity public key');
  exact(bundle.signedPrekey.publicKey, 32, 'signed EC prekey');
  exact(bundle.signedPrekey.signature, 64, 'signed EC prekey signature');
  exact(bundle.pqPrekey.publicKey, 1568, 'signed PQ prekey');
  exact(bundle.pqPrekey.signature, 64, 'signed PQ prekey signature');
  if (bundle.ecOneTimePrekey) exact(bundle.ecOneTimePrekey.publicKey, 32, 'EC one-time prekey');
}

function validateX25519Pair(pair: X25519KeyPair, label: string): void {
  exact(pair.privateKey, 32, `${label} private key`);
  exact(pair.publicKey, 32, `${label} public key`);
}

function exact(value: Uint8Array, expected: number, label: string): void {
  if (value.length !== expected) throw new PqXdhError('INVALID_KEY_MATERIAL', `${label} must be ${expected} bytes`);
}
