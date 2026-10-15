const AES_GCM_NONCE_LENGTH = 12;

export type WrappedSecret = {
  nonce: Uint8Array;
  ciphertext: Uint8Array;
};

export class LocalKeyWrapError extends Error {}

export async function generateLocalMasterKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function wrapLocalSecret(
  key: CryptoKey,
  plaintext: Uint8Array,
  aad: Uint8Array,
  nonce: Uint8Array = crypto.getRandomValues(new Uint8Array(AES_GCM_NONCE_LENGTH)),
): Promise<WrappedSecret> {
  validateMasterKey(key);
  if (nonce.length !== AES_GCM_NONCE_LENGTH) throw new LocalKeyWrapError('AES-GCM local wrapping nonce must be 12 bytes');
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toBuffer(nonce), additionalData: toBuffer(aad), tagLength: 128 },
    key,
    toBuffer(plaintext),
  );
  return { nonce: nonce.slice(), ciphertext: new Uint8Array(ciphertext) };
}

export async function unwrapLocalSecret(key: CryptoKey, wrapped: WrappedSecret, aad: Uint8Array): Promise<Uint8Array> {
  validateMasterKey(key);
  if (wrapped.nonce.length !== AES_GCM_NONCE_LENGTH) throw new LocalKeyWrapError('AES-GCM local wrapping nonce must be 12 bytes');
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: toBuffer(wrapped.nonce), additionalData: toBuffer(aad), tagLength: 128 },
      key,
      toBuffer(wrapped.ciphertext),
    );
    return new Uint8Array(plaintext);
  } catch (error) {
    throw new LocalKeyWrapError(`Local state authentication failed: ${error instanceof Error ? error.name : 'decrypt error'}`);
  }
}

function validateMasterKey(key: CryptoKey): void {
  if (key.type !== 'secret' || key.algorithm.name !== 'AES-GCM' || key.extractable) {
    throw new LocalKeyWrapError('Local master key must be a non-extractable AES-GCM secret key');
  }
  if (!key.usages.includes('encrypt') || !key.usages.includes('decrypt')) {
    throw new LocalKeyWrapError('Local master key must support encrypt and decrypt');
  }
}

function toBuffer(value: Uint8Array): ArrayBuffer {
  return value.slice().buffer as ArrayBuffer;
}
