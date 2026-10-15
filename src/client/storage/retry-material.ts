import { concatBytes, utf8 } from '../crypto/encoding';
import { unwrapLocalSecret, wrapLocalSecret } from '../crypto/local-state/wrapping';
import { LocalStorageError } from './errors';

const RETRY_DOMAIN = utf8('RatchetSecureSupport/outbox-retry-material/v1');
const AES_GCM_NONCE_LENGTH = 12;

export type RetryMaterialIdentity = {
  chat_id: string;
  sender_device_id: string;
  client_message_id: string;
};

export async function encryptRetryMaterial(
  masterKey: CryptoKey,
  identity: RetryMaterialIdentity,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const wrapped = await wrapLocalSecret(masterKey, plaintext, retryMaterialAad(identity));
  return concatBytes(wrapped.nonce, wrapped.ciphertext);
}

export async function decryptRetryMaterial(
  masterKey: CryptoKey,
  identity: RetryMaterialIdentity,
  packed: Uint8Array,
): Promise<Uint8Array> {
  if (packed.length <= AES_GCM_NONCE_LENGTH) {
    throw new LocalStorageError('CORRUPT_STATE', 'Encrypted retry material is truncated');
  }
  return unwrapLocalSecret(
    masterKey,
    {
      nonce: packed.slice(0, AES_GCM_NONCE_LENGTH),
      ciphertext: packed.slice(AES_GCM_NONCE_LENGTH),
    },
    retryMaterialAad(identity),
  );
}

function retryMaterialAad(identity: RetryMaterialIdentity): Uint8Array {
  return concatBytes(
    RETRY_DOMAIN,
    field(identity.chat_id),
    field(identity.sender_device_id),
    field(identity.client_message_id),
  );
}

function field(value: string): Uint8Array {
  const encoded = utf8(value);
  const length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, encoded.length, false);
  return concatBytes(length, encoded);
}
