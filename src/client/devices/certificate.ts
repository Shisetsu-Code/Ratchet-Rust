import {
  DEVICE_CERTIFICATE_PROTOCOL,
  DEVICE_CERTIFICATE_VERSION,
  decodeDeviceCertificate,
  deviceCertificateSigningBytes,
  encodeDeviceCertificate,
  type DeviceCertificatePayload,
} from '../../shared/contracts/device-certificates';
import { wipe } from '../crypto/primitives';
import { xed25519Sign, xed25519Verify } from '../crypto/xeddsa';

export type DeviceCertificateCrypto = {
  sign: (privateKey: Uint8Array, message: Uint8Array) => Promise<Uint8Array>;
  verify: (publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array) => Promise<boolean>;
};

const XED25519_CERTIFICATE_CRYPTO: DeviceCertificateCrypto = {
  sign: xed25519Sign,
  verify: xed25519Verify,
};

export async function createDeviceCertificate(
  signerPrivateIdentityKey: Uint8Array,
  input: Omit<DeviceCertificatePayload, 'protocol' | 'version'>,
  crypto: DeviceCertificateCrypto = XED25519_CERTIFICATE_CRYPTO,
): Promise<string> {
  const payload: DeviceCertificatePayload = {
    protocol: DEVICE_CERTIFICATE_PROTOCOL,
    version: DEVICE_CERTIFICATE_VERSION,
    ...input,
  };
  const signingBytes = deviceCertificateSigningBytes(payload);
  let signature: Uint8Array | undefined;
  try {
    signature = await crypto.sign(signerPrivateIdentityKey, signingBytes);
    if (signature.length !== 64) throw new Error('Device certificate signature must be 64 bytes');
    return encodeDeviceCertificate(payload, signature);
  } finally {
    wipe(signingBytes);
    if (signature) wipe(signature);
  }
}

export async function verifyDeviceCertificate(
  certificate: string,
  signerPublicIdentityKey: Uint8Array,
  crypto: DeviceCertificateCrypto = XED25519_CERTIFICATE_CRYPTO,
): Promise<DeviceCertificatePayload> {
  const decoded = decodeDeviceCertificate(certificate);
  const signingBytes = deviceCertificateSigningBytes(decoded.payload);
  try {
    const valid = await crypto.verify(signerPublicIdentityKey, signingBytes, decoded.signature);
    if (!valid) throw new Error('Device certificate signature verification failed');
    return decoded.payload;
  } finally {
    wipe(signingBytes, decoded.signature);
  }
}
