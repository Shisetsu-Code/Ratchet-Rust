import { z } from 'zod';

export const DEVICE_CERTIFICATE_PROTOCOL = 'secure-device-certificate' as const;
export const DEVICE_CERTIFICATE_VERSION = 1 as const;

export const DeviceCertificatePayloadSchema = z.object({
  protocol: z.literal(DEVICE_CERTIFICATE_PROTOCOL),
  version: z.literal(DEVICE_CERTIFICATE_VERSION),
  user_id: z.string().uuid(),
  device_id: z.string().uuid(),
  signer_device_id: z.string().uuid(),
  crypto_identity_public_key: z.string().min(16).max(4096),
});

const DeviceCertificateWireSchema = z.object({
  payload: DeviceCertificatePayloadSchema,
  signature: z.string().regex(/^[A-Za-z0-9_-]+$/),
});

export const RegisterDeviceCertificateRequestSchema = z.object({
  certificate: z.string().min(32).max(16_384),
});

export type DeviceCertificatePayload = z.infer<typeof DeviceCertificatePayloadSchema>;

export function deviceCertificateSigningBytes(payload: DeviceCertificatePayload): Uint8Array {
  const normalized = DeviceCertificatePayloadSchema.parse(payload);
  return new TextEncoder().encode(JSON.stringify({
    protocol: normalized.protocol,
    version: normalized.version,
    user_id: normalized.user_id,
    device_id: normalized.device_id,
    signer_device_id: normalized.signer_device_id,
    crypto_identity_public_key: normalized.crypto_identity_public_key,
  }));
}

export function encodeDeviceCertificate(payload: DeviceCertificatePayload, signature: Uint8Array): string {
  if (signature.length !== 64) throw new Error('Device certificate signature must be 64 bytes');
  const wire = {
    payload: DeviceCertificatePayloadSchema.parse(payload),
    signature: bytesToBase64Url(signature),
  };
  return bytesToBase64Url(new TextEncoder().encode(JSON.stringify(wire)));
}

export function decodeDeviceCertificate(certificate: string): { payload: DeviceCertificatePayload; signature: Uint8Array } {
  const decoded = new TextDecoder().decode(base64UrlToBytes(certificate));
  const wire = DeviceCertificateWireSchema.parse(JSON.parse(decoded) as unknown);
  const signature = base64UrlToBytes(wire.signature);
  if (signature.length !== 64) throw new Error('Device certificate signature must be 64 bytes');
  return { payload: wire.payload, signature };
}

function bytesToBase64Url(value: Uint8Array): string {
  let binary = '';
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

function base64UrlToBytes(value: string): Uint8Array {
  const padded = value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}
