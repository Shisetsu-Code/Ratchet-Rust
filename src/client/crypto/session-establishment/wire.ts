import { z } from 'zod';
import type { RatchetHeader } from '../double-ratchet/types';
import type { PqXdhInitiationHeader } from '../pqxdh/types';
import { base64UrlToBytes, bytesToBase64Url } from '../local-state/base64url';

const BytesSchema = z.string().regex(/^[A-Za-z0-9_-]+$/);
const RatchetHeaderWireSchema = z.object({
  dh: BytesSchema,
  pn: z.number().int().nonnegative(),
  n: z.number().int().nonnegative(),
});
const PqXdhHeaderWireSchema = z.object({
  identity_public_key: BytesSchema,
  ephemeral_public_key: BytesSchema,
  kem_ciphertext: BytesSchema,
  signed_prekey_id: z.string().min(1),
  pq_prekey_id: z.string().min(1),
  pq_prekey_kind: z.enum(['ONE_TIME', 'LAST_RESORT']),
  ec_one_time_prekey_id: z.string().min(1).nullable(),
});
const PrekeyHeaderWireSchema = z.object({
  protocol: z.literal('secure-messaging'),
  version: z.literal(1),
  kind: z.literal('prekey'),
  session_id: z.string().uuid(),
  pqxdh: PqXdhHeaderWireSchema,
  ratchet: RatchetHeaderWireSchema,
});
const RatchetOnlyHeaderWireSchema = z.object({
  protocol: z.literal('secure-messaging'),
  version: z.literal(1),
  kind: z.literal('ratchet'),
  session_id: z.string().uuid(),
  ratchet: RatchetHeaderWireSchema,
});
const SessionHeaderWireSchema = z.discriminatedUnion('kind', [PrekeyHeaderWireSchema, RatchetOnlyHeaderWireSchema]);

export type PrekeySessionHeader = {
  protocol: 'secure-messaging';
  version: 1;
  kind: 'prekey';
  sessionId: string;
  pqxdh: PqXdhInitiationHeader;
  ratchet: RatchetHeader;
};

export type RatchetSessionHeader = {
  protocol: 'secure-messaging';
  version: 1;
  kind: 'ratchet';
  sessionId: string;
  ratchet: RatchetHeader;
};

export type SessionMessageHeader = PrekeySessionHeader | RatchetSessionHeader;

export function encodeSessionMessageHeader(header: SessionMessageHeader): string {
  const wire = header.kind === 'prekey'
    ? {
        protocol: header.protocol,
        version: header.version,
        kind: header.kind,
        session_id: header.sessionId,
        pqxdh: {
          identity_public_key: bytesToBase64Url(header.pqxdh.identityPublicKey),
          ephemeral_public_key: bytesToBase64Url(header.pqxdh.ephemeralPublicKey),
          kem_ciphertext: bytesToBase64Url(header.pqxdh.kemCiphertext),
          signed_prekey_id: header.pqxdh.signedPrekeyId,
          pq_prekey_id: header.pqxdh.pqPrekeyId,
          pq_prekey_kind: header.pqxdh.pqPrekeyKind,
          ec_one_time_prekey_id: header.pqxdh.ecOneTimePrekeyId,
        },
        ratchet: encodeRatchet(header.ratchet),
      }
    : {
        protocol: header.protocol,
        version: header.version,
        kind: header.kind,
        session_id: header.sessionId,
        ratchet: encodeRatchet(header.ratchet),
      };
  return bytesToBase64Url(new TextEncoder().encode(JSON.stringify(wire)));
}

export function decodeSessionMessageHeader(encoded: string): SessionMessageHeader {
  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(new TextDecoder().decode(base64UrlToBytes(encoded)));
  } catch (error) {
    throw new Error(`Invalid secure message header: ${error instanceof Error ? error.message : 'decode failed'}`);
  }
  const wire = SessionHeaderWireSchema.parse(parsedJson);
  const ratchet = decodeRatchet(wire.ratchet);
  if (wire.kind === 'ratchet') {
    return {
      protocol: 'secure-messaging',
      version: 1,
      kind: 'ratchet',
      sessionId: wire.session_id,
      ratchet,
    };
  }
  return {
    protocol: 'secure-messaging',
    version: 1,
    kind: 'prekey',
    sessionId: wire.session_id,
    pqxdh: {
      identityPublicKey: base64UrlToBytes(wire.pqxdh.identity_public_key),
      ephemeralPublicKey: base64UrlToBytes(wire.pqxdh.ephemeral_public_key),
      kemCiphertext: base64UrlToBytes(wire.pqxdh.kem_ciphertext),
      signedPrekeyId: wire.pqxdh.signed_prekey_id,
      pqPrekeyId: wire.pqxdh.pq_prekey_id,
      pqPrekeyKind: wire.pqxdh.pq_prekey_kind,
      ecOneTimePrekeyId: wire.pqxdh.ec_one_time_prekey_id,
    },
    ratchet,
  };
}

function encodeRatchet(header: RatchetHeader): { dh: string; pn: number; n: number } {
  return { dh: bytesToBase64Url(header.dh), pn: header.pn, n: header.n };
}

function decodeRatchet(header: z.infer<typeof RatchetHeaderWireSchema>): RatchetHeader {
  return { dh: base64UrlToBytes(header.dh), pn: header.pn, n: header.n };
}
