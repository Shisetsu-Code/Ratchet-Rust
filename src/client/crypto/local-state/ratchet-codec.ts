import type { DoubleRatchetState, SkippedMessageKey } from '../double-ratchet/types';
import { base64UrlToBytes, bytesToBase64Url } from './base64url';

const FORMAT_VERSION = 1;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

type SerializedCore = {
  format: 1;
  dhs_private: string;
  dhs_public: string;
  dhr: string | null;
  rk: string;
  cks: string | null;
  ckr: string | null;
  ns: number;
  nr: number;
  pn: number;
};

export function serializeRatchetCore(state: DoubleRatchetState): Uint8Array {
  const value: SerializedCore = {
    format: FORMAT_VERSION,
    dhs_private: bytesToBase64Url(state.dhs.privateKey),
    dhs_public: bytesToBase64Url(state.dhs.publicKey),
    dhr: state.dhr ? bytesToBase64Url(state.dhr) : null,
    rk: bytesToBase64Url(state.rk),
    cks: state.cks ? bytesToBase64Url(state.cks) : null,
    ckr: state.ckr ? bytesToBase64Url(state.ckr) : null,
    ns: state.ns,
    nr: state.nr,
    pn: state.pn,
  };
  return encoder.encode(JSON.stringify(value));
}

export function deserializeRatchetCore(value: Uint8Array, skipped: SkippedMessageKey[] = []): DoubleRatchetState {
  let raw: unknown;
  try {
    raw = JSON.parse(decoder.decode(value));
  } catch {
    throw new Error('Corrupt ratchet state encoding');
  }
  if (!isSerializedCore(raw)) throw new Error('Unsupported or corrupt ratchet state encoding');
  const state: DoubleRatchetState = {
    dhs: {
      privateKey: base64UrlToBytes(raw.dhs_private),
      publicKey: base64UrlToBytes(raw.dhs_public),
    },
    dhr: raw.dhr === null ? null : base64UrlToBytes(raw.dhr),
    rk: base64UrlToBytes(raw.rk),
    cks: raw.cks === null ? null : base64UrlToBytes(raw.cks),
    ckr: raw.ckr === null ? null : base64UrlToBytes(raw.ckr),
    ns: raw.ns,
    nr: raw.nr,
    pn: raw.pn,
    skipped: skipped.map((entry) => ({ dh: entry.dh.slice(), n: entry.n, messageKey: entry.messageKey.slice() })),
  };
  validateState(state);
  return state;
}

function isSerializedCore(value: unknown): value is SerializedCore {
  if (!value || typeof value !== 'object') return false;
  const row = value as Record<string, unknown>;
  return row.format === FORMAT_VERSION
    && typeof row.dhs_private === 'string'
    && typeof row.dhs_public === 'string'
    && (row.dhr === null || typeof row.dhr === 'string')
    && typeof row.rk === 'string'
    && (row.cks === null || typeof row.cks === 'string')
    && (row.ckr === null || typeof row.ckr === 'string')
    && isCounter(row.ns)
    && isCounter(row.nr)
    && isCounter(row.pn);
}

function validateState(state: DoubleRatchetState): void {
  for (const [label, bytes] of [
    ['DHs private', state.dhs.privateKey],
    ['DHs public', state.dhs.publicKey],
    ['root key', state.rk],
  ] as const) {
    if (bytes.length !== 32) throw new Error(`${label} must be 32 bytes`);
  }
  if (state.dhr && state.dhr.length !== 32) throw new Error('DHr must be 32 bytes');
  if (state.cks && state.cks.length !== 32) throw new Error('CKs must be 32 bytes');
  if (state.ckr && state.ckr.length !== 32) throw new Error('CKr must be 32 bytes');
}

function isCounter(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 0xffff_ffff;
}
