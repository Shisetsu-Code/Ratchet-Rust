import type { IDBPDatabase } from 'idb';
import type { SkippedMessageKey } from '../double-ratchet/types';
import type { LocalDbSchema, SkippedMessageKeyRecord } from '../../storage/schema';
import { skippedKeyAad } from './aad';
import { base64UrlToBytes, bytesToBase64Url } from './base64url';
import { unwrapLocalSecret, wrapLocalSecret } from './wrapping';

export async function loadSkippedMessageKeys(
  db: IDBPDatabase<LocalDbSchema>,
  masterKey: CryptoKey,
  sessionId: string,
): Promise<SkippedMessageKey[]> {
  const records = await db.getAllFromIndex('skipped_message_keys', 'by-session', sessionId);
  const result: SkippedMessageKey[] = [];
  for (const record of records) {
    const dhEncoded = bytesToBase64Url(record.dh);
    const plaintext = await unwrapLocalSecret(
      masterKey,
      { nonce: record.nonce, ciphertext: record.encrypted_key },
      skippedKeyAad(sessionId, dhEncoded, record.message_number),
    );
    if (plaintext.length !== 32) throw new Error('Stored skipped message key has invalid length');
    result.push({ dh: record.dh.slice(), n: record.message_number, messageKey: plaintext });
  }
  return result.sort((a, b) => a.n - b.n || bytesToBase64Url(a.dh).localeCompare(bytesToBase64Url(b.dh)));
}

export async function wrapSkippedMessageKeys(
  masterKey: CryptoKey,
  sessionId: string,
  skipped: readonly SkippedMessageKey[],
): Promise<SkippedMessageKeyRecord[]> {
  const now = new Date().toISOString();
  const result: SkippedMessageKeyRecord[] = [];
  for (const entry of skipped) {
    const dhEncoded = bytesToBase64Url(entry.dh);
    const wrapped = await wrapLocalSecret(
      masterKey,
      entry.messageKey,
      skippedKeyAad(sessionId, dhEncoded, entry.n),
    );
    result.push({
      key_id: skippedRecordId(sessionId, entry.dh, entry.n),
      session_id: sessionId,
      dh: entry.dh.slice(),
      message_number: entry.n,
      encrypted_key: wrapped.ciphertext,
      nonce: wrapped.nonce,
      created_at: now,
    });
  }
  return result;
}

export function skippedRecordId(sessionId: string, dh: Uint8Array, messageNumber: number): string {
  return `${sessionId}:${bytesToBase64Url(dh)}:${messageNumber}`;
}

export function parseSkippedRecordId(value: string): { sessionId: string; dh: Uint8Array; messageNumber: number } {
  const last = value.lastIndexOf(':');
  const middle = value.lastIndexOf(':', last - 1);
  if (last <= 0 || middle <= 0) throw new Error('Invalid skipped-key record ID');
  const sessionId = value.slice(0, middle);
  const dh = base64UrlToBytes(value.slice(middle + 1, last));
  const messageNumber = Number(value.slice(last + 1));
  if (!Number.isSafeInteger(messageNumber) || messageNumber < 0) throw new Error('Invalid skipped-key message number');
  return { sessionId, dh, messageNumber };
}
