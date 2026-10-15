import { concatBytes, utf8 } from '../encoding';

const STATE_DOMAIN = utf8('RatchetSecureSupport/local-state/v1');
const SKIPPED_DOMAIN = utf8('RatchetSecureSupport/skipped-key/v1');
const MESSAGE_DOMAIN = utf8('RatchetSecureSupport/message-aad/v1');

export function sessionStateAad(sessionId: string, localDeviceId: string, remoteDeviceId: string): Uint8Array {
  return encodeFields(STATE_DOMAIN, sessionId, localDeviceId, remoteDeviceId);
}

export function skippedKeyAad(sessionId: string, dhBase64Url: string, messageNumber: number): Uint8Array {
  return encodeFields(SKIPPED_DOMAIN, sessionId, dhBase64Url, String(messageNumber));
}

export function conversationMessageAad(
  chatId: string,
  senderUserId: string,
  senderDeviceId: string,
  recipientUserId: string,
  recipientDeviceId: string,
): Uint8Array {
  return encodeFields(
    MESSAGE_DOMAIN,
    'secure-messaging',
    '1',
    chatId,
    senderUserId,
    senderDeviceId,
    recipientUserId,
    recipientDeviceId,
  );
}

function encodeFields(domain: Uint8Array, ...fields: readonly string[]): Uint8Array {
  const encoded = fields.map((field) => {
    const value = utf8(field);
    const length = new Uint8Array(4);
    new DataView(length.buffer).setUint32(0, value.length, false);
    return concatBytes(length, value);
  });
  return concatBytes(domain, ...encoded);
}
