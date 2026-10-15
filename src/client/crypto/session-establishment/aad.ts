import { concatBytes, utf8 } from '../encoding';

const SESSION_DOMAIN = utf8('RatchetSecureSupport/session-message-aad/v1');

export function sessionMessageAad(
  conversationAad: Uint8Array,
  pqxdhAssociatedData: Uint8Array,
  sessionId: string,
): Uint8Array {
  return concatBytes(
    SESSION_DOMAIN,
    lengthPrefix(conversationAad),
    lengthPrefix(pqxdhAssociatedData),
    lengthPrefix(utf8(sessionId)),
  );
}

function lengthPrefix(value: Uint8Array): Uint8Array {
  const length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, value.length, false);
  return concatBytes(length, value);
}
