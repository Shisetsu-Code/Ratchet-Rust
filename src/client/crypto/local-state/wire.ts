import type { DeviceEnvelope } from '../../../shared/contracts/messages';
import type { RatchetCiphertext } from '../double-ratchet/types';
import { decodeSessionMessageHeader, encodeSessionMessageHeader } from '../session-establishment/wire';
import { base64UrlToBytes, bytesToBase64Url } from './base64url';

export function ratchetMessageToEnvelope(
  message: RatchetCiphertext,
  recipientUserId: string,
  recipientDeviceId: string,
  sessionId: string,
): DeviceEnvelope {
  return {
    recipient_user_id: recipientUserId,
    recipient_device_id: recipientDeviceId,
    protocol: 'secure-messaging',
    protocol_version: 2,
    header: encodeSessionMessageHeader({
      protocol: 'secure-messaging',
      version: 1,
      kind: 'ratchet',
      sessionId,
      ratchet: message.header,
    }),
    ciphertext: bytesToBase64Url(message.ciphertext),
  };
}

export function envelopeToRatchetMessage(header: string, ciphertext: string, expectedSessionId: string): RatchetCiphertext {
  const decoded = decodeSessionMessageHeader(header);
  if (decoded.kind !== 'ratchet') throw new Error('Expected an established ratchet message');
  if (decoded.sessionId !== expectedSessionId) throw new Error('Secure message session_id does not match local pairwise session');
  return {
    header: decoded.ratchet,
    ciphertext: base64UrlToBytes(ciphertext),
  };
}
