import type { DBSchema } from 'idb';
import type { SendMessageRequest } from '../../shared/contracts/messages';

export const LOCAL_DB_NAME = 'ratchet-secure-support' as const;
export const LOCAL_DB_SCHEMA_VERSION = 4 as const;

export type DeviceIdentityRecord = { local_device_id: string; identity_public_key: string; encrypted_private_material: Uint8Array; private_material_nonce: Uint8Array; local_master_key?: CryptoKey; created_at: string };
export type PrekeyPurpose = 'SIGNED' | 'ONE_TIME' | 'LAST_RESORT';
export type PrekeyRecord = { prekey_id: string; device_id: string; kind: 'EC' | 'PQ'; purpose: PrekeyPurpose; public_key: string; signature?: string; encrypted_private_material: Uint8Array; private_material_nonce: Uint8Array; created_at: string; published_at?: string; consumed_at?: string };
export type CryptoSessionEstablishmentState = 'PENDING_FIRST_MESSAGE' | 'ESTABLISHED';
export type CryptoSessionRecord = { session_id: string; local_device_id: string; remote_device_id: string; remote_identity_public_key: Uint8Array; lock_name: string; protocol: 'secure-messaging'; protocol_version: 1; pqxdh_associated_data: Uint8Array; establishment_state: CryptoSessionEstablishmentState; state_ciphertext: Uint8Array; state_nonce: Uint8Array; state_version: number; updated_at: string };
export type SkippedMessageKeyRecord = { key_id: string; session_id: string; dh: Uint8Array; message_number: number; encrypted_key: Uint8Array; nonce: Uint8Array; created_at: string };
export type OutboxStatus = 'PENDING' | 'VERIFY_ACCEPTANCE' | 'COMMITTED' | 'FAILED' | 'NEEDS_REENCRYPT';
export type OutboxTransportState = 'DURABLE_LOCAL' | 'WS_IN_FLIGHT' | 'HTTP_FALLBACK_IN_FLIGHT' | 'RETRYING' | 'CONFIRMED' | 'FAILED';
export type StaleSetType = 'RECIPIENT_SET_STALE' | 'RECOVERY_SET_STALE';
export type PendingOutboxRecord = {
  client_message_id: string;
  chat_id: string;
  sender_device_id: string;
  request: SendMessageRequest;
  encrypted_retry_material?: Uint8Array;
  pending_session_ids?: string[];
  status: OutboxStatus;
  transport_state?: OutboxTransportState;
  attempts: number;
  created_at: string;
  updated_at: string;
  last_error_type?: string;
  stale_set_type?: StaleSetType;
  server_message_id?: string;
  server_revision?: number;
  server_accepted_at?: string;
};
export type TrustedDeviceMode = 'SELF' | 'ACCOUNT_AUTHORIZED' | 'TOFU' | 'VERIFIED' | 'CERTIFIED' | 'ROTATED';
export type TrustedPeerDeviceRecord = { device_id: string; user_id: string; identity_public_key: string; trust_mode: TrustedDeviceMode; signer_device_id?: string; certificate?: string; first_seen_at: string; verified_at: string; manual_verified_at?: string; root_device_id?: string; root_fingerprint?: string; revoked_at?: string };
export type EncryptedCacheRecord = { cache_key: string; chat_id: string; revision: number; ciphertext: Uint8Array; nonce: Uint8Array; updated_at: string };
export type EncryptedTimelineRecord = {
  timeline_key: string;
  chat_id: string;
  revision: number;
  applied_revision: number;
  visible: 0 | 1;
  ciphertext: Uint8Array;
  nonce: Uint8Array;
};
export type AttachmentUploadRecord = {
  file_id: string;
  chat_id: string;
  status: 'RESERVED' | 'UPLOADING' | 'READY' | 'COMMITTED' | 'ABORTED' | 'EXPIRED';
  upload_id?: string;
  object_key: string;
  next_part_number: number;
  etags: Record<string,string>;
  encrypted_file_key: Uint8Array;
  file_key_nonce: Uint8Array;
  nonce_prefix: string;
  plaintext_size: number;
  chunk_plaintext_bytes: number;
  encrypted_metadata: string;
  source_fingerprint: string;
  updated_at: string;
};
export type LeaseSetting = { key: string; kind: 'lease'; owner_id: string | null; fencing_token: number; expires_at: number };
export type JsonSetting = { key: string; kind: 'json'; value: unknown };
export type SettingRecord = LeaseSetting | JsonSetting;
export interface LocalDbSchema extends DBSchema {
  device_identity: { key: string; value: DeviceIdentityRecord };
  prekeys: { key: string; value: PrekeyRecord; indexes: { 'by-device': string } };
  sessions: { key: string; value: CryptoSessionRecord; indexes: { 'by-lock-name': string } };
  skipped_message_keys: { key: string; value: SkippedMessageKeyRecord; indexes: { 'by-session': string } };
  pending_outbox: { key: string; value: PendingOutboxRecord; indexes: { 'by-status': OutboxStatus; 'by-chat': string; 'by-chat-status': [string, OutboxStatus]; 'by-chat-status-sequence': [string, OutboxStatus, number]; 'by-chat-device-status-sequence': [string, string, OutboxStatus, number] } };
  trusted_peer_devices: { key: string; value: TrustedPeerDeviceRecord; indexes: { 'by-user': string } };
  encrypted_cache: { key: string; value: EncryptedCacheRecord; indexes: { 'by-chat': string; 'by-chat-revision': [string, number] } };
  message_timeline: { key: string; value: EncryptedTimelineRecord; indexes: { 'by-chat-visible-revision': [string, number, number] } };
  attachment_uploads: { key: string; value: AttachmentUploadRecord; indexes: { 'by-status': AttachmentUploadRecord['status']; 'by-chat': string } };
  settings: { key: string; value: SettingRecord };
}
