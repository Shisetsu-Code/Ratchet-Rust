import {queueServerMessages} from "./server-message-transport";
import type { IDBPDatabase } from 'idb';
import type { LocalDbSchema, PendingOutboxRecord } from '../storage/schema';
import type { DeliveryCacheMetadata } from '../storage/message-cache';
import { LocalStorageError } from '../storage/errors';
import { withCryptoLock } from '../storage/locks';
import { createHttpOutboxTransport, drainPendingOutbox, sendPendingOutboxRecord } from '../storage/outbox';
import { decryptRetryMaterial } from '../storage/retry-material';
import { disposeDeviceIdentity, generateDeviceIdentity, loadDeviceIdentity, persistGeneratedDeviceIdentity } from './key-vault/identity';
import { type AtomicMultiDeviceTarget, type EstablishedAtomicTarget } from './multi-device/atomic-send';
import { prepareAtomicEstablishedMessageBatch } from './multi-device/established-batch';
import { resolveAtomicTargets, resolveCachedAtomicTargets } from './multi-device/resolve-targets';
import { replenishPrekeys } from './prekeys/replenish';
import { wipe } from './primitives';
import { receiveSecureEnvelope } from './session-establishment/receive';
import { base64UrlToBytes } from './local-state/base64url';
import { createSignedRecoveryArchive, decryptBoundRecoveryArchive, type RecoveryRecipient } from './recovery/archive';
import { getRecoveryEnvelopeHttp, getRecoveryRecipientsHttp } from './recovery/api';
import { loadSendKeyContext, type SendKeyContext } from './send-context';
import { assertRecoveryRecipientCoverage, recoveryPinKey, verifyAndPinRecoveryRecipient } from './recovery/trust';
import { getChatDetailHttp } from '../chat/api';
import { ensureSelfDeviceTrust, verifyAndPersistTrustedDeviceSet } from './trust/device-trust';
import { discoverPrekeyBundles } from './prekeys/api';
import { frameAuthenticatedMessageContent, MessageSemanticsError, type MessageSemantics } from '../chat/content';

const MAX_TARGET_REFRESH_ROUNDS = 2;
const MAX_STREAM_SEND_ROUNDS = 5;
export type DeviceIdentity = { deviceId: string; identityPublicKey: Uint8Array };
export type QueueMessageInput = {
  chat_id: string;
  client_message_id: string;
  plaintext?: Uint8Array;
  attachment_ids?: string[];
  sender_sequence?: number;
  allocate_sender_sequence?: boolean;
  mutation?: { target_message_id: string; type: 'EDIT' | 'TOMBSTONE' };
  reply_to_message_id?: string;
};
export type DecryptEnvelopeInput = {
  chat_id: string;
  remote_user_id: string;
  remote_device_id: string;
  header: string;
  ciphertext: string;
  delivery?: DeliveryCacheMetadata;
};
export type DecryptRecoveryMessageInput = MessageSemantics & { message_id: string; recovery_key_id: string; recovery_private_key: Uint8Array };

export interface SecureMessagingEngine {
  createIdentity(): Promise<DeviceIdentity>;
  publishPreKeyBundle(): Promise<void>;
  queueMessage(input: QueueMessageInput): Promise<PendingOutboxRecord>;
  queueEstablishedBatch(inputs: QueueMessageInput[]): Promise<PendingOutboxRecord[] | null>;
  queueStreamingMessage(input: QueueMessageInput): Promise<PendingOutboxRecord | null>;
  flushPreparedMessage(input: QueueMessageInput): Promise<PendingOutboxRecord>;
  sendMessage(input: QueueMessageInput): Promise<PendingOutboxRecord>;
  canBatchMessage(chatId: string): Promise<boolean>;
  clearHotSendContext(chatId?: string): void;
  decryptEnvelope(input: DecryptEnvelopeInput): Promise<Uint8Array>;
  decryptRecoveryMessage(input: DecryptRecoveryMessageInput): Promise<Uint8Array>;
  revokePeerDevice(deviceId: string): Promise<void>;
}

export class BrowserSecureMessagingEngine implements SecureMessagingEngine {
  private sendKeyContextPromise: Promise<SendKeyContext> | null = null;
  private readonly emptyRecoveryUntil = new Map<string, number>();
  private readonly hotTargets = new Map<string, AtomicMultiDeviceTarget[]>();

  constructor(
    private readonly db: IDBPDatabase<LocalDbSchema>,
    private readonly localUserId: string,
    private readonly localDeviceId: string,
  ) {}

  async createIdentity(): Promise<DeviceIdentity> {
    const existing = await this.db.get('device_identity', this.localDeviceId);
    if (existing) {
      const identityPublicKey = base64UrlToBytes(existing.identity_public_key);
      if (identityPublicKey.length !== 32) throw new LocalStorageError('CORRUPT_STATE', 'Stored local X25519 identity key must be 32 bytes');
      return { deviceId: this.localDeviceId, identityPublicKey };
    }
    const generated = await generateDeviceIdentity();
    try {
      const record = await persistGeneratedDeviceIdentity(this.db, this.localDeviceId, generated);
      const identityPublicKey = base64UrlToBytes(record.identity_public_key);
      if (identityPublicKey.length !== 32) throw new LocalStorageError('CORRUPT_STATE', 'Generated local X25519 identity key must be 32 bytes');
      return { deviceId: this.localDeviceId, identityPublicKey };
    } finally {
      disposeDeviceIdentity(generated);
    }
  }

  async publishPreKeyBundle(): Promise<void> {
    const identity = await this.db.get('device_identity', this.localDeviceId);
    if (!identity) throw new LocalStorageError('CORRUPT_STATE', 'Local device identity must exist before publishing prekeys');
    await replenishPrekeys(this.db, this.localDeviceId);
  }

  async canBatchMessage(_chatId: string): Promise<boolean> {
    return true;
  }

  clearHotSendContext(chatId?: string): void {
    if (chatId) {
      this.hotTargets.delete(chatId);
      return;
    }
    this.hotTargets.clear();
    this.emptyRecoveryUntil.clear();
    this.sendKeyContextPromise = null;
  }

  async queueMessage(input: QueueMessageInput): Promise<PendingOutboxRecord> {
    return (await queueServerMessages(this.db,this.localUserId,this.localDeviceId,[input]))[0]!;
  }

  async queueEstablishedBatch(inputs: QueueMessageInput[]): Promise<PendingOutboxRecord[] | null> {
    return queueServerMessages(this.db,this.localUserId,this.localDeviceId,inputs);
  }

  async queueStreamingMessage(input: QueueMessageInput): Promise<PendingOutboxRecord | null> {
    return this.queueMessage(input);
  }

  async queueStreamingBatch(inputs: QueueMessageInput[]): Promise<PendingOutboxRecord[] | null> {
    return queueServerMessages(this.db,this.localUserId,this.localDeviceId,inputs);
  }

  private async queueEstablishedGroup(inputs: QueueMessageInput[], allocateSenderSequence: boolean): Promise<PendingOutboxRecord[] | null> {
    if (inputs.length === 0) return [];
    const first = inputs[0]!;
    if (inputs.some((input) => input.chat_id !== first.chat_id
      || !input.plaintext
      || (input.attachment_ids?.length ?? 0) > 0
      || input.mutation
      || input.reply_to_message_id)) return null;

    const targets = await this.resolveCachedTargetsHot(first.chat_id);
    if (!targets || targets.length === 0 || targets.some((target) => target.mode !== 'established')) return null;
    const establishedTargets = targets as EstablishedAtomicTarget[];
    const [sendContext, recoveryRecipients] = await Promise.all([
      this.getSendKeyContext(),
      this.resolveRecoveryRecipients(first.chat_id, true),
    ]);
    const framed = inputs.map(entry => frameAuthenticatedMessageContent(entry.plaintext!, {
      ...entry, sender_user_id: this.localUserId, sender_device_id: this.localDeviceId,
    }));
    try {
    const recoveryEnvelopes = await this.signRecoveryArchives(framed, recoveryRecipients);
    const queued = await prepareAtomicEstablishedMessageBatch(this.db, sendContext.masterKey, {
      chat_id: first.chat_id,
      sender_user_id: this.localUserId,
      sender_device_id: this.localDeviceId,
      targets: establishedTargets,
      messages: inputs.map((entry, index) => ({
        client_message_id: entry.client_message_id,
        plaintext: framed[index]!,
        recovery_envelopes: recoveryEnvelopes[index]!,
      })),
      allocate_sender_sequence: allocateSenderSequence,
    });
    if (queued) this.hotTargets.set(first.chat_id, establishedTargets);
    return queued;
    } finally {
      framed.forEach((plaintext, index) => { if (plaintext !== inputs[index]!.plaintext) wipe(plaintext); });
    }
  }

  /**
   * Legacy HTTP completion path retained for pending records created by older
   * clients. New interactive sends transport the already-durable request through
   * ChatRealtimeClient and only use HTTP after the realtime ACK deadline.
   */
  async flushPreparedMessage(input: QueueMessageInput): Promise<PendingOutboxRecord> {
    let preservedSequence = input.sender_sequence;
    for (let round = 0; round < MAX_STREAM_SEND_ROUNDS; round += 1) {
      let current = await this.db.get('pending_outbox', input.client_message_id);
      if (!current) current = await this.queueMessage(input);
      preservedSequence ??= current.request.sender_sequence;
      if (current.status === 'COMMITTED' || current.status === 'FAILED') return current;

      const sent = await sendPendingOutboxRecord(this.db, current.client_message_id);
      if (sent.status === 'COMMITTED' || sent.status === 'FAILED') return sent;

      if (sent.status === 'NEEDS_REENCRYPT') {
        this.clearHotSendContext(input.chat_id);
        current = await this.queueMessage({
          ...input,
          ...(preservedSequence !== undefined ? { sender_sequence: preservedSequence } : {}),
        });
        if (current.status === 'COMMITTED' || current.status === 'FAILED') return current;
        continue;
      }

      if (sent.status === 'VERIFY_ACCEPTANCE') continue;
      if (sent.status === 'PENDING' && sent.last_error_type === 'SENDER_SEQUENCE_GAP') {
        await delay(20 * (round + 1));
        continue;
      }
      return sent;
    }
    const final = await this.db.get('pending_outbox', input.client_message_id);
    if (!final) throw new LocalStorageError('CORRUPT_STATE', 'Outgoing streaming message disappeared after retries');
    return final;
  }

  async sendMessage(input: QueueMessageInput): Promise<PendingOutboxRecord> {
    const transport = createHttpOutboxTransport();
    for (let round = 0; round <= MAX_TARGET_REFRESH_ROUNDS; round += 1) {
      const queued = await this.queueMessage(input);
      if (queued.status === 'COMMITTED' || queued.status === 'FAILED') return queued;
      await drainPendingOutbox(this.db, transport, undefined, input.chat_id);
      const current = await this.db.get('pending_outbox', input.client_message_id);
      if (!current) throw new LocalStorageError('CORRUPT_STATE', 'Outgoing message disappeared from local outbox');
      if (current.status !== 'NEEDS_REENCRYPT') return current;
    }
    const final = await this.db.get('pending_outbox', input.client_message_id);
    if (!final) throw new LocalStorageError('CORRUPT_STATE', 'Outgoing message disappeared after target refresh');
    return final;
  }

  async decryptEnvelope(input: DecryptEnvelopeInput): Promise<Uint8Array> {
    const identity = await loadDeviceIdentity(this.db, this.localDeviceId);
    try {
      return await receiveSecureEnvelope(this.db, identity.masterKey, {
        chat_id: input.chat_id,
        local_user_id: this.localUserId,
        local_device_id: this.localDeviceId,
        remote_user_id: input.remote_user_id,
        remote_device_id: input.remote_device_id,
        header: input.header,
        ciphertext: input.ciphertext,
        ...(input.delivery ? { delivery: input.delivery } : {}),
      });
    } finally {
      disposeDeviceIdentity(identity);
    }
  }

  async decryptRecoveryMessage(input: DecryptRecoveryMessageInput): Promise<Uint8Array> {
    const sender = await this.db.get('trusted_peer_devices', input.sender_device_id);
    if (!sender || sender.user_id !== input.sender_user_id || sender.revoked_at) {
      throw new MessageSemanticsError('Recovery sender requires a trusted active identity');
    }
    const discovery = await discoverPrekeyBundles(input.sender_user_id, input.chat_id);
    if (discovery.user_id !== input.sender_user_id || !discovery.devices.some(device => device.device_id === input.sender_device_id)) {
      throw new MessageSemanticsError('Recovery sender is absent from active device discovery');
    }
    await verifyAndPersistTrustedDeviceSet(this.db, input.sender_user_id, discovery.devices);
    const envelope = await getRecoveryEnvelopeHttp(input.chat_id, input.message_id, input.recovery_key_id);
    if (envelope.message_id !== input.message_id || envelope.recovery_key_id !== input.recovery_key_id) {
      throw new MessageSemanticsError('Recovery response differs from requested message or key');
    }
    return decryptBoundRecoveryArchive(envelope, input.recovery_private_key, input, base64UrlToBytes(sender.identity_public_key));
  }

  async revokePeerDevice(deviceId: string): Promise<void> {
    if (deviceId === this.localDeviceId) throw new LocalStorageError('CORRUPT_STATE', 'Current device cannot revoke its own pairwise session through peer revocation');
    const lockName = `crypto:${this.localDeviceId}:${deviceId}`;
    await withCryptoLock(this.db, lockName, async () => {
      const session = await this.db.getFromIndex('sessions', 'by-lock-name', lockName);
      if (!session) return;
      const tx = this.db.transaction(['sessions', 'skipped_message_keys'], 'readwrite');
      const current = await tx.objectStore('sessions').get(session.session_id);
      if (!current || current.local_device_id !== this.localDeviceId || current.remote_device_id !== deviceId) {
        tx.abort();
        throw new LocalStorageError('STATE_VERSION_CONFLICT', 'Pairwise session changed before peer revocation');
      }
      const skipped = tx.objectStore('skipped_message_keys');
      const skippedKeys = await skipped.index('by-session').getAllKeys(session.session_id);
      for (const key of skippedKeys) await skipped.delete(key);
      await tx.objectStore('sessions').delete(session.session_id);
      await tx.done;
    });
    this.hotTargets.clear();
    this.emptyRecoveryUntil.clear();
  }

  private async getSendKeyContext(): Promise<SendKeyContext> {
    if (!this.sendKeyContextPromise) {
      this.sendKeyContextPromise = loadSendKeyContext(this.db, this.localDeviceId).catch((error) => {
        this.sendKeyContextPromise = null;
        throw error;
      });
    }
    return this.sendKeyContextPromise;
  }

  private async createRecoveryEnvelopes(chatId: string, plaintext: Uint8Array, allowCache: boolean) {
    const recipients = await this.resolveRecoveryRecipients(chatId, allowCache);
    return (await this.signRecoveryArchives([plaintext], recipients))[0]!;
  }

  private async signRecoveryArchives(plaintexts: readonly Uint8Array[], recipients: readonly RecoveryRecipient[]) {
    if (recipients.length === 0) return plaintexts.map(() => []);
    const identity = await loadDeviceIdentity(this.db, this.localDeviceId);
    try {
      const archives = [];
      for (const plaintext of plaintexts) {
        archives.push(await createSignedRecoveryArchive(plaintext, recipients, identity.keyPair.privateKey));
      }
      return archives;
    } finally {
      disposeDeviceIdentity(identity);
    }
  }

  private async resolveRecoveryRecipients(chatId: string, allowCache: boolean): Promise<RecoveryRecipient[]> {
    // Cache only the absence of recovery recipients, never public keys or proofs.
    // D1 rejects this exact set if a key is registered meanwhile; that rejection
    // forces a live lookup before re-encryption. No stale key receives plaintext.
    const prefix = recoveryPinKey('');
    const pinnedUsers = (await this.db.getAllKeys('settings'))
      .filter(key => key.startsWith(prefix)).map(key => key.slice(prefix.length));
    if (pinnedUsers.length === 0 && allowCache && (this.emptyRecoveryUntil.get(chatId) ?? 0) > Date.now()) return [];
    this.emptyRecoveryUntil.delete(chatId);
    const set = await getRecoveryRecipientsHttp(chatId);
    if (pinnedUsers.length > 0 || set.recovery_keys.length > 0) {
      const chat = await getChatDetailHttp(chatId);
      if (chat.chat_id !== chatId) throw new Error('Recovery chat discovery returned another conversation');
      assertRecoveryRecipientCoverage(chat.participants.map(participant => participant.user_id), pinnedUsers,
        set.recovery_keys.map(recipient => recipient.user_id));
    }
    if (set.recovery_keys.length === 0) {
      this.emptyRecoveryUntil.set(chatId, Date.now() + 5_000);
      return [];
    }
    const context = await this.getSendKeyContext();
    await ensureSelfDeviceTrust(this.db, this.localUserId, this.localDeviceId, context.publicKeyEncoded);
    for (const recipient of set.recovery_keys) {
      const discovery = await discoverPrekeyBundles(recipient.user_id, chatId);
      if (discovery.user_id !== recipient.user_id) throw new Error('Recovery signer discovery returned another user');
      await verifyAndPersistTrustedDeviceSet(this.db, recipient.user_id, discovery.devices);
      await verifyAndPinRecoveryRecipient(this.db, recipient, discovery.devices.map(device => device.device_id));
    }
    const recipients = set.recovery_keys.map((recipient) => {
      const publicKey = base64UrlToBytes(recipient.public_key);
      if (publicKey.length !== 32) throw new LocalStorageError('CORRUPT_STATE', `Recovery public key ${recipient.recovery_key_id} must be 32 bytes`);
      return { recovery_key_id: recipient.recovery_key_id, public_key: publicKey };
    });
    return recipients;
  }

  private async resolveCachedTargetsHot(chatId: string): Promise<AtomicMultiDeviceTarget[] | null> {
    const hot = this.hotTargets.get(chatId);
    if (hot) return hot;
    const cached = await resolveCachedAtomicTargets(this.db, chatId, this.localDeviceId);
    if (cached) this.hotTargets.set(chatId, cached);
    return cached;
  }

  private async resolveTargetsWithCache(chatId: string, identityPublicKey: string): Promise<AtomicMultiDeviceTarget[]> {
    const cached = await this.resolveCachedTargetsHot(chatId);
    if (cached) return cached;
    const resolved = await resolveAtomicTargets(this.db, chatId, this.localUserId, this.localDeviceId, identityPublicKey);
    if (resolved.every((target) => target.mode === 'established')) this.hotTargets.set(chatId, resolved);
    return resolved;
  }


  private async loadRetryPlaintext(masterKey: CryptoKey, record: PendingOutboxRecord): Promise<Uint8Array> {
    if (!record.encrypted_retry_material) throw new LocalStorageError('CORRUPT_STATE', 'Rejected ciphertext has no encrypted retry material');
    return decryptRetryMaterial(masterKey, {
      chat_id: record.chat_id,
      sender_device_id: record.sender_device_id,
      client_message_id: record.client_message_id,
    }, record.encrypted_retry_material);
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => globalThis.setTimeout(resolve, ms));
}
