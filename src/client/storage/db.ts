import { openDB, type IDBPDatabase } from 'idb';
import { LocalStorageError, normalizeStorageError } from './errors';
import { LOCAL_DB_NAME, LOCAL_DB_SCHEMA_VERSION, type LocalDbSchema } from './schema';

export type LocalDatabaseState = 'OPENING' | 'READY' | 'BLOCKED' | 'TERMINATED';

export async function openLocalDatabase(onState?: (state: LocalDatabaseState) => void): Promise<IDBPDatabase<LocalDbSchema>> {
  onState?.('OPENING');
  let opened: IDBPDatabase<LocalDbSchema> | undefined;
  try {
    const db = await openDB<LocalDbSchema>(LOCAL_DB_NAME, LOCAL_DB_SCHEMA_VERSION, {
      upgrade(database, oldVersion, _newVersion, transaction) {
        if (oldVersion < 1) {
          database.createObjectStore('device_identity', { keyPath: 'local_device_id' });

          const prekeys = database.createObjectStore('prekeys', { keyPath: 'prekey_id' });
          prekeys.createIndex('by-device', 'device_id');

          const sessions = database.createObjectStore('sessions', { keyPath: 'session_id' });
          sessions.createIndex('by-lock-name', 'lock_name', { unique: true });

          const skipped = database.createObjectStore('skipped_message_keys', { keyPath: 'key_id' });
          skipped.createIndex('by-session', 'session_id');

          const outbox = database.createObjectStore('pending_outbox', { keyPath: 'client_message_id' });
          outbox.createIndex('by-status', 'status');
          outbox.createIndex('by-chat', 'chat_id');

          const cache = database.createObjectStore('encrypted_cache', { keyPath: 'cache_key' });
          cache.createIndex('by-chat', 'chat_id');

          const uploads = database.createObjectStore('attachment_uploads', { keyPath: 'file_id' });
          uploads.createIndex('by-status', 'status');
          uploads.createIndex('by-chat', 'chat_id');

          database.createObjectStore('settings', { keyPath: 'key' });
        }
        if (oldVersion < 2) {
          const trusted = database.createObjectStore('trusted_peer_devices', { keyPath: 'device_id' });
          trusted.createIndex('by-user', 'user_id');
        }
        if (oldVersion < 3) {
          transaction.objectStore('encrypted_cache').createIndex('by-chat-revision', ['chat_id', 'revision']);
        }
        if (oldVersion < 4) {
          const timeline = database.createObjectStore('message_timeline', { keyPath: 'timeline_key' });
          timeline.createIndex('by-chat-visible-revision', ['chat_id', 'visible', 'revision']);
          const outbox = transaction.objectStore('pending_outbox');
          outbox.createIndex('by-chat-status', ['chat_id', 'status']);
          outbox.createIndex('by-chat-status-sequence', ['chat_id', 'status', 'request.sender_sequence']);
          outbox.createIndex('by-chat-device-status-sequence', ['chat_id', 'sender_device_id', 'status', 'request.sender_sequence']);
          // Encrypted history is migrated in bounded, resumable batches after
          // opening; WebCrypto must never run inside an upgrade transaction.
        }
      },
      blocked() {
        onState?.('BLOCKED');
      },
      blocking() {
        onState?.('BLOCKED');
        opened?.close();
      },
      terminated() {
        onState?.('TERMINATED');
      },
    });
    opened = db;
    onState?.('READY');
    return db;
  } catch (error) {
    if (error instanceof DOMException && error.name === 'VersionError') {
      throw new LocalStorageError('VERSION_MISMATCH', 'A newer local database schema is already present', error);
    }
    throw normalizeStorageError(error);
  }
}
