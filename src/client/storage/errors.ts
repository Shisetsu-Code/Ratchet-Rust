export type LocalStorageErrorType =
  | 'BLOCKED'
  | 'TERMINATED'
  | 'QUOTA_EXCEEDED'
  | 'VERSION_MISMATCH'
  | 'CORRUPT_STATE'
  | 'LOCK_TIMEOUT'
  | 'LEASE_LOST'
  | 'STATE_VERSION_CONFLICT';

export class LocalStorageError extends Error {
  constructor(readonly type: LocalStorageErrorType, message: string, readonly source?: unknown) {
    super(message);
  }
}

export function normalizeStorageError(error: unknown): LocalStorageError {
  if (error instanceof LocalStorageError) return error;
  if (error instanceof DOMException) {
    if (error.name === 'QuotaExceededError') return new LocalStorageError('QUOTA_EXCEEDED', 'IndexedDB quota exceeded', error);
    if (error.name === 'VersionError') return new LocalStorageError('VERSION_MISMATCH', 'IndexedDB version mismatch', error);
  }
  return new LocalStorageError('CORRUPT_STATE', 'Local storage operation failed', error);
}
