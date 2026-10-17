type Waiter = {
  bytes: number;
  resolve: (release: () => void) => void;
  reject: (reason: unknown) => void;
  signal?: AbortSignal;
  cancel?: () => void;
};

/** A reservation lives until the owner releases its buffers/object URLs. */
export class AttachmentResourceBudget {
  private active = 0;
  private bytes = 0;
  private readonly waiting: Waiter[] = [];
  private readonly maxActive: number;
  private readonly maxBytes: number;
  private readonly maxQueued: number;

  constructor(maxActive: number, maxBytes: number, maxQueued: number) {
    this.maxActive = maxActive; this.maxBytes = maxBytes; this.maxQueued = maxQueued;
  }

  reserve(bytes: number, signal?: AbortSignal): Promise<() => void> {
    if (!Number.isSafeInteger(bytes) || bytes < 1 || bytes > this.maxBytes) return Promise.reject(new Error('Attachment size exceeds the memory budget'));
    if (signal?.aborted) return Promise.reject(signal.reason);
    if (!this.waiting.length && this.canStart(bytes)) return Promise.resolve(this.start(bytes));
    if (this.waiting.length >= this.maxQueued) return Promise.reject(new Error('La cola de archivos está ocupada. Volvé a intentar.'));
    return new Promise((resolve, reject) => {
      const entry: Waiter = { bytes, resolve, reject, ...(signal ? { signal } : {}) };
      entry.cancel = () => {
        const index = this.waiting.indexOf(entry);
        if (index >= 0) this.waiting.splice(index, 1);
        reject(signal?.reason ?? new DOMException('Aborted', 'AbortError'));
        this.drain();
      };
      this.waiting.push(entry);
      signal?.addEventListener('abort', entry.cancel, { once: true });
    });
  }

  private canStart(bytes: number) { return this.active < this.maxActive && this.bytes + bytes <= this.maxBytes; }
  private start(bytes: number): () => void {
    this.active++; this.bytes += bytes;
    let released = false;
    return () => {
      if (released) return;
      released = true; this.active--; this.bytes -= bytes;
      this.drain();
    };
  }
  private drain() {
    while (this.waiting.length && this.canStart(this.waiting[0]!.bytes)) {
      const entry = this.waiting.shift()!;
      if (entry.cancel) entry.signal?.removeEventListener('abort', entry.cancel);
      if (entry.signal?.aborted) { entry.reject(entry.signal.reason); continue; }
      entry.resolve(this.start(entry.bytes));
    }
  }
}

// Includes transient plaintext/ciphertext copies; large files reserve more
// than one slot's byte share. The queue itself is also bounded.
export const attachmentResources = new AttachmentResourceBudget(2, 48 * 1024 * 1024, 8);
