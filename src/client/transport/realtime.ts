import type { SendMessageRequest } from '../../shared/contracts/messages';
import {
  RealtimeServerEventSchema,
  type RealtimeCommittedMessage,
  type RealtimeMessageAck,
  type RealtimeServerEvent,
} from '../../shared/contracts/realtime';

export type ConnectivityState = 'REALTIME' | 'HTTP_SYNC' | 'OFFLINE';

type RealtimeOptions = {
  chatId: string;
  initialRevision: number;
  syncHttp: (afterRevision: number) => Promise<number>;
  onState: (state: ConnectivityState) => void;
  onEvent?: (event: RealtimeServerEvent) => void;
  onReceipt?: (event: Extract<RealtimeServerEvent, { type: 'receipt.committed' }>) => Promise<void>;
  onCommittedMessage?: (event: RealtimeCommittedMessage) => Promise<void>;
  onContiguousOwnCommit?: (ack: RealtimeMessageAck) => Promise<void>;
};

type PendingAck = {
  promise: Promise<RealtimeMessageAck>;
  resolve: (ack: RealtimeMessageAck) => void;
  reject: (error: Error) => void;
};

type PreconnectedRealtimeSocket = {
  chatId: string;
  socket: WebSocket;
  events: RealtimeServerEvent[];
  timer: number | null;
  onMessage: (event: MessageEvent) => void;
  onClose: () => void;
  onError: () => void;
};

type AdoptedRealtimeSocket = {
  socket: WebSocket;
  events: RealtimeServerEvent[];
};

// The application-level ping also performs authoritative reconciliation and
// drains recovery work in the Durable Object. Keep it infrequent so an idle
// chat remains hibernatable while still bounding rare lost-fanout recovery.
const HEARTBEAT_MS = 5 * 60_000;
const MAX_BACKOFF_MS = 30_000;
const HTTP_FALLBACK_POLL_MIN_MS = 1_500;
const HTTP_FALLBACK_POLL_MAX_MS = 30_000;
const PRECONNECT_TTL_MS = 15_000;
const PRECONNECT_MAX_EVENTS = 256;
let preconnectedRealtime: PreconnectedRealtimeSocket | null = null;

/**
 * Start the authenticated WebSocket handshake while local cache/crypto warm-up
 * continues. No event is trusted as durable authority here; the socket is only
 * buffered until ChatRealtimeClient adopts it after the normal HTTP sync.
 */
export function preconnectRealtimeSocket(chatId: string): void {
  if (typeof window === 'undefined' || typeof WebSocket === 'undefined' || typeof navigator === 'undefined' || !navigator.onLine) return;
  const existing = preconnectedRealtime;
  if (existing?.chatId === chatId
    && (existing.socket.readyState === WebSocket.CONNECTING || existing.socket.readyState === WebSocket.OPEN)) return;
  if (existing) releasePreconnectedRealtime(existing, true);

  const socket = new WebSocket(realtimeUrl(chatId, 0));
  let entry!: PreconnectedRealtimeSocket;
  const onMessage = (event: MessageEvent) => {
    if (preconnectedRealtime !== entry || typeof event.data !== 'string') return;
    let value: unknown;
    try {
      value = JSON.parse(event.data);
    } catch {
      return;
    }
    const parsed = RealtimeServerEventSchema.safeParse(value);
    if (!parsed.success) return;
    if (entry.events.length >= PRECONNECT_MAX_EVENTS) {
      releasePreconnectedRealtime(entry, true);
      return;
    }
    entry.events.push(parsed.data);
  };
  const onClose = () => releasePreconnectedRealtime(entry, false);
  const onError = () => {
    try { socket.close(); } catch {}
  };
  entry = {
    chatId,
    socket,
    events: [],
    timer: null,
    onMessage,
    onClose,
    onError,
  };
  preconnectedRealtime = entry;
  socket.addEventListener('message', onMessage);
  socket.addEventListener('close', onClose);
  socket.addEventListener('error', onError);
  entry.timer = window.setTimeout(() => releasePreconnectedRealtime(entry, true), PRECONNECT_TTL_MS);
}

function takePreconnectedRealtimeSocket(chatId: string): AdoptedRealtimeSocket | null {
  const entry = preconnectedRealtime;
  if (!entry || entry.chatId !== chatId) return null;
  if (entry.socket.readyState !== WebSocket.CONNECTING && entry.socket.readyState !== WebSocket.OPEN) {
    releasePreconnectedRealtime(entry, false);
    return null;
  }
  const events = [...entry.events];
  releasePreconnectedRealtime(entry, false);
  return { socket: entry.socket, events };
}

function releasePreconnectedRealtime(entry: PreconnectedRealtimeSocket, closeSocket: boolean): void {
  if (entry.timer !== null && typeof window !== 'undefined') window.clearTimeout(entry.timer);
  entry.timer = null;
  entry.socket.removeEventListener('message', entry.onMessage);
  entry.socket.removeEventListener('close', entry.onClose);
  entry.socket.removeEventListener('error', entry.onError);
  if (preconnectedRealtime === entry) preconnectedRealtime = null;
  if (closeSocket && (entry.socket.readyState === WebSocket.CONNECTING || entry.socket.readyState === WebSocket.OPEN)) {
    try { entry.socket.close(1000, 'preconnect released'); } catch {}
  }
}

function realtimeUrl(chatId: string, afterRevision: number): URL {
  const url = new URL(`/api/v1/chats/${chatId}/realtime`, window.location.origin);
  url.protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  url.searchParams.set('after_revision', String(afterRevision));
  return url;
}

export class RealtimeUnavailableError extends Error {
  constructor(message = 'Realtime socket is unavailable') {
    super(message);
    this.name = 'RealtimeUnavailableError';
  }
}

export class RealtimeMessageRejectedError extends Error {
  constructor(
    readonly errorType: string,
    readonly retryable: boolean,
  ) {
    super(`Realtime message rejected: ${errorType}`);
    this.name = 'RealtimeMessageRejectedError';
  }
}

export class ChatRealtimeClient {
  private socket: WebSocket | null = null;
  private appliedRevision: number;
  private reconnectAttempt = 0;
  private reconnectTimer: number | null = null;
  private heartbeatTimer: number | null = null;
  private resyncTimer: number | null = null;
  private fallbackPollTimer: number | null = null;
  private fallbackPollDelayMs = HTTP_FALLBACK_POLL_MIN_MS;
  private stopped = false;
  private readyForMessages = false;
  private serverReadyRevision: number | null = null;
  private readonly syncingBySocket = new WeakMap<WebSocket, Promise<void>>();
  private requestedRevision: number;
  private readonly pendingAcks = new Map<string, PendingAck>();
  private readonly committedBuffer = new Map<number, RealtimeCommittedMessage | RealtimeMessageAck | Extract<RealtimeServerEvent, { type: 'receipt.committed' }>>();
  private committedDrain: Promise<void> | null = null;

  constructor(private readonly options: RealtimeOptions) {
    this.appliedRevision = options.initialRevision;
    this.requestedRevision = options.initialRevision;
  }

  start(): void {
    this.stopped = false;
    if (!navigator.onLine) {
      this.options.onState('OFFLINE');
      return;
    }
    this.startFallbackPolling();
    this.connect();
  }

  stop(): void {
    this.stopped = true;
    this.readyForMessages = false;
    this.serverReadyRevision = null;
    this.clearTimers();
    this.rejectPendingAcks(new RealtimeUnavailableError('Realtime client stopped'));
    this.socket?.close(1000, 'client stop');
    this.socket = null;
  }

  notifyOnline(): void {
    if (this.stopped) return;
    this.options.onState('HTTP_SYNC');
    this.stopFallbackPolling();
    this.startFallbackPolling();
    this.connect();
  }

  notifyOffline(): void {
    if (this.stopped) return;
    this.readyForMessages = false;
    this.serverReadyRevision = null;
    this.clearTimers();
    this.rejectPendingAcks(new RealtimeUnavailableError('Network went offline'));
    this.socket?.close();
    this.socket = null;
    this.options.onState('OFFLINE');
  }

  get revision(): number {
    return this.appliedRevision;
  }

  get canSendMessages(): boolean {
    return this.readyForMessages && this.socket?.readyState === WebSocket.OPEN;
  }

  sendMessage(request: SendMessageRequest): Promise<RealtimeMessageAck> {
    if (request.sender_sequence === undefined) {
      return Promise.reject(new RealtimeMessageRejectedError('SENDER_SEQUENCE_REQUIRED', false));
    }
    const socket = this.socket;
    if (!this.readyForMessages || !socket || socket.readyState !== WebSocket.OPEN) {
      return Promise.reject(new RealtimeUnavailableError());
    }
    const existing = this.pendingAcks.get(request.client_message_id);
    if (existing) return existing.promise;

    let resolve!: (ack: RealtimeMessageAck) => void;
    let reject!: (error: Error) => void;
    const promise = new Promise<RealtimeMessageAck>((resolvePromise, rejectPromise) => {
      resolve = resolvePromise;
      reject = rejectPromise;
    });
    this.pendingAcks.set(request.client_message_id, { promise, resolve, reject });
    try {
      socket.send(JSON.stringify({ type: 'message.send', request }));
    } catch (error) {
      this.pendingAcks.delete(request.client_message_id);
      reject(error instanceof Error ? error : new RealtimeUnavailableError());
    }
    return promise;
  }

  private connect(): void {
    if (this.stopped || this.socket?.readyState === WebSocket.OPEN || this.socket?.readyState === WebSocket.CONNECTING) return;
    this.options.onState('HTTP_SYNC');
    this.readyForMessages = false;
    this.serverReadyRevision = null;

    const adopted = takePreconnectedRealtimeSocket(this.options.chatId);
    const socket = adopted?.socket ?? new WebSocket(realtimeUrl(this.options.chatId, this.appliedRevision));
    this.socket = socket;

    socket.addEventListener('open', () => {
      this.reconnectAttempt = 0;
    });
    socket.addEventListener('message', (event) => {
      if (this.socket !== socket || typeof event.data !== 'string') return;
      let value: unknown;
      try {
        value = JSON.parse(event.data);
      } catch {
        return;
      }
      const parsed = RealtimeServerEventSchema.safeParse(value);
      if (!parsed.success) return;
      this.handleServerEvent(socket, parsed.data);
    });
    socket.addEventListener('close', () => {
      if (this.socket === socket) {
        this.socket = null;
        this.readyForMessages = false;
        this.serverReadyRevision = null;
        this.stopHeartbeat();
        this.clearResyncTimer();
        this.rejectPendingAcks(new RealtimeUnavailableError('Realtime socket closed before ACK'));
      }
      if (!this.stopped) {
        this.stopFallbackPolling();
        this.startFallbackPolling();
        this.scheduleReconnect();
      }
    });
    socket.addEventListener('error', () => {
      socket.close();
    });

    if (socket.readyState === WebSocket.OPEN) this.reconnectAttempt = 0;
    for (const event of adopted?.events ?? []) {
      if (this.socket !== socket) break;
      this.handleServerEvent(socket, event);
    }
  }

  private handleServerEvent(socket: WebSocket, event: RealtimeServerEvent): void {
    if (event.chat_id !== this.options.chatId) return;
    if (event.type === 'realtime.ready') {
      this.options.onEvent?.(event);
      this.serverReadyRevision = event.revision;
      this.requestedRevision = Math.max(this.requestedRevision, event.revision);
      if (event.revision > this.appliedRevision) void this.ensureHttpSync(socket);
      else this.tryEnterRealtime(socket);
      return;
    }
    if (event.type === 'message.ack') {
      const pending = this.pendingAcks.get(event.client_message_id);
      if (pending) {
        this.pendingAcks.delete(event.client_message_id);
        pending.resolve(event);
      }
      this.options.onEvent?.(event);
      this.enqueueCommittedMessage(socket, event);
      return;
    }
    if (event.type === 'message.nack') {
      const pending = this.pendingAcks.get(event.client_message_id);
      if (pending) {
        this.pendingAcks.delete(event.client_message_id);
        pending.reject(new RealtimeMessageRejectedError(event.error_type, event.retryable));
      }
      this.options.onEvent?.(event);
      return;
    }
    if (event.type === 'message.committed' || event.type === 'receipt.committed') {
      this.options.onEvent?.(event);
      this.enqueueCommittedMessage(socket, event);
      return;
    }

    this.options.onEvent?.(event);
    if (event.type === 'chat.changed' || event.type === 'sync.required' || event.type === 'pong') {
      this.requestedRevision = Math.max(this.requestedRevision, event.revision);
      if (event.revision > this.appliedRevision) void this.ensureHttpSync(socket);
    }
  }

  private tryEnterRealtime(socket: WebSocket): void {
    if (this.stopped || this.socket !== socket || socket.readyState !== WebSocket.OPEN) return;
    if (this.serverReadyRevision === null || this.appliedRevision < this.serverReadyRevision) return;
    if (!this.readyForMessages) {
      this.readyForMessages = true;
      this.stopFallbackPolling();
      this.startHeartbeat(socket);
    }
    this.options.onState('REALTIME');
  }

  private enqueueCommittedMessage(socket: WebSocket, event: RealtimeCommittedMessage | RealtimeMessageAck | Extract<RealtimeServerEvent, { type: 'receipt.committed' }>): void {
    if (event.revision <= this.appliedRevision) return;
    this.requestedRevision = Math.max(this.requestedRevision, event.revision);
    this.committedBuffer.set(event.revision, event);
    if (this.committedDrain) return;
    const drain = this.drainCommittedMessages(socket).finally(() => {
      if (this.committedDrain === drain) this.committedDrain = null;
      if (this.socket === socket && this.hasPendingCommittedWork()) this.enqueueCommittedDrain(socket);
    });
    this.committedDrain = drain;
  }

  private enqueueCommittedDrain(socket: WebSocket): void {
    if (this.committedDrain || this.stopped || this.socket !== socket) return;
    const drain = this.drainCommittedMessages(socket).finally(() => {
      if (this.committedDrain === drain) this.committedDrain = null;
    });
    this.committedDrain = drain;
  }

  private async drainCommittedMessages(socket: WebSocket): Promise<void> {
    while (!this.stopped && this.socket === socket && socket.readyState === WebSocket.OPEN) {
      for (const revision of this.committedBuffer.keys()) {
        if (revision <= this.appliedRevision) this.committedBuffer.delete(revision);
      }

      const nextRevision = this.appliedRevision + 1;
      const next = this.committedBuffer.get(nextRevision);
      if (next) {
        try {
          if (next.type === 'message.ack') { if (this.options.onContiguousOwnCommit) await this.options.onContiguousOwnCommit(next); }
          else if (next.type === 'receipt.committed' && this.options.onReceipt) await this.options.onReceipt(next);
          else if (next.type === 'message.committed' && this.options.onCommittedMessage) await this.options.onCommittedMessage(next);
          else throw new Error('Realtime committed-message handler is unavailable');
          this.appliedRevision = next.revision;
          this.committedBuffer.delete(next.revision);
          continue;
        } catch {
          this.requestedRevision = Math.max(this.requestedRevision, next.revision);
        }
      }

      if (this.requestedRevision > this.appliedRevision) {
        const before = this.appliedRevision;
        await this.ensureHttpSync(socket);
        for (const revision of this.committedBuffer.keys()) {
          if (revision <= this.appliedRevision) this.committedBuffer.delete(revision);
        }
        if (this.appliedRevision <= before) break;
        continue;
      }
      break;
    }
  }

  private hasPendingCommittedWork(): boolean {
    for (const revision of this.committedBuffer.keys()) {
      if (revision > this.appliedRevision) return true;
    }
    return false;
  }

  private ensureHttpSync(socket: WebSocket, force = false): Promise<void> {
    const existing = this.syncingBySocket.get(socket);
    if (existing) return existing;
    this.options.onState('HTTP_SYNC');
    const task = (async () => {
      try {
        let mustSync = force;
        while (mustSync || this.requestedRevision > this.appliedRevision) {
          mustSync = false;
          const before = this.appliedRevision;
          const requested = this.requestedRevision;
          const nextRevision = await this.options.syncHttp(before);
          this.appliedRevision = Math.max(this.appliedRevision, nextRevision);
          if (this.appliedRevision < requested && this.appliedRevision <= before) {
            this.scheduleResync(socket);
            break;
          }
        }
        if (this.socket === socket && socket.readyState === WebSocket.OPEN) {
          socket.send(JSON.stringify({ type: 'ping', after_revision: this.appliedRevision }));
          this.tryEnterRealtime(socket);
        }
      } catch {
        if (!navigator.onLine) this.options.onState('OFFLINE');
        else if (this.socket === socket) {
          this.options.onState('HTTP_SYNC');
          this.scheduleResync(socket);
        }
      } finally {
        this.syncingBySocket.delete(socket);
        if (this.socket === socket && this.requestedRevision > this.appliedRevision) this.scheduleResync(socket);
      }
    })();
    this.syncingBySocket.set(socket, task);
    return task;
  }

  private scheduleResync(socket: WebSocket): void {
    if (this.stopped || this.socket !== socket || socket.readyState !== WebSocket.OPEN || this.resyncTimer !== null) return;
    this.resyncTimer = window.setTimeout(() => {
      this.resyncTimer = null;
      if (!this.stopped && this.socket === socket) void this.ensureHttpSync(socket);
    }, 150);
  }

  private startHeartbeat(socket: WebSocket): void {
    this.stopHeartbeat();
    this.heartbeatTimer = window.setInterval(() => {
      if (this.socket !== socket || socket.readyState !== WebSocket.OPEN) return;
      socket.send(JSON.stringify({ type: 'ping', after_revision: this.appliedRevision }));
    }, HEARTBEAT_MS);
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer !== null) window.clearInterval(this.heartbeatTimer);
    this.heartbeatTimer = null;
  }

  private startFallbackPolling(): void {
    if (this.stopped || !navigator.onLine || this.fallbackPollTimer !== null || this.readyForMessages) return;
    const run = async () => {
      this.fallbackPollTimer = null;
      if (this.stopped || !navigator.onLine || this.readyForMessages) return;
      const before = this.appliedRevision;
      try {
        const next = await this.options.syncHttp(before);
        this.appliedRevision = Math.max(this.appliedRevision, next);
        this.requestedRevision = Math.max(this.requestedRevision, this.appliedRevision);
        this.fallbackPollDelayMs = this.appliedRevision > before
          ? HTTP_FALLBACK_POLL_MIN_MS
          : Math.min(HTTP_FALLBACK_POLL_MAX_MS, this.fallbackPollDelayMs * 2);
        const socket = this.socket;
        if (socket?.readyState === WebSocket.OPEN) this.tryEnterRealtime(socket);
        if (!this.readyForMessages) this.options.onState('HTTP_SYNC');
      } catch {
        this.fallbackPollDelayMs = Math.min(HTTP_FALLBACK_POLL_MAX_MS, this.fallbackPollDelayMs * 2);
        if (!navigator.onLine) this.options.onState('OFFLINE');
      } finally {
        if (!this.stopped && navigator.onLine && !this.readyForMessages) {
          this.fallbackPollTimer = window.setTimeout(() => void run(), this.fallbackPollDelayMs);
        }
      }
    };
    this.fallbackPollTimer = window.setTimeout(() => void run(), this.fallbackPollDelayMs);
  }

  private stopFallbackPolling(): void {
    if (this.fallbackPollTimer !== null) window.clearTimeout(this.fallbackPollTimer);
    this.fallbackPollTimer = null;
    this.fallbackPollDelayMs = HTTP_FALLBACK_POLL_MIN_MS;
  }

  private clearResyncTimer(): void {
    if (this.resyncTimer !== null) window.clearTimeout(this.resyncTimer);
    this.resyncTimer = null;
  }

  private scheduleReconnect(): void {
    if (this.stopped) return;
    if (!navigator.onLine) {
      this.options.onState('OFFLINE');
      return;
    }
    this.options.onState('HTTP_SYNC');
    if (this.reconnectTimer !== null) return;
    const cap = Math.min(MAX_BACKOFF_MS, 1000 * 2 ** this.reconnectAttempt);
    const delay = Math.floor(Math.random() * Math.max(1, cap));
    this.reconnectAttempt += 1;
    this.reconnectTimer = window.setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delay);
  }

  private rejectPendingAcks(error: Error): void {
    for (const pending of this.pendingAcks.values()) pending.reject(error);
    this.pendingAcks.clear();
  }

  private clearTimers(): void {
    this.stopHeartbeat();
    this.stopFallbackPolling();
    this.clearResyncTimer();
    if (this.reconnectTimer !== null) window.clearTimeout(this.reconnectTimer);
    this.reconnectTimer = null;
  }
}
