export type LocalInvalidation =
  | { type: 'session.changed'; session_id: string; state_version: number }
  | { type: 'outbox.changed'; client_message_id: string; status: string };

const CHANNEL_NAME = 'ratchet-local-state-v1';

export class LocalInvalidationBus {
  private readonly channel = typeof BroadcastChannel === 'undefined' ? null : new BroadcastChannel(CHANNEL_NAME);

  publish(event: LocalInvalidation): void {
    this.channel?.postMessage(event);
  }

  subscribe(listener: (event: LocalInvalidation) => void): () => void {
    if (!this.channel) return () => undefined;
    const handler = (event: MessageEvent<unknown>) => {
      if (!event.data || typeof event.data !== 'object') return;
      listener(event.data as LocalInvalidation);
    };
    this.channel.addEventListener('message', handler);
    return () => this.channel?.removeEventListener('message', handler);
  }

  close(): void {
    this.channel?.close();
  }
}
