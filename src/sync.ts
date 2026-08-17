import { SESSION_KEY_PREFIX } from './storage/session.js';

/**
 * Cross-tab session synchronization.
 *
 * Priority mechanism is `BroadcastChannel`; the fallback is the `storage`
 * event of `localStorage`. Messages only carry a notification
 * ("session may have changed"); tokens are never transmitted, the receiving
 * instance always re-reads the session from `SessionStorage`.
 */
export class CrossTabSync {
  private readonly channelName: string;
  private readonly notificationKey: string;
  private readonly onChange: () => void;
  private channel: BroadcastChannel | null = null;
  private storageHandler: ((event: StorageEvent) => void) | null = null;

  constructor(clientId: string, onChange: () => void) {
    this.channelName = `${SESSION_KEY_PREFIX}${clientId}`;
    this.notificationKey = `authoriza:sync:${clientId}`;
    this.onChange = onChange;
  }

  start(): void {
    if (typeof window === 'undefined') {
      return;
    }
    if (typeof BroadcastChannel !== 'undefined') {
      this.channel = new BroadcastChannel(this.channelName);
      this.channel.onmessage = (event: MessageEvent) => {
        if (
          event.data &&
          typeof event.data === 'object' &&
          'type' in event.data &&
          event.data.type === 'session-changed'
        ) {
          this.onChange();
        }
      };
    } else {
      this.storageHandler = (event: StorageEvent) => {
        if (event.key === this.notificationKey) {
          this.onChange();
        }
      };
      window.addEventListener('storage', this.storageHandler);
    }
  }

  post(): void {
    if (this.channel) {
      this.channel.postMessage({ type: 'session-changed' });
      return;
    }

    if (typeof window === 'undefined' || typeof window.localStorage === 'undefined') {
      return;
    }

    try {
      window.localStorage.setItem(
        this.notificationKey,
        `${Date.now()}:${Math.random().toString(36).slice(2)}`,
      );
    } catch {
      // Best effort: cross-tab notification must not break session operations.
    }
  }

  dispose(): void {
    this.channel?.close();
    this.channel = null;
    if (this.storageHandler) {
      window.removeEventListener('storage', this.storageHandler);
      this.storageHandler = null;
    }
  }
}
