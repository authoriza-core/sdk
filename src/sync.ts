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
  private readonly sessionKey: string;
  private readonly onChange: () => void;
  private channel: BroadcastChannel | null = null;
  private storageHandler: ((event: StorageEvent) => void) | null = null;

  constructor(clientId: string, onChange: () => void) {
    this.channelName = `${SESSION_KEY_PREFIX}${clientId}`;
    this.sessionKey = `${SESSION_KEY_PREFIX}${clientId}`;
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
          (event.data as { type?: string }).type === 'session-changed'
        ) {
          this.onChange();
        }
      };
    } else {
      this.storageHandler = (event: StorageEvent) => {
        if (event.key === this.sessionKey) {
          this.onChange();
        }
      };
      window.addEventListener('storage', this.storageHandler);
    }
  }

  post(): void {
    this.channel?.postMessage({ type: 'session-changed' });
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
