import { webcrypto } from 'node:crypto';
import { afterEach, vi } from 'vitest';

// WebCrypto (used for PKCE and JWT verification) is not part of jsdom.
Object.defineProperty(globalThis, 'crypto', { configurable: true, value: webcrypto });

type MessageHandler = (event: { data: unknown; type: string }) => void;

/**
 * Minimal in-memory BroadcastChannel implementation used to test cross-tab
 * synchronization without a real browser.
 */
class MockBroadcastChannel {
  static registry = new Map<string, Set<MockBroadcastChannel>>();

  readonly name: string;
  onmessage: MessageHandler | null = null;

  constructor(name: string) {
    this.name = name;
    if (!MockBroadcastChannel.registry.has(name)) {
      MockBroadcastChannel.registry.set(name, new Set());
    }
    MockBroadcastChannel.registry.get(name)!.add(this);
  }

  postMessage(data: unknown): void {
    const set = MockBroadcastChannel.registry.get(this.name);
    if (!set) {
      return;
    }
    for (const channel of set) {
      if (channel !== this) {
        channel.onmessage?.({ data, type: 'message' });
      }
    }
  }

  close(): void {
    MockBroadcastChannel.registry.get(this.name)?.delete(this);
  }

  static reset(): void {
    MockBroadcastChannel.registry.clear();
  }
}

Object.defineProperty(globalThis, 'BroadcastChannel', {
  configurable: true,
  value: MockBroadcastChannel,
});

// jsdom does not implement navigation. Replace `location` with a fake object
// whose read-only getters delegate to the real jsdom location (so
// `history.pushState`/`replaceState` still update the URL) while `assign`/
// `replace` are stubbed for assertions.
const realLocation = window.location;
const locationAssignMock = vi.fn();
const locationReplaceMock = vi.fn();

const fakeLocation: Record<string, unknown> = {};
for (const key of [
  'href',
  'origin',
  'protocol',
  'host',
  'hostname',
  'port',
  'pathname',
  'search',
  'hash',
] as const) {
  Object.defineProperty(fakeLocation, key, {
    configurable: true,
    get: () => realLocation[key],
  });
}
Object.defineProperty(fakeLocation, 'assign', {
  configurable: true,
  writable: true,
  value: locationAssignMock,
});
Object.defineProperty(fakeLocation, 'replace', {
  configurable: true,
  writable: true,
  value: locationReplaceMock,
});
Object.defineProperty(fakeLocation, 'reload', {
  configurable: true,
  writable: true,
  value: () => {},
});
Object.defineProperty(fakeLocation, 'toString', {
  configurable: true,
  writable: true,
  value: () => realLocation.href,
});
Object.defineProperty(window, 'location', {
  configurable: true,
  value: fakeLocation as unknown as Location,
});

afterEach(() => {
  MockBroadcastChannel.reset();
  window.localStorage.clear();
  window.sessionStorage.clear();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  window.history.replaceState({}, '', '/');
});
