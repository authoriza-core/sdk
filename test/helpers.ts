import { webcrypto } from 'node:crypto';
import { vi } from 'vitest';
import type { AuthState, Authoriza, Session } from '../src/index.js';

export const ISSUER = 'https://oidc.example.com/oidc';
export const CLIENT_ID = 'test-client';
export const REDIRECT_URI = 'https://app.example.com/auth/callback';
export const APP_URL = 'https://app.example.com/';

export interface MockResponse {
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
}

export function httpResponse(body: unknown, status = 200): MockResponse {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

export function discoveryBody(issuer: string = ISSUER): Record<string, unknown> {
  return {
    issuer,
    authorization_endpoint: `${issuer}/auth`,
    token_endpoint: `${issuer}/token`,
    jwks_uri: `${issuer}/jwks`,
    userinfo_endpoint: `${issuer}/me`,
  };
}

export function tokenResponse(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    access_token: 'access-token',
    token_type: 'Bearer',
    expires_in: 3600,
    refresh_token: 'refresh-token',
    id_token: 'id-token',
    ...overrides,
  };
}

/**
 * Registers a fetch mock with a router. `route(input)` may return a
 * `MockResponse`, `undefined` (→ 404), `null` (→ reject with a network error)
 * or a promise of any of these.
 */
export function stubFetch(
  router: (
    input: string,
    init?: RequestInit,
  ) => MockResponse | null | undefined | Promise<MockResponse | null | undefined>,
): ReturnType<typeof vi.fn> {
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url =
      typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    const result = router(url, init);
    if (result === null) {
      throw new TypeError('fetch failed');
    }
    return result ?? httpResponse({ error: 'not_found' }, 404);
  });
  vi.stubGlobal('fetch', fn);
  return fn;
}

/** Waits for the async init (session restore) of a client to finish. */
export async function waitForInit(auth: Authoriza): Promise<void> {
  await vi.waitFor(() => {
    if (!auth.isLoading) {
      return;
    }
    throw new Error('still loading');
  });
}

/** Collects `authStateChanged` snapshots emitted by a client. */
export function collectStates(auth: Authoriza): AuthState[] {
  const states: AuthState[] = [];
  auth.onAuthStateChanged((state) => states.push(state));
  return states;
}

export function makeSession(overrides: Partial<Session> = {}): Session {
  return {
    accessToken: 'access-token',
    refreshToken: 'refresh-token',
    expiresAt: Date.now() + 3600_000,
    user: { id: 'user-1', email: 'user@example.com', name: 'User One' },
    ...overrides,
  };
}

export function sessionKey(clientId: string = CLIENT_ID): string {
  return `authoriza:session:${clientId}`;
}

export function flowKey(clientId: string = CLIENT_ID): string {
  return `authoriza:authflow:${clientId}`;
}

/** Returns the last URL passed to `window.location.assign`, if any. */
export function lastNavigation(): string | null {
  const calls = vi.mocked(window.location.assign).mock.calls;
  if (calls.length === 0) {
    return null;
  }
  return calls[calls.length - 1]![0].toString();
}

export function navigationCount(): number {
  return vi.mocked(window.location.assign).mock.calls.length;
}

export function seedSession(session: Session, clientId: string = CLIENT_ID): void {
  window.localStorage.setItem(sessionKey(clientId), JSON.stringify({ version: 1, ...session }));
}

export { webcrypto };
