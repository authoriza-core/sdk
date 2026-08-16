import { describe, expect, it, vi } from 'vitest';
import { createAuthoriza } from '../src/index.js';
import {
  CLIENT_ID,
  ISSUER,
  REDIRECT_URI,
  collectStates,
  discoveryBody,
  httpResponse,
  makeSession,
  seedSession,
  sessionKey,
  stubFetch,
  waitForInit,
} from './helpers.js';

function makeAuth(onError?: (e: unknown) => void) {
  return createAuthoriza({
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    issuer: ISSUER,
    onError: onError as never,
  });
}

describe('getAccessToken', () => {
  it('returns the valid token without any network request', async () => {
    const fetch = stubFetch(() => httpResponse(discoveryBody()));
    seedSession(makeSession({ expiresAt: Date.now() + 3600_000 }));
    const auth = makeAuth();
    await waitForInit(auth);

    const token = await auth.getAccessToken();
    expect(token).toBe('access-token');
    expect(fetch).not.toHaveBeenCalled();
  });

  it('returns null when the user is not authenticated', async () => {
    stubFetch(() => httpResponse(discoveryBody()));
    const auth = makeAuth();
    await waitForInit(auth);
    await expect(auth.getAccessToken()).resolves.toBeNull();
  });

  it('refreshes an expired access token and persists the new tokens', async () => {
    stubFetch((url, init) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      if (url.endsWith('/token')) {
        const body = new URLSearchParams(init?.body as string);
        expect(body.get('grant_type')).toBe('refresh_token');
        expect(body.get('refresh_token')).toBe('old-refresh');
        expect(body.get('client_id')).toBe(CLIENT_ID);
        expect(body.get('client_secret')).toBeNull();
        return httpResponse({
          access_token: 'new-access',
          token_type: 'Bearer',
          expires_in: 3600,
          refresh_token: 'new-refresh',
        });
      }
      return undefined;
    });
    seedSession(
      makeSession({
        accessToken: 'old-access',
        refreshToken: 'old-refresh',
        expiresAt: Date.now() - 1000,
      }),
    );
    const auth = makeAuth();
    await waitForInit(auth);

    const token = await auth.getAccessToken();
    expect(token).toBe('new-access');
    expect(auth.isAuthenticated).toBe(true);

    const stored = JSON.parse(window.localStorage.getItem(sessionKey())!);
    expect(stored.accessToken).toBe('new-access');
    expect(stored.refreshToken).toBe('new-refresh'); // rotation applied
    expect(stored.expiresAt).toBeGreaterThan(Date.now());
  });

  it('keeps the previous refresh token when the server does not rotate it', async () => {
    stubFetch((url) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      if (url.endsWith('/token')) {
        return httpResponse({ access_token: 'new-access', token_type: 'Bearer', expires_in: 3600 });
      }
      return undefined;
    });
    seedSession(
      makeSession({
        accessToken: 'old',
        refreshToken: 'stable-refresh',
        expiresAt: Date.now() - 1,
      }),
    );
    const auth = makeAuth();
    await waitForInit(auth);

    await auth.getAccessToken();
    const stored = JSON.parse(window.localStorage.getItem(sessionKey())!);
    expect(stored.refreshToken).toBe('stable-refresh');
  });

  it('runs a single refresh request for concurrent callers', async () => {
    const tokenRequests: string[] = [];
    stubFetch((url) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      if (url.endsWith('/token')) {
        tokenRequests.push(url);
        return httpResponse({ access_token: 'new-access', token_type: 'Bearer', expires_in: 3600 });
      }
      return undefined;
    });
    seedSession(makeSession({ accessToken: 'old', refreshToken: 'rt', expiresAt: Date.now() - 1 }));
    const auth = makeAuth();
    await waitForInit(auth);

    const results = await Promise.all([
      auth.getAccessToken(),
      auth.getAccessToken(),
      auth.getAccessToken(),
    ]);
    expect(tokenRequests).toHaveLength(1);
    expect(results).toEqual(['new-access', 'new-access', 'new-access']);
  });

  it('clears the session and returns null when the refresh token is rejected', async () => {
    const onError = vi.fn();
    stubFetch((url) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      if (url.endsWith('/token'))
        return httpResponse({ error: 'invalid_grant', error_description: 'expired' }, 400);
      return undefined;
    });
    seedSession(
      makeSession({ accessToken: 'old', refreshToken: 'dead-refresh', expiresAt: Date.now() - 1 }),
    );
    const auth = makeAuth(onError);
    await waitForInit(auth);

    const states = collectStates(auth);
    const token = await auth.getAccessToken();

    expect(token).toBeNull();
    expect(auth.isAuthenticated).toBe(false);
    expect(auth.user).toBeNull();
    expect(window.localStorage.getItem(sessionKey())).toBeNull();
    // The authenticated → unauthenticated transition was published.
    expect(states.some((s) => !s.isAuthenticated && !s.isLoading)).toBe(true);
  });

  it('keeps the session on a technical refresh failure and throws TOKEN_REFRESH_FAILED', async () => {
    stubFetch((url) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      if (url.endsWith('/token')) return null; // network failure
      return undefined;
    });
    seedSession(makeSession({ accessToken: 'old', refreshToken: 'rt', expiresAt: Date.now() - 1 }));
    const auth = makeAuth();
    await waitForInit(auth);

    await expect(auth.getAccessToken()).rejects.toMatchObject({ code: 'TOKEN_REFRESH_FAILED' });
    expect(auth.isAuthenticated).toBe(true);
    expect(window.localStorage.getItem(sessionKey())).not.toBeNull();
  });

  it('propagates the same refresh error to all concurrent callers', async () => {
    stubFetch((url) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      if (url.endsWith('/token')) return null;
      return undefined;
    });
    seedSession(makeSession({ accessToken: 'old', refreshToken: 'rt', expiresAt: Date.now() - 1 }));
    const auth = makeAuth();
    await waitForInit(auth);

    const results = await Promise.allSettled([
      auth.getAccessToken(),
      auth.getAccessToken(),
      auth.getAccessToken(),
    ]);
    for (const result of results) {
      expect(result.status).toBe('rejected');
      if (result.status === 'rejected') {
        expect((result.reason as { code: string }).code).toBe('TOKEN_REFRESH_FAILED');
      }
    }
  });

  it('does not write back refreshed tokens when logout happens concurrently', async () => {
    let resolveGate!: () => void;
    const gate = new Promise<void>((resolve) => {
      resolveGate = resolve;
    });
    stubFetch((url) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      if (url.endsWith('/token')) {
        return gate.then(() =>
          httpResponse({ access_token: 'new-access', token_type: 'Bearer', expires_in: 3600 }),
        );
      }
      return undefined;
    });
    seedSession(makeSession({ accessToken: 'old', refreshToken: 'rt', expiresAt: Date.now() - 1 }));
    const auth = makeAuth();
    await waitForInit(auth);

    const pending = auth.getAccessToken();
    await new Promise((r) => setTimeout(r, 0));
    await auth.logout();
    resolveGate();

    await expect(pending).resolves.toBeNull();
    expect(auth.isAuthenticated).toBe(false);
    expect(window.localStorage.getItem(sessionKey())).toBeNull();
  });

  it('does not emit authStateChanged for a successful silent refresh', async () => {
    stubFetch((url) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      if (url.endsWith('/token')) {
        return httpResponse({ access_token: 'new-access', token_type: 'Bearer', expires_in: 3600 });
      }
      return undefined;
    });
    seedSession(makeSession({ accessToken: 'old', refreshToken: 'rt', expiresAt: Date.now() - 1 }));
    const auth = makeAuth();
    await waitForInit(auth);

    const states = collectStates(auth);
    await auth.getAccessToken();
    expect(states).toHaveLength(0);
  });
});
