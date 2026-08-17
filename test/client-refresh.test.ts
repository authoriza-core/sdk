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
import { generateRsaKeyPair, makeIdToken } from './jwt-helper.js';

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

  it('throws USER_NOT_AUTHENTICATED when the user is not authenticated', async () => {
    stubFetch(() => httpResponse(discoveryBody()));
    const auth = makeAuth();
    await waitForInit(auth);
    await expect(auth.getAccessToken()).rejects.toMatchObject({
      code: 'USER_NOT_AUTHENTICATED',
    });
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

  it('clears the session and throws TOKEN_REFRESH_FAILED when the refresh token is rejected', async () => {
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

    await expect(auth.getAccessToken()).rejects.toMatchObject({
      code: 'TOKEN_REFRESH_FAILED',
      details: { oauthError: 'invalid_grant', oauthErrorDescription: 'expired' },
      cause: expect.objectContaining({
        name: 'OAuthServerError',
        oauthError: 'invalid_grant',
        oauthErrorDescription: 'expired',
      }),
    });
    expect(auth.isAuthenticated).toBe(false);
    expect(auth.user).toBeNull();
    expect(window.localStorage.getItem(sessionKey())).toBeNull();
    // The authenticated → unauthenticated transition was published.
    expect(states.some((s) => !s.isAuthenticated && !s.isLoading)).toBe(true);
  });

  it('propagates the same controlled refresh rejection to concurrent callers', async () => {
    const tokenRequests: string[] = [];
    stubFetch((url) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      if (url.endsWith('/token')) {
        tokenRequests.push(url);
        return httpResponse({ error: 'invalid_token', error_description: 'revoked' }, 400);
      }
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

    expect(tokenRequests).toHaveLength(1);
    const reasons = results.map((result) => {
      expect(result.status).toBe('rejected');
      return result.status === 'rejected' ? result.reason : undefined;
    });
    expect(reasons[0]).toBe(reasons[1]);
    expect(reasons[1]).toBe(reasons[2]);
    expect(reasons[0]).toMatchObject({
      code: 'TOKEN_REFRESH_FAILED',
      details: { oauthError: 'invalid_token', oauthErrorDescription: 'revoked' },
      cause: expect.objectContaining({
        name: 'OAuthServerError',
        oauthError: 'invalid_token',
        oauthErrorDescription: 'revoked',
      }),
    });
    expect(auth.isAuthenticated).toBe(false);
    expect(window.localStorage.getItem(sessionKey())).toBeNull();
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

    await expect(pending).rejects.toMatchObject({ code: 'USER_NOT_AUTHENTICATED' });
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

  it('updates the user from the id_token returned during refresh', async () => {
    const keyPair = await generateRsaKeyPair();
    stubFetch(async (url) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      if (url.endsWith('/jwks')) return httpResponse({ keys: [keyPair.jwk] });
      if (url.endsWith('/token')) {
        const idToken = await makeIdToken(keyPair, {
          payload: { sub: 'user-2', email: 'new@example.com', name: 'New User' },
        });
        return httpResponse({
          access_token: 'new-access',
          token_type: 'Bearer',
          expires_in: 3600,
          refresh_token: 'new-refresh',
          id_token: idToken,
        });
      }
      return undefined;
    });
    seedSession(
      makeSession({
        accessToken: 'old',
        refreshToken: 'rt',
        expiresAt: Date.now() - 1,
        user: { id: 'user-1', email: 'old@example.com', name: 'Old User' },
      }),
    );
    const auth = makeAuth();
    await waitForInit(auth);

    await auth.getAccessToken();

    expect(auth.user).toEqual({ id: 'user-2', email: 'new@example.com', name: 'New User' });
    const stored = JSON.parse(window.localStorage.getItem(sessionKey())!);
    expect(stored.user).toEqual({ id: 'user-2', email: 'new@example.com', name: 'New User' });
  });

  it('keeps the previous user when the refresh response does not include an id_token', async () => {
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
        refreshToken: 'rt',
        expiresAt: Date.now() - 1,
        user: { id: 'user-1', email: 'old@example.com', name: 'Old User' },
      }),
    );
    const auth = makeAuth();
    await waitForInit(auth);

    await auth.getAccessToken();

    expect(auth.user).toEqual({ id: 'user-1', email: 'old@example.com', name: 'Old User' });
  });

  it('throws TOKEN_REFRESH_FAILED when the refresh response contains an invalid id_token', async () => {
    const onError = vi.fn();
    stubFetch((url) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      if (url.endsWith('/token')) {
        return httpResponse({
          access_token: 'new-access',
          token_type: 'Bearer',
          expires_in: 3600,
          refresh_token: 'new-refresh',
          id_token: 'invalid-token',
        });
      }
      return undefined;
    });
    seedSession(makeSession({ accessToken: 'old', refreshToken: 'rt', expiresAt: Date.now() - 1 }));
    const auth = makeAuth(onError);
    await waitForInit(auth);

    await expect(auth.getAccessToken()).rejects.toMatchObject({ code: 'TOKEN_REFRESH_FAILED' });
    expect(auth.isAuthenticated).toBe(true);
  });
});
