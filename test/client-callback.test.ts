import { describe, expect, it, vi } from 'vitest';
import { createAuthoriza } from '../src/index.js';
import {
  CLIENT_ID,
  ISSUER,
  REDIRECT_URI,
  discoveryBody,
  flowKey,
  httpResponse,
  lastNavigation,
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

function seedFlow(state: string, overrides: Record<string, unknown> = {}) {
  window.sessionStorage.setItem(
    flowKey(),
    JSON.stringify({
      state,
      nonce: 'nonce-1',
      codeVerifier: 'code-verifier-1',
      redirectAfterLoginTo: '/dashboard',
      ...overrides,
    }),
  );
}

function navigateToCallback(params: Record<string, string>) {
  const qs = new URLSearchParams(params).toString();
  window.history.pushState({}, '', `/auth/callback?${qs}`);
}

describe('automatic callback handling', () => {
  it('completes a successful authorization code flow', async () => {
    const keyPair = await generateRsaKeyPair();
    const state = 'state-123';
    navigateToCallback({ code: 'code-1', state });
    seedFlow(state);

    const codeVerifier = 'code-verifier-1';
    const fetch = stubFetch(async (url, init) => {
      if (url.includes('.well-known/openid-configuration')) return httpResponse(discoveryBody());
      if (url.endsWith('/jwks')) return httpResponse({ keys: [keyPair.jwk] });
      if (url.endsWith('/token')) {
        const body = new URLSearchParams(init?.body as string);
        expect(body.get('grant_type')).toBe('authorization_code');
        expect(body.get('client_id')).toBe(CLIENT_ID);
        expect(body.get('code')).toBe('code-1');
        expect(body.get('redirect_uri')).toBe(REDIRECT_URI);
        expect(body.get('code_verifier')).toBe(codeVerifier);
        const idToken = await makeIdToken(keyPair, { payload: { nonce: 'nonce-1' } });
        return httpResponse({
          access_token: 'access-token',
          token_type: 'Bearer',
          expires_in: 3600,
          refresh_token: 'refresh-token',
          id_token: idToken,
        });
      }
      return undefined;
    });

    const auth = makeAuth();
    await waitForInit(auth);

    expect(auth.isAuthenticated).toBe(true);
    expect(auth.user).toEqual({ id: 'user-1', email: 'user@example.com', name: 'User One' });
    await expect(auth.getUser()).resolves.toEqual(auth.user);

    const stored = JSON.parse(window.localStorage.getItem(sessionKey())!);
    expect(stored.accessToken).toBe('access-token');
    expect(stored.refreshToken).toBe('refresh-token');
    expect(stored.expiresAt).toBeGreaterThan(Date.now());

    // Session persisted before redirect; flow data is cleared.
    expect(window.sessionStorage.getItem(flowKey())).toBeNull();
    // Callback parameters removed from the URL.
    expect(window.location.search).not.toContain('code=');
    expect(window.location.search).not.toContain('state=');
    // Application redirect performed after a successful login.
    expect(lastNavigation()).toBe('/dashboard');

    expect(fetch.mock.calls.map((c) => String(c[0]))).toContain(`${ISSUER}/jwks`);
  });

  it.each([
    'https://evil.example/callback',
    '//evil.example',
    '/javascript:alert(1)',
    '/dashboard\\evil',
  ])(
    'rejects a callback when the stored redirectAfterLoginTo is tampered with: %s',
    async (redirectAfterLoginTo) => {
      const onError = vi.fn();
      navigateToCallback({ code: 'code-1', state: 'state-123' });
      seedFlow('state-123', { redirectAfterLoginTo });
      stubFetch((url) => {
        if (url.includes('.well-known')) return httpResponse(discoveryBody());
        return undefined;
      });

      const auth = makeAuth(onError);
      await waitForInit(auth);

      expect(auth.isAuthenticated).toBe(false);
      expect(auth.user).toBeNull();
      expect(onError).toHaveBeenCalledTimes(1);
      expect(onError.mock.calls[0]![0].code).toBe('INVALID_REDIRECT_AFTER_LOGIN');
      expect(window.localStorage.getItem(sessionKey())).toBeNull();
      expect(window.sessionStorage.getItem(flowKey())).toBeNull();
      expect(lastNavigation()).toBeNull();
    },
  );

  it('rejects a callback with a mismatched state and does not create a session', async () => {
    const onError = vi.fn();
    navigateToCallback({ code: 'code-1', state: 'wrong-state' });
    seedFlow('state-123');
    stubFetch((url) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      return undefined;
    });

    const auth = makeAuth(onError);
    await waitForInit(auth);

    expect(auth.isAuthenticated).toBe(false);
    expect(auth.user).toBeNull();
    expect(onError).toHaveBeenCalledTimes(1);
    expect(onError.mock.calls[0]![0].code).toBe('INVALID_STATE');
    expect(window.localStorage.getItem(sessionKey())).toBeNull();
    expect(window.sessionStorage.getItem(flowKey())).toBeNull();
    // Error diagnostics stay in the URL.
    expect(window.location.search).toContain('code=');
    expect(lastNavigation()).toBeNull();
  });

  it('maps access_denied to USER_CANCELLED', async () => {
    const onError = vi.fn();
    navigateToCallback({
      error: 'access_denied',
      error_description: 'User cancelled',
      state: 'state-123',
    });
    seedFlow('state-123');
    stubFetch(() => httpResponse(discoveryBody()));

    const auth = makeAuth(onError);
    await waitForInit(auth);

    expect(auth.isAuthenticated).toBe(false);
    expect(onError.mock.calls[0]![0].code).toBe('USER_CANCELLED');
    expect(window.localStorage.getItem(sessionKey())).toBeNull();
  });

  it('maps other authorization server errors to AUTHORIZATION_ERROR', async () => {
    const onError = vi.fn();
    navigateToCallback({ error: 'login_required', state: 'state-123' });
    seedFlow('state-123');
    stubFetch(() => httpResponse(discoveryBody()));

    const auth = makeAuth(onError);
    await waitForInit(auth);

    expect(onError.mock.calls[0]![0].code).toBe('AUTHORIZATION_ERROR');
    expect(onError.mock.calls[0]![0].details).toMatchObject({ oauthError: 'login_required' });
  });

  it('reports a token exchange failure and keeps the user unauthenticated', async () => {
    const onError = vi.fn();
    navigateToCallback({ code: 'bad-code', state: 'state-123' });
    seedFlow('state-123');
    stubFetch((url) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      if (url.endsWith('/token')) return httpResponse({ error: 'invalid_grant' }, 400);
      return undefined;
    });

    const auth = makeAuth(onError);
    await waitForInit(auth);

    expect(auth.isAuthenticated).toBe(false);
    expect(onError.mock.calls[0]![0].code).toBe('TOKEN_EXCHANGE_FAILED');
    expect(window.localStorage.getItem(sessionKey())).toBeNull();
    expect(window.sessionStorage.getItem(flowKey())).toBeNull();
    // No redirect after a failed login.
    expect(lastNavigation()).toBeNull();
  });

  it('rejects a network failure during token exchange', async () => {
    const onError = vi.fn();
    navigateToCallback({ code: 'code-1', state: 'state-123' });
    seedFlow('state-123');
    stubFetch((url) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      if (url.endsWith('/token')) return null;
      return undefined;
    });

    const auth = makeAuth(onError);
    await waitForInit(auth);

    expect(auth.isAuthenticated).toBe(false);
    expect(onError.mock.calls[0]![0].code).toBe('NETWORK_ERROR');
    expect(window.localStorage.getItem(sessionKey())).toBeNull();
  });

  it('rejects an ID Token with a wrong nonce', async () => {
    const onError = vi.fn();
    const keyPair = await generateRsaKeyPair();
    navigateToCallback({ code: 'code-1', state: 'state-123' });
    seedFlow('state-123');
    stubFetch(async (url) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      if (url.endsWith('/jwks')) return httpResponse({ keys: [keyPair.jwk] });
      if (url.endsWith('/token')) {
        const idToken = await makeIdToken(keyPair, { payload: { nonce: 'different-nonce' } });
        return httpResponse({
          access_token: 'at',
          token_type: 'Bearer',
          expires_in: 3600,
          id_token: idToken,
        });
      }
      return undefined;
    });

    const auth = makeAuth(onError);
    await waitForInit(auth);

    expect(auth.isAuthenticated).toBe(false);
    expect(onError.mock.calls[0]![0].code).toBe('INVALID_NONCE');
    expect(window.localStorage.getItem(sessionKey())).toBeNull();
  });

  it('rejects an ID Token signed with an unknown key', async () => {
    const onError = vi.fn();
    const keyPair = await generateRsaKeyPair();
    const other = await generateRsaKeyPair('other-key');
    navigateToCallback({ code: 'code-1', state: 'state-123' });
    seedFlow('state-123');
    stubFetch(async (url) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      if (url.endsWith('/jwks')) return httpResponse({ keys: [other.jwk] });
      if (url.endsWith('/token')) {
        const idToken = await makeIdToken(keyPair, { payload: { nonce: 'nonce-1' } });
        return httpResponse({
          access_token: 'at',
          token_type: 'Bearer',
          expires_in: 3600,
          id_token: idToken,
        });
      }
      return undefined;
    });

    const auth = makeAuth(onError);
    await waitForInit(auth);

    expect(onError.mock.calls[0]![0].code).toBe('TOKEN_EXCHANGE_FAILED');
  });

  it('does not treat a URL without a stored flow as a callback', async () => {
    const onError = vi.fn();
    navigateToCallback({ code: 'code-1', state: 'state-123' });
    stubFetch(() => httpResponse(discoveryBody()));

    const auth = makeAuth(onError);
    await waitForInit(auth);

    expect(auth.isAuthenticated).toBe(false);
    expect(window.localStorage.getItem(sessionKey())).toBeNull();
  });

  it('does not process an arbitrary URL with a code parameter', async () => {
    window.history.pushState({}, '', `/some/page?code=not-a-callback`);
    const onError = vi.fn();
    stubFetch(() => httpResponse(discoveryBody()));
    const auth = makeAuth(onError);
    await waitForInit(auth);
    expect(auth.isAuthenticated).toBe(false);
    expect(onError).not.toHaveBeenCalled();
  });
});
