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

describe('full authentication flow (login → authorization → callback → token exchange → session)', () => {
  it('completes end-to-end with PKCE, state and nonce', async () => {
    const keyPair = await generateRsaKeyPair();

    const fetch = stubFetch(async (url, init) => {
      if (url.includes('.well-known/openid-configuration')) return httpResponse(discoveryBody());
      if (url.endsWith('/jwks')) return httpResponse({ keys: [keyPair.jwk] });
      if (url.endsWith('/token')) {
        const body = new URLSearchParams(init?.body as string);
        const flow = JSON.parse(window.sessionStorage.getItem(flowKey())!);
        // PKCE: the code_verifier passed at the token endpoint must produce the
        // code_challenge sent in the authorization request.
        const { sha256Base64Url } = await import('../src/utils/crypto.js');
        const challengeAtAuth = new URL(authorizationUrl).searchParams.get('code_challenge');
        expect(await sha256Base64Url(body.get('code_verifier')!)).toBe(challengeAtAuth);

        const idToken = await makeIdToken(keyPair, {
          payload: {
            nonce: flow.nonce,
            sub: 'user-1',
            email: 'user@example.com',
            name: 'User One',
          },
        });
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

    // 1. Login page: start the flow.
    const appClient = createAuthoriza({
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      issuer: ISSUER,
    });
    await appClient.login({ redirectAfterLoginTo: '/dashboard' });

    const authorizationUrl = lastNavigation()!;
    expect(authorizationUrl).toContain(`${ISSUER}/auth?`);
    const authParams = new URL(authorizationUrl).searchParams;
    const state = authParams.get('state')!;
    const nonce = authParams.get('nonce')!;
    expect(state).toBeTruthy();
    expect(nonce).toBeTruthy();
    expect(authParams.get('code_challenge_method')).toBe('S256');
    expect(authParams.get('code_verifier')).toBeNull();

    // 2. Authoriza redirects back to the callback URL.
    window.history.pushState({}, '', `/auth/callback?code=auth-code&state=${state}`);

    // 3. New page load on the callback URL → automatic callback processing.
    const callbackClient = createAuthoriza({
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      issuer: ISSUER,
    });
    await waitForInit(callbackClient);

    expect(callbackClient.isAuthenticated).toBe(true);
    expect(callbackClient.user).toEqual({
      id: 'user-1',
      email: 'user@example.com',
      name: 'User One',
    });
    expect(await callbackClient.getAccessToken()).toBe('access-token');

    const stored = JSON.parse(window.localStorage.getItem(sessionKey())!);
    expect(stored.accessToken).toBe('access-token');
    expect(stored.refreshToken).toBe('refresh-token');
    expect(stored.expiresAt).toBeGreaterThan(Date.now());

    // Flow data and callback params are cleaned up.
    expect(window.sessionStorage.getItem(flowKey())).toBeNull();
    expect(window.location.search).not.toContain('code=');
    expect(lastNavigation()).toBe('/dashboard');

    // The login-page client observes the session change via cross-tab sync.
    await new Promise((r) => setTimeout(r, 0));
    expect(appClient.isAuthenticated).toBe(true);

    expect(fetch).toHaveBeenCalled();
  });
});

describe('login → callback with an invalid state', () => {
  it('never creates a session and reports INVALID_STATE', async () => {
    const keyPair = await generateRsaKeyPair();
    stubFetch(async (url) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      if (url.endsWith('/jwks')) return httpResponse({ keys: [keyPair.jwk] });
      if (url.endsWith('/token')) {
        const flow = JSON.parse(window.sessionStorage.getItem(flowKey())!);
        const idToken = await makeIdToken(keyPair, { payload: { nonce: flow.nonce } });
        return httpResponse({
          access_token: 'at',
          token_type: 'Bearer',
          expires_in: 3600,
          id_token: idToken,
        });
      }
      return undefined;
    });

    const errors: string[] = [];
    const onError = (e: { code: string }) => errors.push(e.code);

    const appClient = createAuthoriza({
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      issuer: ISSUER,
    });
    await appClient.login();

    // Callback arrives with a forged state.
    window.history.pushState({}, '', `/auth/callback?code=auth-code&state=forged-state`);
    vi.mocked(window.location.assign).mockClear();
    const callbackClient = createAuthoriza({
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      issuer: ISSUER,
      onError,
    });
    await waitForInit(callbackClient);

    expect(callbackClient.isAuthenticated).toBe(false);
    expect(errors).toContain('INVALID_STATE');
    expect(window.localStorage.getItem(sessionKey())).toBeNull();
    expect(lastNavigation()).toBeNull();
  });
});

describe('login → token exchange error', () => {
  it('keeps the user unauthenticated and does not redirect', async () => {
    const errors: string[] = [];
    stubFetch((url) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      if (url.endsWith('/token')) return httpResponse({ error: 'invalid_grant' }, 400);
      return undefined;
    });

    const appClient = createAuthoriza({
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      issuer: ISSUER,
    });
    await appClient.login();
    const state = new URL(lastNavigation()!).searchParams.get('state')!;

    window.history.pushState({}, '', `/auth/callback?code=bad-code&state=${state}`);
    vi.mocked(window.location.assign).mockClear();
    const callbackClient = createAuthoriza({
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      issuer: ISSUER,
      onError: (e) => errors.push(e.code),
    });
    await waitForInit(callbackClient);

    expect(callbackClient.isAuthenticated).toBe(false);
    expect(errors).toContain('TOKEN_EXCHANGE_FAILED');
    expect(window.localStorage.getItem(sessionKey())).toBeNull();
    expect(lastNavigation()).toBeNull();
  });
});
