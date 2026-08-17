import { describe, expect, it } from 'vitest';
import { createAuthoriza } from '../src/index.js';
import {
  APP_URL,
  CLIENT_ID,
  ISSUER,
  REDIRECT_URI,
  discoveryBody,
  flowKey,
  httpResponse,
  lastNavigation,
  navigationCount,
  seedSession,
  stubFetch,
  waitForInit,
} from './helpers.js';

function makeAuth(overrides: Record<string, unknown> = {}) {
  return createAuthoriza({
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    issuer: ISSUER,
    ...overrides,
  });
}

describe('login', () => {
  it('redirects to the authorization endpoint with the required parameters', async () => {
    const fetch = stubFetch((url) => {
      if (url.includes('.well-known/openid-configuration')) return httpResponse(discoveryBody());
      return undefined;
    });

    const auth = makeAuth();
    await auth.login({ redirectAfterLoginTo: '/dashboard' });

    expect(window.location.href).toBe(APP_URL);
    const target = lastNavigation();
    expect(target).not.toBeNull();
    const url = new URL(target!);
    expect(url.origin + url.pathname).toBe(`${ISSUER}/auth`);

    const params = url.searchParams;
    expect(params.get('client_id')).toBe(CLIENT_ID);
    expect(params.get('redirect_uri')).toBe(REDIRECT_URI);
    expect(params.get('response_type')).toBe('code');
    expect(params.get('code_challenge_method')).toBe('S256');
    expect(params.get('state')).toBeTruthy();
    expect(params.get('nonce')).toBeTruthy();
    expect(params.get('code_challenge')).toBeTruthy();
    expect(params.get('code_verifier')).toBeNull();

    const scope = params.get('scope');
    expect(scope).toContain('openid');
    expect(scope).toContain('profile');
    expect(scope).toContain('email');
    expect(scope).toContain('offline_access');

    // The flow parameters are persisted so the callback can be validated.
    const flow = JSON.parse(window.sessionStorage.getItem(flowKey())!);
    expect(flow.state).toBe(params.get('state'));
    expect(flow.nonce).toBe(params.get('nonce'));
    expect(flow.redirectAfterLoginTo).toBe('/dashboard');
    expect(flow.codeVerifier).toBeTruthy();

    expect(fetch).toHaveBeenCalledTimes(1); // discovery only
  });

  it('allows overriding the issuer via configuration', async () => {
    const customIssuer = 'https://auth.test.example/tenant';
    stubFetch((url) => {
      if (url.includes('/tenant/.well-known/openid-configuration')) {
        return httpResponse(discoveryBody(customIssuer));
      }
      return undefined;
    });
    const auth = createAuthoriza({
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      issuer: customIssuer,
    });
    await auth.login();
    const url = new URL(lastNavigation()!);
    expect(url.origin + url.pathname).toBe(`${customIssuer}/auth`);
  });

  it('uses the default Authoriza issuer when none is configured', async () => {
    stubFetch((url) => {
      if (url === 'https://oidc.authoriza.ru/oidc/.well-known/openid-configuration') {
        return httpResponse(discoveryBody('https://oidc.authoriza.ru/oidc'));
      }
      return undefined;
    });
    const auth = createAuthoriza({
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
    });
    await auth.login();
    const url = new URL(lastNavigation()!);
    expect(url.origin + url.pathname).toBe('https://oidc.authoriza.ru/oidc/auth');
  });

  it('uses configured scopes plus only mandatory SDK scopes', async () => {
    stubFetch((url) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      return undefined;
    });
    const auth = makeAuth({ scope: ['custom_scope', 'openid'] });
    await auth.login();
    const scope = new URL(lastNavigation()!).searchParams.get('scope');
    expect(scope).toContain('openid');
    expect(scope).toContain('custom_scope');
    expect(scope).not.toContain('profile');
    expect(scope).not.toContain('email');
    expect(scope).not.toContain('offline_access');
    expect(scope!.split(' ').filter((s) => s === 'openid')).toHaveLength(1);
  });

  it('does not redirect when already authenticated', async () => {
    stubFetch((url) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      return undefined;
    });
    seedSession({
      accessToken: 'at',
      refreshToken: 'rt',
      expiresAt: Date.now() + 3600_000,
      user: { id: 'u1' },
    });
    const auth = makeAuth();
    await waitForInit(auth);
    expect(auth.isAuthenticated).toBe(true);

    await auth.login({ redirectAfterLoginTo: '/dashboard' });
    expect(navigationCount()).toBe(0);
  });

  it('rejects an invalid redirectAfterLoginTo before redirecting', async () => {
    stubFetch((url) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      return undefined;
    });
    const auth = makeAuth();
    await expect(
      auth.login({ redirectAfterLoginTo: 'https://evil.example.com' }),
    ).rejects.toMatchObject({
      code: 'INVALID_REDIRECT_AFTER_LOGIN',
    });
    await expect(auth.login({ redirectAfterLoginTo: '//evil.example.com' })).rejects.toMatchObject({
      code: 'INVALID_REDIRECT_AFTER_LOGIN',
    });
    await expect(auth.login({ redirectAfterLoginTo: 'javascript:alert(1)' })).rejects.toMatchObject(
      {
        code: 'INVALID_REDIRECT_AFTER_LOGIN',
      },
    );
    expect(navigationCount()).toBe(0);
    expect(window.sessionStorage.getItem(flowKey())).toBeNull();
  });

  it('fails with DISCOVERY_FAILED when discovery is unavailable', async () => {
    stubFetch((url) => {
      if (url.includes('.well-known')) return httpResponse({ error: 'server_error' }, 500);
      return undefined;
    });
    const auth = makeAuth();
    await expect(auth.login()).rejects.toMatchObject({
      code: 'DISCOVERY_FAILED',
    });
    expect(navigationCount()).toBe(0);
    // The aborted flow must be cleaned up so the next login starts fresh.
    expect(window.sessionStorage.getItem(flowKey())).toBeNull();
  });

  it('fails with NETWORK_ERROR when the network is down', async () => {
    stubFetch((url) => (url.includes('.well-known') ? null : undefined));
    const auth = makeAuth();
    await expect(auth.login()).rejects.toMatchObject({ code: 'NETWORK_ERROR' });
    expect(navigationCount()).toBe(0);
  });

  it('deduplicates concurrent login calls with identical options', async () => {
    stubFetch((url) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      return undefined;
    });
    const auth = makeAuth();
    await Promise.all([
      auth.login({ redirectAfterLoginTo: '/dashboard' }),
      auth.login({ redirectAfterLoginTo: '/dashboard' }),
    ]);
    expect(navigationCount()).toBe(1);
  });

  it('joins a second login() with no options to the running flow', async () => {
    stubFetch((url) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      return undefined;
    });
    const auth = makeAuth();
    await Promise.all([auth.login({ redirectAfterLoginTo: '/dashboard' }), auth.login()]);
    expect(navigationCount()).toBe(1);
  });

  it('rejects a conflicting concurrent login with AUTH_FLOW_IN_PROGRESS', async () => {
    stubFetch((url) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      return undefined;
    });
    const auth = makeAuth();
    const results = await Promise.allSettled([
      auth.login({ redirectAfterLoginTo: '/dashboard' }),
      auth.login({ redirectAfterLoginTo: '/profile' }),
    ]);
    expect(results[0].status).toBe('fulfilled');
    expect(results[1].status).toBe('rejected');
    if (results[1].status === 'rejected') {
      expect((results[1].reason as { code: string }).code).toBe('AUTH_FLOW_IN_PROGRESS');
    }
    expect(navigationCount()).toBe(1);
    // The first flow is untouched.
    const flow = JSON.parse(window.sessionStorage.getItem(flowKey())!);
    expect(flow.redirectAfterLoginTo).toBe('/dashboard');
  });

  it('waits for session restore before deciding to start a new flow', async () => {
    stubFetch((url) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      return undefined;
    });
    seedSession({
      accessToken: 'at',
      refreshToken: 'rt',
      expiresAt: Date.now() + 3600_000,
      user: { id: 'u1' },
    });
    const auth = makeAuth();
    // login() is called immediately; it must wait for restore and then skip
    // the redirect because a valid session already exists.
    await auth.login();
    expect(navigationCount()).toBe(0);
  });
});
