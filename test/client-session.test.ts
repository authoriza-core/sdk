import { describe, expect, it, vi } from 'vitest';
import { createAuthoriza } from '../src/index.js';
import type { Session, SessionStorage } from '../src/index.js';
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

describe('session restore', () => {
  it('restores an existing valid session', async () => {
    seedSession(makeSession());
    const auth = makeAuth();
    await waitForInit(auth);
    expect(auth.isAuthenticated).toBe(true);
    expect(auth.user).toEqual({ id: 'user-1', email: 'user@example.com', name: 'User One' });
    expect(auth.getAuthState()).toEqual({
      isAuthenticated: true,
      isLoading: false,
      user: { id: 'user-1', email: 'user@example.com', name: 'User One' },
    });
  });

  it('starts in loading state and becomes unauthenticated when no session exists', async () => {
    const auth = makeAuth();
    expect(auth.getAuthState()).toEqual({ isAuthenticated: false, isLoading: true, user: null });
    const states = collectStates(auth);
    await waitForInit(auth);
    expect(auth.isAuthenticated).toBe(false);
    expect(states[states.length - 1]).toEqual({
      isAuthenticated: false,
      isLoading: false,
      user: null,
    });
  });

  it('discards a corrupted session and becomes unauthenticated without crashing', async () => {
    const onError = vi.fn();
    window.localStorage.setItem(sessionKey(), '{definitely not json');
    const auth = makeAuth(onError);
    await waitForInit(auth);
    expect(auth.isAuthenticated).toBe(false);
    expect(window.localStorage.getItem(sessionKey())).toBeNull();
  });

  it('discards a session with an unknown format version', async () => {
    window.localStorage.setItem(
      sessionKey(),
      JSON.stringify({
        version: 99,
        accessToken: 'at',
        refreshToken: 'rt',
        expiresAt: Date.now() + 1000,
      }),
    );
    const auth = makeAuth();
    await waitForInit(auth);
    expect(auth.isAuthenticated).toBe(false);
    expect(window.localStorage.getItem(sessionKey())).toBeNull();
  });

  it('discards an expired session without a refresh token', async () => {
    seedSession(makeSession({ refreshToken: null, expiresAt: Date.now() - 1000 }));
    const auth = makeAuth();
    await waitForInit(auth);
    expect(auth.isAuthenticated).toBe(false);
    expect(window.localStorage.getItem(sessionKey())).toBeNull();
  });

  it('keeps an expired session that can still be refreshed', async () => {
    seedSession(makeSession({ expiresAt: Date.now() - 1000 }));
    const auth = makeAuth();
    await waitForInit(auth);
    expect(auth.isAuthenticated).toBe(true);
    expect(window.localStorage.getItem(sessionKey())).not.toBeNull();
  });
});

describe('logout', () => {
  it('clears the session, user and storage and emits the state change', async () => {
    seedSession(makeSession());
    const auth = makeAuth();
    await waitForInit(auth);

    const states = collectStates(auth);
    await auth.logout();

    expect(auth.isAuthenticated).toBe(false);
    expect(auth.user).toBeNull();
    expect(window.localStorage.getItem(sessionKey())).toBeNull();
    expect(states[states.length - 1]).toEqual({
      isAuthenticated: false,
      isLoading: false,
      user: null,
    });
  });

  it('is safe to call when there is no session', async () => {
    const auth = makeAuth();
    await waitForInit(auth);
    await expect(auth.logout()).resolves.toBeUndefined();
    expect(auth.isAuthenticated).toBe(false);
  });

  it('does not navigate to the Authoriza end-session endpoint', async () => {
    stubFetch((url) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      return undefined;
    });
    seedSession(makeSession());
    const auth = makeAuth();
    await waitForInit(auth);
    await auth.logout();
    const { lastNavigation } = await import('./helpers.js');
    expect(lastNavigation()).toBeNull();
  });
});

describe('cross-tab synchronization', () => {
  it('detects a session created in another instance', async () => {
    stubFetch((url) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      return undefined;
    });
    const a = makeAuth();
    const b = makeAuth();
    await Promise.all([waitForInit(a), waitForInit(b)]);
    expect(b.isAuthenticated).toBe(false);

    // Simulate another tab completing login: write the session and notify.
    seedSession(makeSession());
    const channel = new BroadcastChannel(sessionKey());
    channel.postMessage({ type: 'session-changed' });

    await vi.waitFor(() => {
      if (!b.isAuthenticated) {
        throw new Error('session not synced');
      }
    });
    expect(b.user?.id).toBe('user-1');
  });

  it('detects logout in another instance', async () => {
    stubFetch((url) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      return undefined;
    });
    seedSession(makeSession());
    const a = makeAuth();
    const b = makeAuth();
    await Promise.all([waitForInit(a), waitForInit(b)]);
    expect(a.isAuthenticated).toBe(true);
    expect(b.isAuthenticated).toBe(true);

    await a.logout();

    await vi.waitFor(() => {
      if (b.isAuthenticated) {
        throw new Error('logout not synced');
      }
    });
    expect(b.user).toBeNull();
    expect(window.localStorage.getItem(sessionKey())).toBeNull();
  });

  it('uses the localStorage notification fallback with custom SessionStorage', async () => {
    vi.stubGlobal('BroadcastChannel', undefined);

    const originalSetItem = Storage.prototype.setItem;
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(function setItemWithStorageEvent(
      this: Storage,
      key: string,
      value: string,
    ) {
      originalSetItem.call(this, key, value);
      if (this === window.localStorage) {
        window.dispatchEvent(
          new StorageEvent('storage', {
            key,
            newValue: value,
            storageArea: window.localStorage,
          }),
        );
      }
    });

    stubFetch((url) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      return undefined;
    });

    let sharedSession: Session | null = makeSession();
    const storage: SessionStorage = {
      async get() {
        return sharedSession
          ? { ...sharedSession, user: sharedSession.user && { ...sharedSession.user } }
          : null;
      },
      async set(session) {
        sharedSession = { ...session, user: session.user && { ...session.user } };
      },
      async clear() {
        sharedSession = null;
      },
    };

    const a = createAuthoriza({
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      issuer: ISSUER,
      sessionStorage: storage,
    });
    const b = createAuthoriza({
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      issuer: ISSUER,
      sessionStorage: storage,
    });
    await Promise.all([waitForInit(a), waitForInit(b)]);
    expect(a.isAuthenticated).toBe(true);
    expect(b.isAuthenticated).toBe(true);

    await a.logout();

    await vi.waitFor(() => {
      if (b.isAuthenticated) {
        throw new Error('fallback logout not synced');
      }
    });
    expect(b.user).toBeNull();
    expect(window.localStorage.getItem('authoriza:sync:test-client')).not.toBeNull();
    expect(window.localStorage.getItem('authoriza:sync:test-client')).not.toContain('access-token');
    expect(window.localStorage.getItem('authoriza:sync:test-client')).not.toContain(
      'refresh-token',
    );
  });

  it('keeps different clientIds isolated', async () => {
    stubFetch((url) => {
      if (url.includes('.well-known')) return httpResponse(discoveryBody());
      return undefined;
    });
    const a = createAuthoriza({
      clientId: 'client-a',
      redirectUri: REDIRECT_URI,
      issuer: ISSUER,
    });
    const b = createAuthoriza({
      clientId: 'client-b',
      redirectUri: REDIRECT_URI,
      issuer: ISSUER,
    });
    await Promise.all([waitForInit(a), waitForInit(b)]);

    // Session for client-a must not affect client-b.
    seedSession(makeSession(), 'client-a');
    const channelA = new BroadcastChannel('authoriza:session:client-a');
    channelA.postMessage({ type: 'session-changed' });

    await vi.waitFor(() => {
      if (!a.isAuthenticated) {
        throw new Error('client-a not authenticated');
      }
    });
    expect(b.isAuthenticated).toBe(false);
  });
});
