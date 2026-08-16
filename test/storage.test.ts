import { describe, expect, it, vi } from 'vitest';
import type { Session } from '../src/index.js';
import { SESSION_KEY_PREFIX, parseStoredSession } from '../src/storage/session.js';
import { LocalStorageSessionStorage } from '../src/storage/sessionStorage.js';

function makeStoredSession(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    version: 1,
    accessToken: 'at',
    refreshToken: 'rt',
    expiresAt: 1234,
    user: { id: 'u1', email: 'e@x.com', name: 'Name' },
    ...overrides,
  });
}

describe('parseStoredSession', () => {
  it('parses a valid stored session', () => {
    const result = parseStoredSession(makeStoredSession());
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.session).toEqual({
        accessToken: 'at',
        refreshToken: 'rt',
        expiresAt: 1234,
        user: { id: 'u1', email: 'e@x.com', name: 'Name' },
      });
    }
  });

  it('rejects invalid JSON', () => {
    expect(parseStoredSession('{not json').ok).toBe(false);
  });

  it('rejects an unknown version', () => {
    expect(parseStoredSession(makeStoredSession({ version: 999 })).ok).toBe(false);
  });

  it('rejects missing required fields', () => {
    expect(parseStoredSession(makeStoredSession({ accessToken: undefined })).ok).toBe(false);
    expect(parseStoredSession(makeStoredSession({ refreshToken: 42 })).ok).toBe(false);
    expect(parseStoredSession(makeStoredSession({ expiresAt: 'soon' })).ok).toBe(false);
    expect(parseStoredSession(makeStoredSession({ user: { name: 'no id' } })).ok).toBe(false);
  });

  it('accepts missing optional user fields and null user', () => {
    const noUser = parseStoredSession(makeStoredSession({ user: null }));
    expect(noUser.ok).toBe(true);
    if (noUser.ok) expect(noUser.session.user).toBeNull();

    const partialUser = parseStoredSession(makeStoredSession({ user: { id: 'u1' } }));
    expect(partialUser.ok).toBe(true);
    if (partialUser.ok) expect(partialUser.session.user).toEqual({ id: 'u1' });
  });
});

describe('LocalStorageSessionStorage', () => {
  it('stores, reads and clears a session under a clientId-scoped key', async () => {
    const storage = new LocalStorageSessionStorage('client-a');
    const session: Session = {
      accessToken: 'at',
      refreshToken: 'rt',
      expiresAt: 1234,
      user: { id: 'u1' },
    };
    await storage.set(session);
    expect(window.localStorage.getItem('authoriza:session:client-a')).not.toBeNull();
    await expect(storage.get()).resolves.toEqual(session);

    await storage.clear();
    expect(window.localStorage.getItem('authoriza:session:client-a')).toBeNull();
    await expect(storage.get()).resolves.toBeNull();
  });

  it('isolates sessions by clientId', async () => {
    const a = new LocalStorageSessionStorage('client-a');
    const b = new LocalStorageSessionStorage('client-b');
    await a.set({ accessToken: 'at-a', refreshToken: null, expiresAt: 1, user: null });
    await b.set({ accessToken: 'at-b', refreshToken: null, expiresAt: 1, user: null });
    expect((await a.get())?.accessToken).toBe('at-a');
    expect((await b.get())?.accessToken).toBe('at-b');
  });

  it('discards corrupt data instead of throwing', async () => {
    const storage = new LocalStorageSessionStorage('client-a');
    window.localStorage.setItem(`${SESSION_KEY_PREFIX}client-a`, '{corrupt');
    await expect(storage.get()).resolves.toBeNull();
    expect(window.localStorage.getItem(`${SESSION_KEY_PREFIX}client-a`)).toBeNull();
  });

  it('discards sessions with an unknown version', async () => {
    const storage = new LocalStorageSessionStorage('client-a');
    window.localStorage.setItem(
      `${SESSION_KEY_PREFIX}client-a`,
      makeStoredSession({ version: 42 }),
    );
    await expect(storage.get()).resolves.toBeNull();
  });

  it('surfaces storage errors as STORAGE_ERROR', async () => {
    const storage = new LocalStorageSessionStorage('client-a');
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new DOMException('denied', 'SecurityError');
    });
    await expect(storage.get()).rejects.toMatchObject({ code: 'STORAGE_ERROR' });
  });
});
