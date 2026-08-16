import { AuthorizaError } from '../errors.js';
import type { Session, SessionStorage } from '../types.js';
import { SESSION_KEY_PREFIX, SESSION_VERSION, parseStoredSession } from './session.js';

function storageUnavailable(): never {
  throw new AuthorizaError('STORAGE_ERROR', 'localStorage is not available in this environment');
}

/**
 * Default `SessionStorage` implementation based on browser `localStorage`.
 * The synchronous `localStorage` API is adapted to the asynchronous
 * `SessionStorage` interface.
 */
export class LocalStorageSessionStorage implements SessionStorage {
  private readonly key: string;

  constructor(clientId: string) {
    this.key = `${SESSION_KEY_PREFIX}${clientId}`;
  }

  get keyName(): string {
    return this.key;
  }

  async get(): Promise<Session | null> {
    if (typeof window === 'undefined' || typeof window.localStorage === 'undefined') {
      storageUnavailable();
    }
    let raw: string | null;
    try {
      raw = window.localStorage.getItem(this.key);
    } catch (cause) {
      throw new AuthorizaError('STORAGE_ERROR', 'Failed to read session from localStorage', {
        cause,
      });
    }
    if (raw === null) {
      return null;
    }
    const parsed = parseStoredSession(raw);
    if (!parsed.ok) {
      try {
        window.localStorage.removeItem(this.key);
      } catch (cause) {
        throw new AuthorizaError(
          'STORAGE_ERROR',
          'Failed to remove invalid session from localStorage',
          { cause },
        );
      }
      return null;
    }
    return parsed.session;
  }

  async set(session: Session): Promise<void> {
    if (typeof window === 'undefined' || typeof window.localStorage === 'undefined') {
      storageUnavailable();
    }
    let raw: string;
    try {
      raw = JSON.stringify({ version: SESSION_VERSION, ...session });
    } catch (cause) {
      throw new AuthorizaError('STORAGE_ERROR', 'Failed to serialize session', { cause });
    }
    try {
      window.localStorage.setItem(this.key, raw);
    } catch (cause) {
      throw new AuthorizaError('STORAGE_ERROR', 'Failed to write session to localStorage', {
        cause,
      });
    }
  }

  async clear(): Promise<void> {
    if (typeof window === 'undefined' || typeof window.localStorage === 'undefined') {
      storageUnavailable();
    }
    try {
      window.localStorage.removeItem(this.key);
    } catch (cause) {
      throw new AuthorizaError('STORAGE_ERROR', 'Failed to clear session from localStorage', {
        cause,
      });
    }
  }
}
