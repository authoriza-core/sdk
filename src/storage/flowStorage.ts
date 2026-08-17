import { AuthorizaError } from '../errors.js';
import { isValidRelativePath } from '../utils/url.js';

export const AUTH_FLOW_KEY_PREFIX = 'authoriza:authflow:';

/**
 * Temporary per-tab state of an active authentication flow. Stored separately
 * from the user session and only lives for the duration of one flow.
 */
export interface AuthFlow {
  state: string;
  nonce: string;
  codeVerifier: string;
  redirectAfterLoginTo: string | null;
}

/**
 * Stores the temporary `AuthFlow` in browser `sessionStorage`, keyed by
 * `clientId` so instances sharing a client also share the flow space, while
 * different clients stay isolated.
 */
export class AuthFlowStorage {
  private readonly key: string;

  constructor(clientId: string) {
    this.key = `${AUTH_FLOW_KEY_PREFIX}${clientId}`;
  }

  async get(): Promise<AuthFlow | null> {
    if (typeof window === 'undefined' || typeof window.sessionStorage === 'undefined') {
      return null;
    }
    let raw: string | null;
    try {
      raw = window.sessionStorage.getItem(this.key);
    } catch (cause) {
      throw new AuthorizaError('STORAGE_ERROR', 'Failed to read authentication flow', { cause });
    }
    if (raw === null) {
      return null;
    }
    let record: Record<string, unknown>;
    try {
      record = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      return null;
    }
    if (
      !record ||
      typeof record.state !== 'string' ||
      typeof record.nonce !== 'string' ||
      typeof record.codeVerifier !== 'string'
    ) {
      return null;
    }
    let redirectAfterLoginTo: string | null = null;
    if (record.redirectAfterLoginTo !== null && record.redirectAfterLoginTo !== undefined) {
      if (!isValidRelativePath(record.redirectAfterLoginTo)) {
        throw new AuthorizaError(
          'INVALID_REDIRECT_AFTER_LOGIN',
          'Stored redirectAfterLoginTo value is invalid',
        );
      }
      redirectAfterLoginTo = record.redirectAfterLoginTo;
    }
    return {
      state: record.state,
      nonce: record.nonce,
      codeVerifier: record.codeVerifier,
      redirectAfterLoginTo,
    };
  }

  async set(flow: AuthFlow): Promise<void> {
    if (typeof window === 'undefined' || typeof window.sessionStorage === 'undefined') {
      throw new AuthorizaError(
        'STORAGE_ERROR',
        'sessionStorage is not available in this environment',
      );
    }
    try {
      window.sessionStorage.setItem(this.key, JSON.stringify(flow));
    } catch (cause) {
      throw new AuthorizaError('STORAGE_ERROR', 'Failed to store authentication flow', { cause });
    }
  }

  async clear(): Promise<void> {
    if (typeof window === 'undefined' || typeof window.sessionStorage === 'undefined') {
      return;
    }
    try {
      window.sessionStorage.removeItem(this.key);
    } catch (cause) {
      throw new AuthorizaError('STORAGE_ERROR', 'Failed to clear authentication flow', { cause });
    }
  }
}
