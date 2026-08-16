import { AuthorizaError } from '../errors.js';

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
    try {
      const record = JSON.parse(raw) as Record<string, unknown>;
      if (
        !record ||
        typeof record.state !== 'string' ||
        typeof record.nonce !== 'string' ||
        typeof record.codeVerifier !== 'string'
      ) {
        return null;
      }
      const redirectAfterLoginTo =
        record.redirectAfterLoginTo === null || record.redirectAfterLoginTo === undefined
          ? null
          : typeof record.redirectAfterLoginTo === 'string'
            ? record.redirectAfterLoginTo
            : null;
      return {
        state: record.state,
        nonce: record.nonce,
        codeVerifier: record.codeVerifier,
        redirectAfterLoginTo,
      };
    } catch {
      return null;
    }
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
