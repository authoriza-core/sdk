import { AuthorizaClient } from './client.js';
import type { Authoriza, AuthorizaConfig } from './types.js';

/**
 * Creates an isolated Authoriza client instance.
 *
 * The instance is created synchronously and without any network requests.
 * Session restoration happens asynchronously; observe `isLoading` /
 * `getAuthState()` / `onAuthStateChanged` to track when it completes.
 *
 * @throws {AuthorizaError} with code `INVALID_CONFIG` if the configuration is
 * invalid.
 */
export function createAuthoriza(config: AuthorizaConfig): Authoriza {
  return new AuthorizaClient(config);
}
