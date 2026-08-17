import { AuthorizaError } from './errors.js';
import { LocalStorageSessionStorage } from './storage/sessionStorage.js';
import type { AuthorizaConfig, SessionStorage } from './types.js';

export const DEFAULT_ISSUER = 'https://oidc.authoriza.ru/oidc';

/** Scopes that are mandatory for the SDK to function. `openid` is required for OIDC. */
export const REQUIRED_SCOPES = ['openid'] as const;

/**
 * Scopes used when an application does not configure scopes explicitly.
 * Applications that provide `scope` opt in only to those scopes plus the
 * mandatory OIDC scope above.
 */
export const DEFAULT_SCOPES = ['openid', 'profile', 'email', 'offline_access'] as const;

export interface NormalizedConfig {
  clientId: string;
  redirectUri: string;
  issuer: string;
  scopes: string[];
  sessionStorage: SessionStorage;
  onError?: (error: AuthorizaError) => void;
}

function fail(message: string): never {
  throw new AuthorizaError('INVALID_CONFIG', message);
}

function isValidHttpUrl(value: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  return parsed.protocol === 'https:' || parsed.protocol === 'http:';
}

export function normalizeConfig(config: AuthorizaConfig): NormalizedConfig {
  if (config === null || typeof config !== 'object') {
    fail('config must be an object');
  }

  const clientId = config.clientId;
  if (typeof clientId !== 'string' || clientId.trim().length === 0) {
    fail('clientId is required and must be a non-empty string');
  }

  const redirectUri = config.redirectUri;
  if (typeof redirectUri !== 'string' || !isValidHttpUrl(redirectUri)) {
    fail('redirectUri is required and must be a valid http(s) URL');
  }

  const configuredIssuer = config.issuer ?? DEFAULT_ISSUER;
  if (typeof configuredIssuer !== 'string' || configuredIssuer.trim().length === 0) {
    fail('issuer must be a non-empty string');
  }
  if (!isValidHttpUrl(configuredIssuer)) {
    fail('issuer must be a valid http(s) URL');
  }
  const issuer = configuredIssuer.replace(/\/+$/, '');

  let configuredScopes: string[] | undefined;
  if (config.scope !== undefined) {
    if (
      !Array.isArray(config.scope) ||
      config.scope.some((s) => typeof s !== 'string' || s.trim().length === 0)
    ) {
      fail('scope must be an array of non-empty strings');
    }
    configuredScopes = config.scope;
  }
  const scopeSource =
    configuredScopes === undefined ? DEFAULT_SCOPES : [...REQUIRED_SCOPES, ...configuredScopes];
  const scopes = [...new Set(scopeSource)];

  let sessionStorage: SessionStorage;
  if (config.sessionStorage === undefined) {
    sessionStorage = new LocalStorageSessionStorage(clientId);
  } else if (
    typeof config.sessionStorage.get !== 'function' ||
    typeof config.sessionStorage.set !== 'function' ||
    typeof config.sessionStorage.clear !== 'function'
  ) {
    fail('sessionStorage must implement get(), set() and clear()');
  } else {
    sessionStorage = config.sessionStorage;
  }

  if (config.onError !== undefined && typeof config.onError !== 'function') {
    fail('onError must be a function');
  }

  return {
    clientId,
    redirectUri,
    issuer,
    scopes,
    sessionStorage,
    onError: config.onError,
  };
}
