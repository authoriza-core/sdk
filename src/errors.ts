/**
 * Stable machine-readable error codes exposed by the SDK.
 *
 * These codes are part of the public API and must not change without a major
 * version bump. Applications must branch on `error.code`, never on
 * `error.message`.
 */
export type AuthorizaErrorCode =
  | 'INVALID_CONFIG'
  | 'DISCOVERY_FAILED'
  | 'NETWORK_ERROR'
  | 'AUTH_FLOW_IN_PROGRESS'
  | 'INVALID_STATE'
  | 'AUTHORIZATION_ERROR'
  | 'TOKEN_EXCHANGE_FAILED'
  | 'TOKEN_REFRESH_FAILED'
  | 'INVALID_SESSION'
  | 'STORAGE_ERROR'
  | 'USER_CANCELLED'
  | 'UNSUPPORTED_TOKEN_TYPE'
  | 'INVALID_REDIRECT_AFTER_LOGIN'
  | 'INVALID_NONCE';

const DEFAULT_MESSAGES: Record<AuthorizaErrorCode, string> = {
  INVALID_CONFIG: 'Invalid SDK configuration',
  DISCOVERY_FAILED: 'OIDC Discovery failed',
  NETWORK_ERROR: 'Network request failed',
  AUTH_FLOW_IN_PROGRESS: 'An authentication flow is already in progress',
  INVALID_STATE: 'OAuth state mismatch',
  AUTHORIZATION_ERROR: 'Authorization server returned an error',
  TOKEN_EXCHANGE_FAILED: 'Token exchange failed',
  TOKEN_REFRESH_FAILED: 'Token refresh failed',
  INVALID_SESSION: 'The session is invalid',
  STORAGE_ERROR: 'Session storage operation failed',
  USER_CANCELLED: 'User cancelled the authorization',
  UNSUPPORTED_TOKEN_TYPE: 'Unsupported token type',
  INVALID_REDIRECT_AFTER_LOGIN: 'Invalid redirectAfterLoginTo value',
  INVALID_NONCE: 'ID Token nonce mismatch',
};

export interface AuthorizaErrorOptions {
  cause?: unknown;
  details?: Record<string, unknown>;
}

/**
 * Base class for every controlled error thrown by the SDK.
 *
 * The `code` field is the stable machine-readable identifier. `message` is
 * intended only for diagnostics and may change between versions.
 */
export class AuthorizaError extends Error {
  readonly code: AuthorizaErrorCode;
  readonly details?: Record<string, unknown>;

  constructor(code: AuthorizaErrorCode, message?: string, options?: AuthorizaErrorOptions) {
    super(message ?? DEFAULT_MESSAGES[code], { cause: options?.cause });
    this.name = 'AuthorizaError';
    this.code = code;
    this.details = options?.details;
  }
}

export function isAuthorizaError(value: unknown): value is AuthorizaError {
  return value instanceof AuthorizaError;
}

/**
 * Internal error type representing a standard OAuth 2.0 error response body
 * returned by the authorization or token endpoint. Not exported publicly.
 */
export class OAuthServerError extends Error {
  readonly oauthError: string;
  readonly oauthErrorDescription?: string;

  constructor(oauthError: string, oauthErrorDescription?: string) {
    super(`Authorization server returned error: ${oauthError}`);
    this.name = 'OAuthServerError';
    this.oauthError = oauthError;
    this.oauthErrorDescription = oauthErrorDescription;
  }
}
