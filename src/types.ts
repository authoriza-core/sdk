import type { AuthorizaError } from './errors.js';

/**
 * Model of the authenticated user built from ID Token claims.
 *
 * `id` always comes from the `sub` claim. `email` and `name` are optional and
 * are only present when the corresponding claims exist in the ID Token.
 */
export interface User {
  id: string;
  email?: string;
  name?: string;
}

/**
 * Persistent user session stored through `SessionStorage`.
 *
 * `expiresAt` is an absolute Unix timestamp in milliseconds computed as
 * `receivedAt + expires_in * 1000`.
 */
export interface Session {
  accessToken: string;
  refreshToken: string | null;
  expiresAt: number;
  user: User | null;
}

/**
 * Public authentication state of a client instance.
 */
export interface AuthState {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: User | null;
}

/**
 * Abstraction over the persistent session storage.
 *
 * The SDK never touches the storage mechanism directly in the authentication
 * flow; everything goes through this interface.
 */
export interface SessionStorage {
  get(): Promise<Session | null>;
  set(session: Session): Promise<void>;
  clear(): Promise<void>;
}

export interface LoginOptions {
  /** Relative application path to navigate to after a successful login. */
  redirectAfterLoginTo?: string;
}

export interface AuthorizaConfig {
  /** Required OIDC client identifier. */
  clientId: string;
  /** Required technical OIDC callback URL. */
  redirectUri: string;
  /** Optional issuer URL; defaults to the Authoriza production issuer. */
  issuer?: string;
  /** Optional additional scopes merged with the required SDK scopes. */
  scope?: string[];
  /** Optional custom session storage implementation. */
  sessionStorage?: SessionStorage;
  /**
   * Shared error handler of the instance. Used for errors raised during
   * asynchronous authentication flow processing, including callback handling.
   */
  onError?: (error: AuthorizaError) => void;
}

/**
 * Public client surface returned by {@link createAuthoriza}.
 */
export interface Authoriza {
  login(options?: LoginOptions): Promise<void>;
  logout(): Promise<void>;
  getUser(): Promise<User | null>;
  getAccessToken(): Promise<string | null>;
  getAuthState(): AuthState;
  readonly isAuthenticated: boolean;
  readonly isLoading: boolean;
  readonly user: User | null;
  onAuthStateChanged(handler: (state: AuthState) => void): () => void;
  on(event: 'authStateChanged', handler: (state: AuthState) => void): () => void;
}
