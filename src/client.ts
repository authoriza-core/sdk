import { normalizeConfig } from './config.js';
import type { NormalizedConfig } from './config.js';
import { AuthorizaError, OAuthServerError, isAuthorizaError } from './errors.js';
import { fetchDiscovery } from './oidc/discovery.js';
import type { OidcDiscovery } from './oidc/discovery.js';
import { fetchJwks } from './oidc/jwks.js';
import type { AuthorizaJwk, JsonWebKeySet } from './oidc/jwks.js';
import { decodeJwt, verifyJwtSignature } from './oidc/jwt.js';
import { parseTokenResponse, tokenRequest } from './oidc/token.js';
import { AuthFlowStorage } from './storage/flowStorage.js';
import type { AuthFlow } from './storage/flowStorage.js';
import { CrossTabSync } from './sync.js';
import type { AuthState, AuthorizaConfig, LoginOptions, Session, User } from './types.js';
import { createPkcePair, randomBase64Url, sha256Base64Url } from './utils/crypto.js';
import { clearCallbackParams, isCallbackUrl, isValidRelativePath, navigate } from './utils/url.js';

/** Refresh the access token this early before it formally expires. */
const REFRESH_SAFETY_MARGIN_MS = 60_000;

const SUPPORTED_ID_TOKEN_ALGORITHMS = ['RS256', 'PS256', 'ES256'] as const;

interface DecodedIdToken {
  header: { alg?: unknown; kid?: unknown };
  payload: Record<string, unknown>;
  signature: Uint8Array<ArrayBuffer>;
  signedData: Uint8Array<ArrayBuffer>;
}

function wrapStorageError(cause: unknown): never {
  if (isAuthorizaError(cause)) {
    throw cause;
  }
  throw new AuthorizaError('STORAGE_ERROR', 'Session storage operation failed', { cause });
}

function buildUser(claims: Record<string, unknown>): User {
  const user: User = { id: claims.sub as string };
  if (typeof claims.email === 'string') {
    user.email = claims.email;
  }
  if (typeof claims.name === 'string') {
    user.name = claims.name;
  }
  return user;
}

function userEqual(a: User | null, b: User | null): boolean {
  if (a === b) {
    return true;
  }
  if (!a || !b) {
    return false;
  }
  return a.id === b.id && a.email === b.email && a.name === b.name;
}

export class AuthorizaClient {
  private readonly config: NormalizedConfig;
  private readonly flowStorage: AuthFlowStorage;
  private readonly sync: CrossTabSync;
  private readonly listeners = new Set<(state: AuthState) => void>();

  private discovery: OidcDiscovery | null = null;
  private jwks: JsonWebKeySet | null = null;

  private currentSession: Session | null = null;
  private loading = true;
  private initPromise: Promise<void> | null = null;
  private refreshPromise: Promise<string | null> | null = null;
  private loginPromise: Promise<void> | null = null;
  private activeLoginRedirect: string | null = null;
  private lastEmittedState: AuthState | null = null;

  constructor(config: AuthorizaConfig) {
    this.config = normalizeConfig(config);
    this.flowStorage = new AuthFlowStorage(this.config.clientId);
    this.sync = new CrossTabSync(this.config.clientId, () => {
      void this.reloadFromStorage();
    });
    this.sync.start();
    this.initPromise = this.init();
  }

  get isAuthenticated(): boolean {
    return this.currentSession !== null;
  }

  get isLoading(): boolean {
    return this.loading;
  }

  get user(): User | null {
    const user = this.currentSession?.user ?? null;
    return user ? Object.assign({}, user) : null;
  }

  getAuthState(): AuthState {
    return { isAuthenticated: this.isAuthenticated, isLoading: this.isLoading, user: this.user };
  }

  onAuthStateChanged(handler: (state: AuthState) => void): () => void {
    this.listeners.add(handler);
    return () => {
      this.listeners.delete(handler);
    };
  }

  on(event: 'authStateChanged', handler: (state: AuthState) => void): () => void {
    if (event !== 'authStateChanged') {
      throw new AuthorizaError('INVALID_CONFIG', `Unsupported event: ${String(event)}`);
    }
    return this.onAuthStateChanged(handler);
  }

  private async ready(): Promise<void> {
    if (this.initPromise) {
      await this.initPromise;
    }
  }

  private async init(): Promise<void> {
    this.loading = true;
    this.emitState();
    try {
      if (typeof window === 'undefined') {
        return;
      }
      await this.restoreSession();
      if (isCallbackUrl(window.location.href, this.config.redirectUri)) {
        await this.processCallback();
      }
    } catch (error) {
      this.reportError(error);
    } finally {
      this.loading = false;
      this.emitState();
    }
  }

  private async restoreSession(): Promise<void> {
    const session = await this.readSession();
    if (session === null) {
      this.setCurrentSession(null);
      return;
    }
    if (session.expiresAt <= Date.now() && session.refreshToken === null) {
      // Expired and impossible to refresh: treat as invalid and discard.
      await this.clearStoredSession();
      this.setCurrentSession(null);
      return;
    }
    this.setCurrentSession(session);
  }

  // ----- public API -------------------------------------------------------

  async login(options?: LoginOptions): Promise<void> {
    const opts = options ?? {};
    await this.ready();

    if (this.currentSession) {
      // Already authenticated: do not start a redundant authorization flow.
      return;
    }

    const redirectAfterLoginTo = opts.redirectAfterLoginTo ?? null;
    if (
      opts.redirectAfterLoginTo !== undefined &&
      !isValidRelativePath(opts.redirectAfterLoginTo)
    ) {
      throw new AuthorizaError(
        'INVALID_REDIRECT_AFTER_LOGIN',
        `Invalid redirectAfterLoginTo: ${String(opts.redirectAfterLoginTo)}`,
      );
    }

    if (this.loginPromise) {
      // A second call with no options (or identical options) joins the running
      // flow. Only an explicit conflicting option is rejected.
      if (
        opts.redirectAfterLoginTo !== undefined &&
        this.activeLoginRedirect !== redirectAfterLoginTo
      ) {
        throw new AuthorizaError(
          'AUTH_FLOW_IN_PROGRESS',
          'An authentication flow is already in progress with different options',
        );
      }
      return this.loginPromise;
    }

    const promise = this.runLogin(redirectAfterLoginTo);
    this.loginPromise = promise;
    this.activeLoginRedirect = redirectAfterLoginTo;
    try {
      await promise;
    } finally {
      this.loginPromise = null;
      this.activeLoginRedirect = null;
    }
  }

  async logout(): Promise<void> {
    await this.ready();
    try {
      await this.clearStoredSession();
    } finally {
      this.currentSession = null;
      this.loginPromise = null;
      this.activeLoginRedirect = null;
      this.refreshPromise = null;
      await this.clearFlow();
      this.sync.post();
      this.emitState();
    }
  }

  async getUser(): Promise<User | null> {
    await this.ready();
    return this.user;
  }

  async getAccessToken(): Promise<string | null> {
    await this.ready();
    const session = this.currentSession;
    if (!session) {
      return null;
    }
    if (Date.now() + REFRESH_SAFETY_MARGIN_MS < session.expiresAt) {
      return session.accessToken;
    }
    return this.refreshToken();
  }

  // ----- login internals --------------------------------------------------

  private async runLogin(redirectAfterLoginTo: string | null): Promise<void> {
    const storedFlow = await this.flowStorage.get();
    if (storedFlow) {
      if (storedFlow.redirectAfterLoginTo !== redirectAfterLoginTo) {
        throw new AuthorizaError(
          'AUTH_FLOW_IN_PROGRESS',
          'An authentication flow is already in progress with different options',
        );
      }
      await this.startLogin(storedFlow);
      return;
    }
    const flow = await this.createFlow(redirectAfterLoginTo);
    await this.flowStorage.set(flow);
    await this.startLogin(flow);
  }

  private async createFlow(redirectAfterLoginTo: string | null): Promise<AuthFlow> {
    const { codeVerifier } = await createPkcePair();
    return {
      state: randomBase64Url(32),
      nonce: randomBase64Url(32),
      codeVerifier,
      redirectAfterLoginTo,
    };
  }

  private async startLogin(flow: AuthFlow): Promise<void> {
    try {
      const discovery = await this.getDiscovery();
      const url = await this.buildAuthorizationUrl(discovery, flow);
      navigate(url);
    } catch (error) {
      await this.clearFlow();
      throw error;
    }
  }

  private async buildAuthorizationUrl(discovery: OidcDiscovery, flow: AuthFlow): Promise<string> {
    const codeChallenge = await sha256Base64Url(flow.codeVerifier);
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: 'code',
      scope: this.config.scopes.join(' '),
      state: flow.state,
      nonce: flow.nonce,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });
    return `${discovery.authorization_endpoint}?${params.toString()}`;
  }

  // ----- callback internals -----------------------------------------------

  private async processCallback(): Promise<void> {
    const url = new URL(window.location.href);
    const params = url.searchParams;
    const code = params.get('code');
    const state = params.get('state');
    const oauthError = params.get('error');
    const errorDescription = params.get('error_description');

    let flow: AuthFlow | null;
    try {
      flow = await this.flowStorage.get();
    } catch (error) {
      await this.clearFlow();
      throw error;
    }
    if (!flow) {
      throw new AuthorizaError(
        'INVALID_STATE',
        'Callback does not match an active authentication flow',
      );
    }
    if (typeof state !== 'string' || state !== flow.state) {
      await this.clearFlow();
      throw new AuthorizaError('INVALID_STATE', 'OAuth state mismatch in callback');
    }
    if (oauthError !== null) {
      await this.clearFlow();
      if (oauthError === 'access_denied') {
        throw new AuthorizaError('USER_CANCELLED', 'User cancelled the authorization', {
          details: { oauthError, oauthErrorDescription: errorDescription ?? undefined },
        });
      }
      throw new AuthorizaError('AUTHORIZATION_ERROR', 'Authorization server returned an error', {
        details: { oauthError, oauthErrorDescription: errorDescription ?? undefined },
      });
    }
    if (typeof code !== 'string' || code.length === 0) {
      await this.clearFlow();
      throw new AuthorizaError('AUTHORIZATION_ERROR', 'Callback is missing an authorization code');
    }

    const discovery = await this.getDiscovery();

    let session: Session;
    try {
      let tokenData: Record<string, unknown>;
      try {
        tokenData = await tokenRequest(discovery.token_endpoint, {
          grant_type: 'authorization_code',
          client_id: this.config.clientId,
          code,
          redirect_uri: this.config.redirectUri,
          code_verifier: flow.codeVerifier,
        });
      } catch (error) {
        if (error instanceof OAuthServerError) {
          throw new AuthorizaError('TOKEN_EXCHANGE_FAILED', 'Token exchange failed', {
            cause: error,
            details: {
              oauthError: error.oauthError,
              oauthErrorDescription: error.oauthErrorDescription,
            },
          });
        }
        throw error;
      }

      const parsed = parseTokenResponse(tokenData);
      if (parsed.idToken === null) {
        throw new AuthorizaError('TOKEN_EXCHANGE_FAILED', 'Token response is missing id_token');
      }
      const idClaims = await this.validateIdToken(parsed.idToken, flow.nonce);
      session = {
        accessToken: parsed.accessToken,
        refreshToken: parsed.refreshToken,
        expiresAt: Date.now() + parsed.expiresIn * 1000,
        user: buildUser(idClaims),
      };
    } catch (error) {
      await this.clearFlow();
      throw error;
    }

    try {
      await this.writeSession(session);
    } catch (error) {
      await this.clearFlow();
      throw error;
    }
    this.currentSession = session;
    clearCallbackParams();
    await this.clearFlow();
    this.sync.post();
    this.emitState();
    if (flow.redirectAfterLoginTo !== null) {
      navigate(flow.redirectAfterLoginTo);
    }
  }

  private async validateIdToken(
    idToken: string,
    expectedNonce: string | undefined,
  ): Promise<Record<string, unknown>> {
    const discovery = await this.getDiscovery();
    let decoded: DecodedIdToken;
    try {
      const raw = decodeJwt(idToken);
      decoded = {
        header: { alg: raw.header.alg, kid: raw.header.kid },
        payload: raw.payload,
        signature: raw.signature,
        signedData: raw.signedData,
      };
    } catch (cause) {
      throw new AuthorizaError('TOKEN_EXCHANGE_FAILED', 'ID Token is malformed', { cause });
    }

    const alg = decoded.header.alg;
    if (
      typeof alg !== 'string' ||
      !SUPPORTED_ID_TOKEN_ALGORITHMS.includes(alg as (typeof SUPPORTED_ID_TOKEN_ALGORITHMS)[number])
    ) {
      throw new AuthorizaError(
        'TOKEN_EXCHANGE_FAILED',
        `ID Token uses an unsupported algorithm: ${String(alg)}`,
        {
          details: { alg },
        },
      );
    }

    const key = await this.getSigningKey(
      typeof decoded.header.kid === 'string' ? decoded.header.kid : undefined,
      alg,
    );
    let valid: boolean;
    try {
      valid = await verifyJwtSignature(decoded.signedData, decoded.signature, key, alg);
    } catch (cause) {
      throw new AuthorizaError('TOKEN_EXCHANGE_FAILED', 'Failed to verify ID Token signature', {
        cause,
      });
    }
    if (!valid) {
      throw new AuthorizaError('TOKEN_EXCHANGE_FAILED', 'ID Token signature is invalid');
    }

    const claims = decoded.payload;
    if (claims.iss !== discovery.issuer) {
      throw new AuthorizaError(
        'TOKEN_EXCHANGE_FAILED',
        'ID Token issuer does not match the configured issuer',
      );
    }
    const audience = claims.aud;
    const audienceMatches = Array.isArray(audience)
      ? audience.includes(this.config.clientId)
      : audience === this.config.clientId;
    if (!audienceMatches) {
      throw new AuthorizaError(
        'TOKEN_EXCHANGE_FAILED',
        'ID Token audience does not match client_id',
      );
    }
    if (typeof claims.exp !== 'number' || claims.exp * 1000 <= Date.now()) {
      throw new AuthorizaError('TOKEN_EXCHANGE_FAILED', 'ID Token is missing exp or has expired');
    }
    if (expectedNonce !== undefined && claims.nonce !== expectedNonce) {
      throw new AuthorizaError(
        'INVALID_NONCE',
        'ID Token nonce does not match the authentication flow',
      );
    }
    if (typeof claims.sub !== 'string' || claims.sub.length === 0) {
      throw new AuthorizaError('TOKEN_EXCHANGE_FAILED', 'ID Token is missing the sub claim');
    }
    return claims;
  }

  private async getSigningKey(kid: string | undefined, alg: string): Promise<AuthorizaJwk> {
    const keyType = alg === 'ES256' ? 'EC' : 'RSA';
    const find = (keys: AuthorizaJwk[]): AuthorizaJwk | undefined =>
      keys.find(
        (key) =>
          (kid === undefined || key.kid === kid) &&
          key.kty === keyType &&
          (key.use === undefined || key.use === 'sig'),
      );

    let keys = this.jwks?.keys ?? [];
    let key = find(keys);
    if (!key) {
      // Unknown kid: re-fetch JWKS to support signing key rotation.
      const discovery = await this.getDiscovery();
      this.jwks = await fetchJwks(discovery.jwks_uri);
      keys = this.jwks.keys;
      key = find(keys);
    }
    if (!key) {
      throw new AuthorizaError('TOKEN_EXCHANGE_FAILED', 'No suitable signing key found in JWKS', {
        details: { kid, alg },
      });
    }
    return key;
  }

  private async getDiscovery(): Promise<OidcDiscovery> {
    if (this.discovery) {
      return this.discovery;
    }
    const discovery = await fetchDiscovery(this.config.issuer);
    this.discovery = discovery;
    return discovery;
  }

  // ----- refresh internals -------------------------------------------------

  private refreshToken(): Promise<string | null> {
    if (this.refreshPromise) {
      return this.refreshPromise;
    }
    this.refreshPromise = this.doRefresh().finally(() => {
      this.refreshPromise = null;
    });
    return this.refreshPromise;
  }

  private async doRefresh(): Promise<string | null> {
    const session = this.currentSession;
    if (!session) {
      return null;
    }
    if (!session.refreshToken) {
      // Cannot refresh: the session is no longer usable.
      await this.invalidateSession();
      return null;
    }

    let discovery: OidcDiscovery;
    try {
      discovery = await this.getDiscovery();
    } catch (error) {
      throw new AuthorizaError('TOKEN_REFRESH_FAILED', 'Token refresh failed', { cause: error });
    }

    let tokenData: Record<string, unknown>;
    try {
      tokenData = await tokenRequest(discovery.token_endpoint, {
        grant_type: 'refresh_token',
        refresh_token: session.refreshToken,
        client_id: this.config.clientId,
      });
    } catch (error) {
      if (
        error instanceof OAuthServerError &&
        (error.oauthError === 'invalid_grant' || error.oauthError === 'invalid_token')
      ) {
        await this.invalidateSession();
        throw new AuthorizaError('TOKEN_REFRESH_FAILED', 'Token refresh failed', {
          cause: error,
          details: {
            oauthError: error.oauthError,
            oauthErrorDescription: error.oauthErrorDescription,
          },
        });
      }
      throw new AuthorizaError('TOKEN_REFRESH_FAILED', 'Token refresh failed', { cause: error });
    }

    let parsed: ReturnType<typeof parseTokenResponse>;
    try {
      parsed = parseTokenResponse(tokenData);
    } catch (error) {
      if (isAuthorizaError(error) && error.code === 'UNSUPPORTED_TOKEN_TYPE') {
        throw error;
      }
      throw new AuthorizaError('TOKEN_REFRESH_FAILED', 'Token refresh failed', { cause: error });
    }

    if (this.currentSession !== session) {
      // A logout (or another operation) replaced the session while the refresh
      // was in flight: do not write the refreshed tokens back.
      return null;
    }

    let user = session.user;
    if (parsed.idToken !== null) {
      try {
        const idClaims = await this.validateIdToken(parsed.idToken, undefined);
        user = buildUser(idClaims);
      } catch (error) {
        throw new AuthorizaError('TOKEN_REFRESH_FAILED', 'Token refresh failed', { cause: error });
      }
    }

    const refreshed: Session = {
      accessToken: parsed.accessToken,
      refreshToken: parsed.refreshToken ?? session.refreshToken,
      expiresAt: Date.now() + parsed.expiresIn * 1000,
      user,
    };
    await this.writeSession(refreshed);
    this.currentSession = refreshed;
    this.sync.post();
    // No authStateChanged event: the authentication state did not change.
    return refreshed.accessToken;
  }

  private async invalidateSession(): Promise<void> {
    this.currentSession = null;
    try {
      await this.clearStoredSession();
    } finally {
      await this.clearFlow();
      this.sync.post();
      this.emitState();
    }
  }

  // ----- storage helpers ---------------------------------------------------

  private async readSession(): Promise<Session | null> {
    try {
      return await this.config.sessionStorage.get();
    } catch (cause) {
      return wrapStorageError(cause);
    }
  }

  private async writeSession(session: Session): Promise<void> {
    try {
      await this.config.sessionStorage.set(session);
    } catch (cause) {
      return wrapStorageError(cause);
    }
  }

  private async clearStoredSession(): Promise<void> {
    try {
      await this.config.sessionStorage.clear();
    } catch (cause) {
      return wrapStorageError(cause);
    }
  }

  private async clearFlow(): Promise<void> {
    try {
      await this.flowStorage.clear();
    } catch {
      // Best effort: a failure to clear temporary flow data must not break the
      // session operation itself.
    }
  }

  // ----- state / events ----------------------------------------------------

  private setCurrentSession(session: Session | null): void {
    this.currentSession = session;
    this.emitState();
  }

  private emitState(): void {
    const state = this.getAuthState();
    const last = this.lastEmittedState;
    if (
      last &&
      last.isAuthenticated === state.isAuthenticated &&
      last.isLoading === state.isLoading &&
      userEqual(last.user, state.user)
    ) {
      return;
    }
    this.lastEmittedState = state;
    for (const listener of [...this.listeners]) {
      try {
        listener(state);
      } catch (error) {
        // Listener errors belong to the application.
        console.log(error);
      }
    }
  }

  private reportError(error: unknown): void {
    const handler = this.config.onError;
    if (!handler || !isAuthorizaError(error)) {
      return;
    }
    try {
      handler(error);
    } catch {
      // Errors thrown by the handler are the application's responsibility.
    }
  }

  private async reloadFromStorage(): Promise<void> {
    if (typeof window === 'undefined') {
      return;
    }
    try {
      await this.ready();
    } catch {
      return;
    }
    let session: Session | null;
    try {
      session = await this.readSession();
    } catch (error) {
      this.reportError(error);
      return;
    }
    if (session && session.expiresAt <= Date.now() && session.refreshToken === null) {
      try {
        await this.clearStoredSession();
      } catch (error) {
        this.reportError(error);
      }
      session = null;
    }
    this.setCurrentSession(session);
  }
}
