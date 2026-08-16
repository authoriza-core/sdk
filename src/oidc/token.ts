import { AuthorizaError, OAuthServerError } from '../errors.js';

export interface ParsedTokenResponse {
  accessToken: string;
  expiresIn: number;
  refreshToken: string | null;
  idToken: string | null;
  tokenType: string | null;
}

/**
 * POSTs to the token endpoint with `application/x-www-form-urlencoded` body.
 * No client authentication is used (public client).
 *
 * Throws:
 * - `NETWORK_ERROR` for transport failures and non-OAuth HTTP errors;
 * - `OAuthServerError` for standard OAuth error responses;
 * - `TOKEN_EXCHANGE_FAILED` for malformed 2xx responses.
 */
export async function tokenRequest(
  endpoint: string,
  params: Record<string, string>,
): Promise<Record<string, unknown>> {
  let response: Response;
  try {
    response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(params).toString(),
      credentials: 'omit',
    });
  } catch (cause) {
    throw new AuthorizaError('NETWORK_ERROR', 'Token endpoint request failed', { cause });
  }

  let data: unknown;
  try {
    data = await response.json();
  } catch {
    data = null;
  }

  if (!response.ok) {
    if (
      data &&
      typeof data === 'object' &&
      typeof (data as Record<string, unknown>).error === 'string'
    ) {
      const errorBody = data as Record<string, unknown>;
      throw new OAuthServerError(
        errorBody.error as string,
        typeof errorBody.error_description === 'string' ? errorBody.error_description : undefined,
      );
    }
    throw new AuthorizaError('NETWORK_ERROR', `Token endpoint returned HTTP ${response.status}`, {
      details: { status: response.status },
    });
  }

  if (
    !data ||
    typeof data !== 'object' ||
    typeof (data as Record<string, unknown>).access_token !== 'string'
  ) {
    throw new AuthorizaError(
      'TOKEN_EXCHANGE_FAILED',
      'Token endpoint returned a malformed response',
    );
  }
  return data as Record<string, unknown>;
}

/**
 * Validates the shape of a successful token response.
 */
export function parseTokenResponse(data: Record<string, unknown>): ParsedTokenResponse {
  const accessToken = data.access_token;
  const tokenType = typeof data.token_type === 'string' ? data.token_type : null;
  const expiresIn = data.expires_in;

  if (typeof accessToken !== 'string' || accessToken.length === 0) {
    throw new AuthorizaError('TOKEN_EXCHANGE_FAILED', 'Token response is missing access_token');
  }
  if (typeof expiresIn !== 'number' || !Number.isFinite(expiresIn)) {
    throw new AuthorizaError('TOKEN_EXCHANGE_FAILED', 'Token response is missing expires_in');
  }
  if (tokenType !== null && tokenType.toLowerCase() !== 'bearer') {
    throw new AuthorizaError('UNSUPPORTED_TOKEN_TYPE', `Unsupported token type: ${tokenType}`, {
      details: { tokenType },
    });
  }

  return {
    accessToken,
    expiresIn,
    refreshToken:
      typeof data.refresh_token === 'string' && data.refresh_token.length > 0
        ? data.refresh_token
        : null,
    idToken: typeof data.id_token === 'string' && data.id_token.length > 0 ? data.id_token : null,
    tokenType,
  };
}
