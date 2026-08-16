import { AuthorizaError } from '../errors.js';

/** JWK as returned by the JWKS endpoint (the DOM `JsonWebKey` type omits `kid`). */
export interface AuthorizaJwk extends JsonWebKey {
  kid?: string;
}

export interface JsonWebKeySet {
  keys: AuthorizaJwk[];
}

export async function fetchJwks(jwksUri: string): Promise<JsonWebKeySet> {
  let response: Response;
  try {
    response = await fetch(jwksUri, { credentials: 'omit' });
  } catch (cause) {
    throw new AuthorizaError('NETWORK_ERROR', 'Failed to fetch JWKS', { cause });
  }
  if (!response.ok) {
    throw new AuthorizaError('NETWORK_ERROR', `JWKS endpoint returned HTTP ${response.status}`, {
      details: { status: response.status },
    });
  }
  let data: unknown;
  try {
    data = await response.json();
  } catch (cause) {
    throw new AuthorizaError('NETWORK_ERROR', 'JWKS endpoint returned an invalid JSON document', {
      cause,
    });
  }
  if (!data || typeof data !== 'object' || !Array.isArray((data as Record<string, unknown>).keys)) {
    throw new AuthorizaError('NETWORK_ERROR', 'JWKS endpoint returned an invalid key set');
  }
  return data as JsonWebKeySet;
}
