import { AuthorizaError } from '../errors.js';
import { buildDiscoveryUrl } from '../utils/url.js';

export interface OidcDiscovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  userinfo_endpoint?: string;
  id_token_signing_alg_values_supported?: string[];
}

const REQUIRED_FIELDS = ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri'] as const;

function validateDiscovery(data: unknown, expectedIssuer: string): OidcDiscovery {
  if (!data || typeof data !== 'object') {
    throw new AuthorizaError('DISCOVERY_FAILED', 'OIDC Discovery document is not an object');
  }
  const record = data as Record<string, unknown>;
  for (const field of REQUIRED_FIELDS) {
    if (typeof record[field] !== 'string' || record[field].length === 0) {
      throw new AuthorizaError(
        'DISCOVERY_FAILED',
        `OIDC Discovery is missing required field "${field}"`,
      );
    }
  }
  if (record.issuer !== expectedIssuer) {
    throw new AuthorizaError(
      'DISCOVERY_FAILED',
      'OIDC Discovery issuer does not match the configured issuer',
      { details: { expected: expectedIssuer, actual: record.issuer } },
    );
  }
  return {
    issuer: record.issuer as string,
    authorization_endpoint: record.authorization_endpoint as string,
    token_endpoint: record.token_endpoint as string,
    jwks_uri: record.jwks_uri as string,
    userinfo_endpoint:
      typeof record.userinfo_endpoint === 'string' ? record.userinfo_endpoint : undefined,
    id_token_signing_alg_values_supported: Array.isArray(
      record.id_token_signing_alg_values_supported,
    )
      ? record.id_token_signing_alg_values_supported.filter(
          (x): x is string => typeof x === 'string',
        )
      : undefined,
  };
}

export async function fetchDiscovery(issuer: string): Promise<OidcDiscovery> {
  const url = buildDiscoveryUrl(issuer);
  let response: Response;
  try {
    response = await fetch(url, { credentials: 'omit' });
  } catch (cause) {
    throw new AuthorizaError('NETWORK_ERROR', 'Failed to fetch OIDC Discovery document', { cause });
  }
  if (!response.ok) {
    throw new AuthorizaError(
      'DISCOVERY_FAILED',
      `OIDC Discovery returned HTTP ${response.status}`,
      {
        details: { status: response.status },
      },
    );
  }
  let data: unknown;
  try {
    data = await response.json();
  } catch (cause) {
    throw new AuthorizaError(
      'DISCOVERY_FAILED',
      'OIDC Discovery returned an invalid JSON document',
      { cause },
    );
  }
  return validateDiscovery(data, issuer);
}
