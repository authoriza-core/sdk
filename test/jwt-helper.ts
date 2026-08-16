import { webcrypto } from 'node:crypto';
import type { AuthorizaJwk } from '../src/oidc/jwks.js';
import { base64UrlEncode } from '../src/utils/crypto.js';

export interface KeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  jwk: AuthorizaJwk;
}

export async function generateRsaKeyPair(kid = 'key-1'): Promise<KeyPair> {
  const { publicKey, privateKey } = await webcrypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  );
  const jwk = await webcrypto.subtle.exportKey('jwk', publicKey);
  return {
    privateKey,
    publicKey,
    jwk: { ...jwk, kid, alg: 'RS256', use: 'sig' } as AuthorizaJwk,
  };
}

export async function generateEcKeyPair(kid = 'ec-key-1'): Promise<KeyPair> {
  const { publicKey, privateKey } = await webcrypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  const jwk = await webcrypto.subtle.exportKey('jwk', publicKey);
  return {
    privateKey,
    publicKey,
    jwk: { ...jwk, kid, alg: 'ES256', use: 'sig' } as AuthorizaJwk,
  };
}

export async function generateRsaPssKeyPair(kid = 'ps-key-1'): Promise<KeyPair> {
  const { publicKey, privateKey } = await webcrypto.subtle.generateKey(
    {
      name: 'RSA-PSS',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  );
  const jwk = await webcrypto.subtle.exportKey('jwk', publicKey);
  return {
    privateKey,
    publicKey,
    jwk: { ...jwk, kid, alg: 'PS256', use: 'sig' } as AuthorizaJwk,
  };
}

/** Converts a DER ECDSA signature into raw R||S as used by JWS. */
export function derToRawEcdsa(der: Uint8Array): Uint8Array {
  if (der[0] !== 0x30) {
    throw new Error('Not a DER SEQUENCE');
  }
  let offset = 2;
  const firstLength = der[1]!;
  if ((firstLength & 0x80) !== 0) {
    offset += firstLength & 0x7f;
  }
  const readInteger = (): Uint8Array => {
    if (der[offset]! !== 0x02) {
      throw new Error('Expected DER INTEGER');
    }
    let length = der[offset + 1]!;
    let start = offset + 2;
    if (der[start] === 0x00) {
      start += 1;
      length -= 1;
    }
    const value = der.slice(start, start + length);
    offset = start + length;
    return value;
  };
  const r = readInteger();
  const s = readInteger();
  const out = new Uint8Array(r.length + s.length);
  out.set(r, 0);
  out.set(s, r.length);
  return out;
}

export function base64UrlEncodeJson(value: unknown): string {
  return base64UrlEncode(new TextEncoder().encode(JSON.stringify(value)));
}

function josePart(payload: unknown): string {
  return base64UrlEncodeJson(payload);
}

export async function signJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  privateKey: CryptoKey,
): Promise<string> {
  const data = `${josePart(header)}.${josePart(payload)}`;
  const bytes = new TextEncoder().encode(data);
  const alg = typeof header.alg === 'string' ? header.alg : 'RS256';
  let signature: Uint8Array;
  if (alg === 'ES256') {
    const sig = new Uint8Array(
      await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, bytes),
    );
    // Node's WebCrypto returns raw R||S while browsers return DER.
    signature = sig.length > 64 && sig[0] === 0x30 ? derToRawEcdsa(sig) : sig;
  } else if (alg === 'PS256') {
    signature = new Uint8Array(
      await webcrypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, privateKey, bytes),
    );
  } else {
    signature = new Uint8Array(await webcrypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, bytes));
  }
  return `${data}.${base64UrlEncode(signature)}`;
}

export function makeIdTokenPayload(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    iss: 'https://oidc.example.com/oidc',
    sub: 'user-1',
    aud: 'test-client',
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
    nonce: 'nonce',
    email: 'user@example.com',
    name: 'User One',
    ...overrides,
  };
}

export interface IdTokenOptions {
  kid?: string;
  header?: Record<string, unknown>;
  payload?: Record<string, unknown>;
}

export async function makeIdToken(keyPair: KeyPair, options: IdTokenOptions = {}): Promise<string> {
  const header = {
    alg: 'RS256',
    typ: 'JWT',
    kid: options.kid ?? keyPair.jwk.kid,
    ...options.header,
  };
  const payload = makeIdTokenPayload(options.payload);
  return signJwt(header, payload, keyPair.privateKey);
}
