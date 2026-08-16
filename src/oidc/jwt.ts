import { base64UrlDecode, base64UrlDecodeString } from '../utils/crypto.js';

export interface DecodedJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: Uint8Array<ArrayBuffer>;
  /** UTF-8 bytes of `header.payload` used for signature verification. */
  signedData: Uint8Array<ArrayBuffer>;
}

export function decodeJwt(token: string): DecodedJwt {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('JWT must consist of three parts');
  }
  const [headerPart, payloadPart, signaturePart] = parts;
  if (!headerPart || !payloadPart || !signaturePart) {
    throw new Error('JWT is missing parts');
  }
  let header: unknown;
  let payload: unknown;
  try {
    header = JSON.parse(base64UrlDecodeString(headerPart));
    payload = JSON.parse(base64UrlDecodeString(payloadPart));
  } catch (cause) {
    throw new Error(
      `Malformed JWT encoding: ${cause instanceof Error ? cause.message : String(cause)}`,
      {
        cause,
      },
    );
  }
  if (!header || typeof header !== 'object') {
    throw new Error('JWT header is not an object');
  }
  if (!payload || typeof payload !== 'object') {
    throw new Error('JWT payload is not an object');
  }
  return {
    header: header as Record<string, unknown>,
    payload: payload as Record<string, unknown>,
    signature: base64UrlDecode(signaturePart),
    signedData: new TextEncoder().encode(`${headerPart}.${payloadPart}`),
  };
}

function toDerInteger(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  let value = bytes;
  let start = 0;
  while (start < value.length - 1 && value[start] === 0) {
    start += 1;
  }
  value = value.slice(start);
  if ((value[0]! & 0x80) !== 0) {
    return new Uint8Array([0x02, value.length + 1, 0x00, ...value]);
  }
  return new Uint8Array([0x02, value.length, ...value]);
}

/**
 * Converts a raw R||S ECDSA signature (as used in JWS for ES256) into the DER
 * encoding expected by WebCrypto `subtle.verify`.
 */
export function rawEcdsaToDer(signature: Uint8Array): Uint8Array<ArrayBuffer> {
  if (signature.length % 2 !== 0) {
    throw new Error('Invalid ECDSA signature length');
  }
  const half = signature.length / 2;
  const r = toDerInteger(signature.slice(0, half));
  const s = toDerInteger(signature.slice(half));
  const content = new Uint8Array([...r, ...s]);
  let header: number[];
  if (content.length < 0x80) {
    header = [0x30, content.length];
  } else if (content.length < 0x100) {
    header = [0x30, 0x81, content.length];
  } else {
    header = [0x30, 0x82, content.length >> 8, content.length & 0xff];
  }
  return new Uint8Array([...header, ...content]);
}

/**
 * Verifies a JWS signature with WebCrypto using the algorithms supported by
 * Authoriza: PS256, RS256 and ES256.
 *
 * Returns `false` (never throws) for unsupported algorithms or verification
 * failures so callers can decide how to report the error.
 */
export async function verifyJwtSignature(
  signedData: Uint8Array<ArrayBuffer>,
  signature: Uint8Array<ArrayBuffer>,
  jwk: JsonWebKey,
  alg: string,
): Promise<boolean> {
  if (typeof crypto === 'undefined' || typeof crypto.subtle === 'undefined') {
    return false;
  }
  const subtle = crypto.subtle;
  try {
    if (alg === 'RS256') {
      const key = await subtle.importKey(
        'jwk',
        jwk,
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['verify'],
      );
      return await subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, key, signature, signedData);
    }
    if (alg === 'PS256') {
      const key = await subtle.importKey('jwk', jwk, { name: 'RSA-PSS', hash: 'SHA-256' }, false, [
        'verify',
      ]);
      return await subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, key, signature, signedData);
    }
    if (alg === 'ES256') {
      const key = await subtle.importKey(
        'jwk',
        jwk,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify'],
      );
      return await subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        key,
        rawEcdsaToDer(signature),
        signedData,
      );
    }
    return false;
  } catch {
    return false;
  }
}
