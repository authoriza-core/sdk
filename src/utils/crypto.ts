/**
 * Cryptographic helpers built on top of standard Web APIs
 * (`crypto.getRandomValues`, `crypto.subtle`, `TextEncoder`).
 */

const B64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

export function base64UrlEncode(input: Uint8Array): string {
  let out = '';
  for (let i = 0; i < input.length; i += 3) {
    const b0 = input[i]!;
    const b1 = i + 1 < input.length ? input[i + 1]! : 0;
    const b2 = i + 2 < input.length ? input[i + 2]! : 0;
    out += B64URL_ALPHABET[b0 >> 2]!;
    out += B64URL_ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)]!;
    out += i + 1 < input.length ? B64URL_ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)]! : '';
    out += i + 2 < input.length ? B64URL_ALPHABET[b2 & 0x3f]! : '';
  }
  return out;
}

export function base64UrlDecode(input: string): Uint8Array<ArrayBuffer> {
  const clean = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = clean.length % 4;
  const padded = pad === 0 ? clean : clean + '===='.slice(0, 4 - pad);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function base64UrlDecodeString(input: string): string {
  return new TextDecoder().decode(base64UrlDecode(input));
}

/** Cryptographically random base64url string of `bytes` random bytes. */
export function randomBase64Url(bytes = 32): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return base64UrlEncode(arr);
}

export async function sha256Base64Url(input: string): Promise<string> {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return base64UrlEncode(new Uint8Array(hash));
}

export interface PkcePair {
  codeVerifier: string;
  codeChallenge: string;
}

/**
 * Creates a fresh PKCE pair per RFC 7636 using method S256.
 */
export async function createPkcePair(): Promise<PkcePair> {
  const codeVerifier = randomBase64Url(32);
  const codeChallenge = await sha256Base64Url(codeVerifier);
  return { codeVerifier, codeChallenge };
}
