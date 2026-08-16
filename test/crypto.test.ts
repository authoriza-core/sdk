import { describe, expect, it } from 'vitest';
import {
  base64UrlDecode,
  base64UrlDecodeString,
  base64UrlEncode,
  createPkcePair,
  randomBase64Url,
} from '../src/utils/crypto.js';

describe('base64url', () => {
  it('round-trips arbitrary bytes without padding', () => {
    const bytes = new TextEncoder().encode('hello world, this is a test of base64url encoding!');
    const encoded = base64UrlEncode(bytes);
    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
    expect(encoded).not.toContain('=');
    expect(new TextDecoder().decode(base64UrlDecode(encoded))).toBe(
      'hello world, this is a test of base64url encoding!',
    );
  });

  it('matches RFC 7636 example: verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"', async () => {
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    const challenge = await createPkcePairFromVerifier(verifier);
    expect(challenge).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });

  it('decodes a padded standard base64 string', () => {
    expect(base64UrlDecodeString('aGVsbG8')).toBe('hello');
  });
});

async function createPkcePairFromVerifier(verifier: string): Promise<string> {
  const { sha256Base64Url } = await import('../src/utils/crypto.js');
  return sha256Base64Url(verifier);
}

describe('randomBase64Url', () => {
  it('produces URL-safe random values of expected length', () => {
    const a = randomBase64Url(32);
    const b = randomBase64Url(32);
    expect(a).toHaveLength(43);
    expect(a).not.toBe(b);
    expect(a).toMatch(/^[A-Za-z0-9_-]+$/);
  });
});

describe('createPkcePair', () => {
  it('produces a valid verifier/challenge pair', async () => {
    const { codeVerifier, codeChallenge } = await createPkcePair();
    expect(codeVerifier).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(codeVerifier.length).toBeGreaterThanOrEqual(43);
    expect(codeChallenge).toMatch(/^[A-Za-z0-9_-]+$/);
    const expected = await createPkcePairFromVerifier(codeVerifier);
    expect(codeChallenge).toBe(expected);
  });

  it('generates a different pair on each call', async () => {
    const first = await createPkcePair();
    const second = await createPkcePair();
    expect(first.codeVerifier).not.toBe(second.codeVerifier);
  });
});
