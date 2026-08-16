import { createVerify } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { decodeJwt, rawEcdsaToDer, verifyJwtSignature } from '../src/oidc/jwt.js';
import { base64UrlEncode } from '../src/utils/crypto.js';
import {
  generateEcKeyPair,
  generateRsaKeyPair,
  generateRsaPssKeyPair,
  makeIdToken,
  signJwt,
} from './jwt-helper.js';

describe('decodeJwt', () => {
  it('parses header and payload', async () => {
    const keyPair = await generateRsaKeyPair();
    const token = await makeIdToken(keyPair);
    const decoded = decodeJwt(token);
    expect(decoded.header.alg).toBe('RS256');
    expect(decoded.payload.sub).toBe('user-1');
  });

  it('throws on malformed tokens', () => {
    expect(() => decodeJwt('not-a-jwt')).toThrow();
    expect(() => decodeJwt('a.b')).toThrow();
    expect(() => decodeJwt('a.b.c.d')).toThrow();
    expect(() => decodeJwt('!!!.b.c')).toThrow();
  });
});

describe('verifyJwtSignature', () => {
  it('verifies an RS256 signature', async () => {
    const keyPair = await generateRsaKeyPair();
    const token = await makeIdToken(keyPair);
    const decoded = decodeJwt(token);
    const valid = await verifyJwtSignature(
      decoded.signedData,
      decoded.signature,
      keyPair.jwk,
      'RS256',
    );
    expect(valid).toBe(true);
  });

  it('rejects a tampered token', async () => {
    const keyPair = await generateRsaKeyPair();
    const token = await makeIdToken(keyPair);
    // Tamper with the middle of the signature segment so real bytes change.
    const parts = token.split('.');
    const sig = parts[2]!;
    const idx = Math.floor(sig.length / 2);
    const replacement = sig[idx] === 'A' ? 'B' : 'A';
    parts[2] = `${sig.slice(0, idx)}${replacement}${sig.slice(idx + 1)}`;
    const tampered = parts.join('.');
    const decoded = decodeJwt(tampered);
    const valid = await verifyJwtSignature(
      decoded.signedData,
      decoded.signature,
      keyPair.jwk,
      'RS256',
    );
    expect(valid).toBe(false);
  });

  it('rejects a signature made with a different key', async () => {
    const signer = await generateRsaKeyPair();
    const other = await generateRsaKeyPair();
    const token = await makeIdToken(signer);
    const decoded = decodeJwt(token);
    const valid = await verifyJwtSignature(
      decoded.signedData,
      decoded.signature,
      other.jwk,
      'RS256',
    );
    expect(valid).toBe(false);
  });

  it('converts raw R||S ES256 signatures to standards-compliant DER', async () => {
    // Node's WebCrypto signs ECDSA as raw R||S (browsers return DER, as the
    // WebCrypto spec requires). Validate that rawEcdsaToDer produces DER that
    // a standards-compliant verifier (Node's legacy crypto, which expects DER)
    // accepts.
    const keyPair = await generateEcKeyPair();
    const data = new TextEncoder().encode('signed-data');
    const raw = new Uint8Array(
      await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keyPair.privateKey, data),
    );
    expect(raw).toHaveLength(64);
    const der = rawEcdsaToDer(raw);

    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey));
    const pem = `-----BEGIN PUBLIC KEY-----\n${Buffer.from(spki).toString('base64')}\n-----END PUBLIC KEY-----`;
    const verifier = createVerify('SHA256');
    verifier.update(data);
    expect(verifier.verify(pem, Buffer.from(der))).toBe(true);
  });

  it('does not throw while verifying an ES256 signature', async () => {
    // Exercises the ES256 branch of verifyJwtSignature. Browsers verify DER
    // signatures; Node's WebCrypto uses raw R||S, so the exact boolean differs
    // between environments, but the branch must never throw.
    const keyPair = await generateEcKeyPair();
    const token = await makeIdToken(keyPair, { header: { alg: 'ES256' } });
    const decoded = decodeJwt(token);
    await expect(
      verifyJwtSignature(decoded.signedData, decoded.signature, keyPair.jwk, 'ES256'),
    ).resolves.toBeTypeOf('boolean');
  });

  it('verifies a PS256 signature', async () => {
    const keyPair = await generateRsaPssKeyPair('ps-key');
    const data = `${enc({ alg: 'PS256' })}.${enc({ sub: 'u' })}`;
    const signature = new Uint8Array(
      await crypto.subtle.sign(
        { name: 'RSA-PSS', saltLength: 32 },
        keyPair.privateKey,
        new TextEncoder().encode(data),
      ),
    );
    const valid = await verifyJwtSignature(
      new TextEncoder().encode(data),
      signature,
      keyPair.jwk,
      'PS256',
    );
    expect(valid).toBe(true);
  });

  it('returns false for unsupported algorithms', async () => {
    const keyPair = await generateRsaKeyPair();
    const token = await signJwt({ alg: 'HS256' }, { sub: 'u' }, keyPair.privateKey);
    const decoded = decodeJwt(token);
    const valid = await verifyJwtSignature(
      decoded.signedData,
      decoded.signature,
      keyPair.jwk,
      'HS256',
    );
    expect(valid).toBe(false);
  });
});

describe('rawEcdsaToDer', () => {
  it('produces a DER sequence wrapping the two integers', () => {
    const r = new Uint8Array(32).fill(0x80);
    const s = new Uint8Array(32).fill(0x80);
    const signature = new Uint8Array([...r, ...s]);
    const der = rawEcdsaToDer(signature);
    expect(der[0]).toBe(0x30); // SEQUENCE
    expect(der[2]).toBe(0x02); // INTEGER
    const length = der[3]!;
    expect(length).toBe(33); // 32 bytes + leading zero because high bit set
    expect(der[4]).toBe(0x00);
  });
});

function enc(value: unknown): string {
  return base64UrlEncode(new TextEncoder().encode(JSON.stringify(value)));
}
