import { describe, expect, it } from 'vitest';
import { AuthorizaError, createAuthoriza } from '../src/index.js';

describe('createAuthoriza configuration', () => {
  it('throws INVALID_CONFIG when clientId is missing', () => {
    expect(() =>
      createAuthoriza({ clientId: '', redirectUri: 'https://app.example.com/cb' }),
    ).toThrowError(AuthorizaError);
    expect(() =>
      createAuthoriza({ clientId: '', redirectUri: 'https://app.example.com/cb' }),
    ).toThrowError(expect.objectContaining({ code: 'INVALID_CONFIG' }));
  });

  it('throws INVALID_CONFIG when redirectUri is missing or invalid', () => {
    expect(() => createAuthoriza({ clientId: 'a' } as never)).toThrowError(
      expect.objectContaining({ code: 'INVALID_CONFIG' }),
    );
    expect(() => createAuthoriza({ clientId: 'a', redirectUri: 'not-a-url' })).toThrowError(
      expect.objectContaining({ code: 'INVALID_CONFIG' }),
    );
    expect(() =>
      createAuthoriza({ clientId: 'a', redirectUri: 'javascript:alert(1)' }),
    ).toThrowError(expect.objectContaining({ code: 'INVALID_CONFIG' }));
  });

  it('throws INVALID_CONFIG when issuer is invalid', () => {
    expect(() =>
      createAuthoriza({ clientId: 'a', redirectUri: 'https://app.example.com/cb', issuer: 'nope' }),
    ).toThrowError(expect.objectContaining({ code: 'INVALID_CONFIG' }));
  });

  it('throws INVALID_CONFIG when scope is not an array of strings', () => {
    expect(() =>
      createAuthoriza({
        clientId: 'a',
        redirectUri: 'https://app.example.com/cb',
        scope: ['openid', 42] as never,
      }),
    ).toThrowError(expect.objectContaining({ code: 'INVALID_CONFIG' }));
  });

  it('throws INVALID_CONFIG when sessionStorage does not implement the interface', () => {
    expect(() =>
      createAuthoriza({
        clientId: 'a',
        redirectUri: 'https://app.example.com/cb',
        sessionStorage: {} as never,
      }),
    ).toThrowError(expect.objectContaining({ code: 'INVALID_CONFIG' }));
  });

  it('throws INVALID_CONFIG when onError is not a function', () => {
    expect(() =>
      createAuthoriza({
        clientId: 'a',
        redirectUri: 'https://app.example.com/cb',
        onError: 'nope' as never,
      }),
    ).toThrowError(expect.objectContaining({ code: 'INVALID_CONFIG' }));
  });

  it('accepts a minimal valid configuration', () => {
    const auth = createAuthoriza({ clientId: 'a', redirectUri: 'https://app.example.com/cb' });
    expect(auth.getAuthState()).toEqual({ isAuthenticated: false, isLoading: true, user: null });
  });

  it('normalizes issuer by stripping a trailing slash', () => {
    const auth = createAuthoriza({
      clientId: 'a',
      redirectUri: 'https://app.example.com/cb',
      issuer: 'https://issuer.example.com/oidc/',
    });
    expect(auth.getAuthState().isLoading).toBe(true);
  });
});
