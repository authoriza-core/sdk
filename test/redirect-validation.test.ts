import { describe, expect, it } from 'vitest';
import { isValidRelativePath } from '../src/utils/url.js';

describe('isValidRelativePath (redirectAfterLoginTo validation)', () => {
  it.each([
    '/dashboard',
    '/account/profile',
    '/orders/123',
    '/dashboard?tab=settings',
    '/dashboard#profile',
    '/dashboard?tab=settings#profile',
    '/',
  ])('accepts %s', (value) => {
    expect(isValidRelativePath(value)).toBe(true);
  });

  it.each([
    'https://example.com/dashboard',
    'http://example.com/dashboard',
    '//evil.example.com',
    '/\\evil.example.com',
    'javascript:alert(1)',
    'data:text/html,<script>',
    'blob:https://example.com/abc',
    'dashboard',
    '',
    'relative/path',
    '/javascript:alert(1)',
    '/data:x',
    '/path/with\\backslash',
    '/path\u0000with',
    '/path\nwith',
  ])('rejects %j', (value) => {
    expect(isValidRelativePath(value)).toBe(false);
  });

  it('rejects non-strings', () => {
    expect(isValidRelativePath(null)).toBe(false);
    expect(isValidRelativePath(42)).toBe(false);
    expect(isValidRelativePath(undefined)).toBe(false);
  });
});
