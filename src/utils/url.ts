/**
 * URL helpers for callback detection, `redirectAfterLoginTo` validation and
 * browser navigation.
 */

export function buildDiscoveryUrl(issuer: string): string {
  return `${issuer}/.well-known/openid-configuration`;
}

/**
 * Validates a `redirectAfterLoginTo` value.
 *
 * Only relative paths of the current application are allowed. Absolute URLs,
 * protocol-relative URLs and URLs with dangerous schemes are rejected.
 */
export function isValidRelativePath(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0) {
    return false;
  }
  if (!value.startsWith('/')) {
    return false;
  }
  if (value.startsWith('//') || value.startsWith('/\\')) {
    return false;
  }
  if (value.includes('\\')) {
    return false;
  }
  // Reject control characters and DEL.
  // biome-ignore lint/suspicious/noControlCharactersInRegex:
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(value)) {
    return false;
  }
  // Reject scheme-like path segments, e.g. /javascript:alert(1)
  return !/^\/[a-zA-Z][a-zA-Z0-9+.-]*:/.test(value);
}

/**
 * Determines whether the current URL is a callback URL for the configured
 * `redirectUri` and contains authorization flow parameters (code+state or
 * error+state).
 */
export function isCallbackUrl(currentUrl: string, redirectUri: string): boolean {
  let current: URL;
  let target: URL;
  try {
    current = new URL(currentUrl);
    target = new URL(redirectUri);
  } catch {
    return false;
  }
  if (current.origin !== target.origin || current.pathname !== target.pathname) {
    return false;
  }
  const params = current.searchParams;
  const hasAuthState = params.has('state');
  return (params.has('code') || params.has('error')) && hasAuthState;
}

/** Removes authorization flow parameters from the URL without reloading. */
export function clearCallbackParams(): void {
  if (typeof window === 'undefined' || typeof history === 'undefined') {
    return;
  }
  const url = new URL(window.location.href);
  for (const param of ['code', 'state', 'error', 'error_description']) {
    url.searchParams.delete(param);
  }
  const clean = `${url.pathname}${url.search}${url.hash}`;
  history.replaceState(history.state, '', clean);
}

export function navigate(url: string): void {
  if (typeof window === 'undefined' || typeof window.location === 'undefined') {
    throw new Error('Browser navigation is not available in this environment');
  }
  window.location.assign(url);
}
