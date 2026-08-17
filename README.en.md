# @authoriza/sdk

[Читать на русском](./README.md)

Framework-agnostic OIDC SDK for [Authoriza](https://authoriza.ru). Implements
Authorization Code Flow with PKCE for browser SPA applications.

## Features

- Login, logout, session restoration after page reload
- Automatic access token refresh with concurrent request protection
- Automatic OIDC callback handling
- Cross-tab state synchronization
- Full TypeScript types
- Zero runtime dependencies
- SSR-safe import and instance creation

## Installation

```bash
npm install @authoriza/sdk
```

## Quick Start

```ts
import { createAuthoriza } from '@authoriza/sdk';

const auth = createAuthoriza({
  clientId: 'YOUR_CLIENT_ID',
  redirectUri: 'https://example.com/auth/callback',
});

// Check state
auth.isAuthenticated; // boolean
auth.user;            // User | null
auth.isLoading;       // boolean

// Login
await auth.login({ redirectAfterLoginTo: '/dashboard' });

// Get access token for API requests
const token = await auth.getAccessToken();

// Logout (local)
await auth.logout();
```

## Configuration

```ts
interface AuthorizaConfig {
  /** Required identifier of the frontend application registered in Authoriza */
  clientId: string;
  /** Required technical OIDC callback URL. Not the page the user lands on after login */
  redirectUri: string;
  /** OIDC server URL.
   *  Defaults to the Authoriza production server: https://oidc.authoriza.ru/oidc */
  issuer?: string;
  /** Array of scopes. `openid` is added automatically.
   *  Defaults to ['openid', 'profile', 'email', 'offline_access'] */
  scope?: string[];
  /** Custom session storage implementation.
   *  Defaults to `localStorage` */
  sessionStorage?: SessionStorage;
  /** Handler for errors raised during asynchronous authentication flow
   *  processing (callback, refresh, etc.) */
  onError?: (error: AuthorizaError) => void;
}
```

## API

### `createAuthoriza(config): Authoriza`

Creates a client instance. Creation is synchronous with no network requests.

### `auth.login(options?)`

Starts the authentication flow. Redirects the browser to Authoriza.

```ts
await auth.login();
await auth.login({ redirectAfterLoginTo: '/dashboard' });
```

`redirectAfterLoginTo` is a relative application path to navigate to after a successful login.

### `auth.logout()`

Clears the local session. Does not redirect to Authoriza.

```ts
await auth.logout();
```

### `auth.getUser()`

Returns the current user or `null`.

```ts
const user = await auth.getUser();
// { id: string; email?: string; name?: string } | null
```

### `auth.getAccessToken()`

Returns a valid access token. Automatically refreshes if the token has expired.

```ts
const token = await auth.getAccessToken();
```

Throws `AuthorizaError` with code `USER_NOT_AUTHENTICATED` if the user is not authenticated.

### `auth.getAuthState()`

Returns the current authentication state.

```ts
const state = auth.getAuthState();
// { isAuthenticated: boolean; isLoading: boolean; user: User | null }
```

### `auth.isAuthenticated`

Synchronous getter. `true` if there is an active session.

### `auth.isLoading`

Synchronous getter. `true` while the SDK is restoring the session after instance creation.

### `auth.user`

Synchronous getter. Current user or `null`.

### `auth.onAuthStateChanged(handler)` / `auth.on('authStateChanged', handler)`

Subscribes to authentication state changes. Returns an unsubscribe function.

```ts
const unsubscribe = auth.onAuthStateChanged((state) => {
  console.log(state.isAuthenticated, state.user);
});

// unsubscribe
unsubscribe();
```

## Error Handling

All SDK errors are represented by the `AuthorizaError` class with a stable `code` field:

```ts
import { createAuthoriza, isAuthorizaError } from '@authoriza/sdk';

const auth = createAuthoriza({
  clientId: 'YOUR_CLIENT_ID',
  redirectUri: 'https://example.com/auth/callback',
  onError(error) {
    switch (error.code) {
      case 'INVALID_STATE':
        // callback substitution detected
        break;
      case 'TOKEN_EXCHANGE_FAILED':
        // code-to-token exchange failed
        break;
      case 'TOKEN_REFRESH_FAILED':
        // access token refresh failed
        break;
      default:
        // other error
        break;
    }
  },
});

// Errors from sync/promise methods:
try {
  await auth.getAccessToken();
} catch (error) {
  if (isAuthorizaError(error)) {
    console.error(error.code, error.message);
  }
}
```

### Error Codes

| Code                           | Description                                   |
|--------------------------------|-----------------------------------------------|
| `INVALID_CONFIG`               | Invalid SDK configuration                     |
| `DISCOVERY_FAILED`             | OIDC Discovery failed                         |
| `NETWORK_ERROR`                | Network request failed                        |
| `AUTH_FLOW_IN_PROGRESS`        | An authentication flow is already in progress |
| `INVALID_STATE`                | OAuth state mismatch                          |
| `AUTHORIZATION_ERROR`          | Authorization server returned an error        |
| `TOKEN_EXCHANGE_FAILED`        | Authorization code exchange for tokens failed |
| `TOKEN_REFRESH_FAILED`         | Access token refresh failed                   |
| `USER_NOT_AUTHENTICATED`       | User is not authenticated                     |
| `INVALID_SESSION`              | Session is invalid                            |
| `STORAGE_ERROR`                | Session storage operation failed              |
| `USER_CANCELLED`               | User cancelled the authorization              |
| `INVALID_REDIRECT_AFTER_LOGIN` | Invalid `redirectAfterLoginTo` value          |
| `INVALID_NONCE`                | ID Token nonce mismatch                       |
| `UNSUPPORTED_TOKEN_TYPE`       | Unsupported token type                        |

## Custom Session Storage

```ts
import { createAuthoriza, type SessionStorage } from '@authoriza/sdk';

const storage: SessionStorage = {
  async get() { /* return Session | null */ },
  async set(session) { /* persist session */ },
  async clear() { /* remove session */ },
};

const auth = createAuthoriza({
  clientId: 'YOUR_CLIENT_ID',
  redirectUri: 'https://example.com/auth/callback',
  sessionStorage: storage,
});
```

## Callback Handling

Create an SDK instance on the page specified in `redirectUri` — the SDK will detect that the
current URL is the callback URL and automatically handle the response. The instance can be
created on any page of the application.

```ts
// On the page https://example.com/auth/callback
const auth = createAuthoriza({
  clientId: 'YOUR_CLIENT_ID',
  redirectUri: 'https://example.com/auth/callback',
});
// The SDK will automatically detect the callback URL and handle the authorization code
```

No separate `handleCallback()` method is needed.

## Types

```ts
import type {
  Authoriza,
  AuthorizaConfig,
  AuthState,
  LoginOptions,
  Session,
  SessionStorage,
  User,
  AuthorizaError,
  AuthorizaErrorCode,
} from '@authoriza/sdk';
```

## Compatibility

- Modern browsers: Chrome, Edge, Firefox, Safari
- ESM only
- TypeScript types included
- SSR-safe (import and instance creation do not require browser globals)

## License

MIT
