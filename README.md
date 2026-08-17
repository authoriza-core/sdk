# @authoriza/sdk

[README in English](./README.en.md)

Framework-agnostic OIDC SDK для [Авторизы](https://authoriza.ru). Реализует Authorization
Code Flow с PKCE для браузерных приложений.

## Возможности

- Вход, выход, восстановление сессии после перезагрузки страницы
- Автоматическое обновление access token с защитой от параллельных запросов
- Автоматическая обработка OIDC callback
- Межвкладочная синхронизация состояния
- Полные TypeScript-типы
- Нулевые runtime-зависимости
- SSR-safe импорт и создание экземпляра

## Установка

```bash
npm install @authoriza/sdk
```

## Быстрый старт

```ts
import { createAuthoriza } from '@authoriza/sdk';

const auth = createAuthoriza({
  clientId: 'YOUR_CLIENT_ID',
  redirectUri: 'https://example.com/auth/callback',
});

// Проверка состояния
auth.isAuthenticated; // boolean
auth.user;            // User | null
auth.isLoading;       // boolean

// Вход
await auth.login({ redirectAfterLoginTo: '/dashboard' });

// Получение access token для API-запросов
const token = await auth.getAccessToken();

// Выход (локальный)
await auth.logout();
```

## Конфигурация

```ts
interface AuthorizaConfig {
  /** Обязательный идентификатор frontend-приложения,
   *  зарегистрированного в Авторизе */
  clientId: string;
  /** Обязательный технический OIDC callback URL. Не является адресом,
   *  куда пользователь попадает после входа */
  redirectUri: string;
  /** URL OIDC-сервера.
   *  По умолчанию — production Авторизы: https://oidc.authoriza.ru/oidc */
  issuer?: string;
  /** Массив scopes. `openid` добавляется автоматически.
   *  По умолчанию — ['openid', 'profile', 'email', 'offline_access'] */
  scope?: string[];
  /** Пользовательская реализация хранилища сессии.
   *  По умолчанию — `localStorage` */
  sessionStorage?: SessionStorage;
  /** Обработчик ошибок, возникающих при асинхронной обработке
   *  authentication flow (callback, refresh и т. д.) */
  onError?: (error: AuthorizaError) => void;
}
```

## API

### `createAuthoriza(config): Authoriza`

Создаёт экземпляр клиента. Создание синхронное, без сетевых запросов.

### `auth.login(options?)`

Запускает authentication flow. Перенаправляет браузер на Авторизу.

```ts
await auth.login();
await auth.login({ redirectAfterLoginTo: '/dashboard' });
```

`redirectAfterLoginTo` — относительный путь приложения, на который будет перенаправлен
пользователь после успешного входа.

### `auth.logout()`

Удаляет локальную сессию. Не выполняет redirect на Авторизу.

```ts
await auth.logout();
```

### `auth.getUser()`

Возвращает текущего пользователя или `null`.

```ts
const user = await auth.getUser();
// { id: string; email?: string; name?: string } | null
```

### `auth.getAccessToken()`

Возвращает действующий access token. Если токен истёк — автоматически выполняет refresh.

```ts
const token = await auth.getAccessToken();
```

Если пользователь не авторизован, выбрасывает `AuthorizaError` с кодом `USER_NOT_AUTHENTICATED`.

### `auth.getAuthState()`

Возвращает текущее состояние авторизации.

```ts
const state = auth.getAuthState();
// { isAuthenticated: boolean; isLoading: boolean; user: User | null }
```

### `auth.isAuthenticated`

`true`, если есть действующая сессия.

### `auth.isLoading`

`true`, пока SDK восстанавливает сессию после создания экземпляра.

### `auth.user`

Текущий пользователь или `null`.

### `auth.onAuthStateChanged(handler)` / `auth.on('authStateChanged', handler)`

Подписка на изменение состояния авторизации. Возвращает функцию отписки.

```ts
const unsubscribe = auth.onAuthStateChanged((state) => {
  console.log(state.isAuthenticated, state.user);
});

// отписка
unsubscribe();
```

## Обработка ошибок

Все ошибки SDK представлены классом `AuthorizaError` со стабильным полем `code`:

```ts
import { createAuthoriza, isAuthorizaError } from '@authoriza/sdk';

const auth = createAuthoriza({
  clientId: 'YOUR_CLIENT_ID',
  redirectUri: 'https://example.com/auth/callback',
  onError(error) {
    switch (error.code) {
      case 'INVALID_STATE':
        // подмена callback
        break;
      case 'TOKEN_EXCHANGE_FAILED':
        // ошибка обмена кода на токены
        break;
      case 'TOKEN_REFRESH_FAILED':
        // не удалось обновить access token
        break;
      default:
        // другая ошибка
        break;
    }
  },
});

// Ошибки синхронных/проmise-методов:
try {
  await auth.getAccessToken();
} catch (error) {
  if (isAuthorizaError(error)) {
    console.error(error.code, error.message);
  }
}
```

### Коды ошибок

| Код                            | Описание                                     |
|--------------------------------|----------------------------------------------|
| `INVALID_CONFIG`               | Некорректная конфигурация SDK                |
| `DISCOVERY_FAILED`             | OIDC Discovery завершился ошибкой            |
| `NETWORK_ERROR`                | Ошибка сетевого запроса                      |
| `AUTH_FLOW_IN_PROGRESS`        | Authentication flow уже выполняется          |
| `INVALID_STATE`                | Несоответствие OAuth state                   |
| `AUTHORIZATION_ERROR`          | Сервер авторизации вернул ошибку             |
| `TOKEN_EXCHANGE_FAILED`        | Обмен authorization code на токены не удался |
| `TOKEN_REFRESH_FAILED`         | Обновление access token не удалось           |
| `USER_NOT_AUTHENTICATED`       | Пользователь не авторизован                  |
| `INVALID_SESSION`              | Сессия недействительна                       |
| `STORAGE_ERROR`                | Ошибка операции хранилища сессии             |
| `USER_CANCELLED`               | Пользователь отменил авторизацию             |
| `INVALID_REDIRECT_AFTER_LOGIN` | Некорректное значение `redirectAfterLoginTo` |
| `INVALID_NONCE`                | Несоответствие nonce ID Token                |
| `UNSUPPORTED_TOKEN_TYPE`       | Неподдерживаемый тип токена                  |

## Пользовательское хранилище сессии

```ts
import { createAuthoriza, type SessionStorage } from '@authoriza/sdk';

const storage: SessionStorage = {
  async get() { /* вернуть Session | null */ },
  async set(session) { /* сохранить сессию */ },
  async clear() { /* удалить сессию */ },
};

const auth = createAuthoriza({
  clientId: 'YOUR_CLIENT_ID',
  redirectUri: 'https://example.com/auth/callback',
  sessionStorage: storage,
});
```

## Обработка callback

Создайте экземпляр SDK на странице, указанной в `redirectUri`, — SDK определит, что текущий
URL является callback URL, и автоматически обработает ответ. Экземпляр при этом можно
создавать на любой странице приложения.

```ts
// На странице https://example.com/auth/callback
const auth = createAuthoriza({
  clientId: 'YOUR_CLIENT_ID',
  redirectUri: 'https://example.com/auth/callback',
});
// SDK автоматически определит callback URL и обработает authorization code
```

Отдельный метод `handleCallback()` не требуется.

## Типы

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

## Совместимость

- Современные браузеры: Chrome, Edge, Firefox, Safari
- ESM-only
- TypeScript types включены
- SSR-safe (импорт и создание экземпляра не требуют browser globals)

## Лицензия

MIT
