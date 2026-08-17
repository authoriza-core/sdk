# API Авторизы: контракт для frontend SDK

Документ описывает API Авторизы, которое используется `@authoriza/sdk` для реализации browser authentication flow.

Документ является техническим контрактом между SDK и серверной частью Авторизы.

SDK должен реализовывать только те возможности API, которые явно описаны в этом документе.

Наличие дополнительных возможностей в OIDC Discovery не означает, что SDK должен их поддерживать.

---

## 1. Общая модель

Авториза предоставляет стандартный OpenID Connect API.

Frontend SDK использует:

- OIDC Discovery;
- Authorization Code Flow;
- PKCE;
- ID Token;
- Refresh Token.

SDK является public client.

`client_secret` в frontend SDK не используется.

Защита authorization code flow обеспечивается PKCE с методом:

```text
S256
```

---

# 2. OIDC Issuer

Issuer Авторизы по умолчанию:

```text
https://oidc.authoriza.ru/oidc
```

SDK должен позволять переопределить issuer через конфигурацию.

Другие OIDC endpoints не задаются пользователем SDK отдельно.

Все endpoints должны определяться через OIDC Discovery.

---

# 3. OIDC Discovery

SDK должен получить OIDC configuration через стандартный Discovery endpoint.

Для default issuer:

```http
GET https://oidc.authoriza.ru/oidc/.well-known/openid-configuration
```

Ожидаемый Discovery document:

```json
{
  "authorization_endpoint": "https://oidc.authoriza.ru/oidc/auth",
  "issuer": "https://oidc.authoriza.ru/oidc",
  "jwks_uri": "https://oidc.authoriza.ru/oidc/jwks",
  "token_endpoint": "https://oidc.authoriza.ru/oidc/token",
  "userinfo_endpoint": "https://oidc.authoriza.ru/oidc/me"
}
```

Полный актуальный Discovery document Авторизы также содержит дополнительные endpoints и capabilities, однако первая версия SDK их не использует.

SDK должен использовать как минимум следующие поля:

```text
issuer
authorization_endpoint
token_endpoint
jwks_uri
```

Если обязательное поле отсутствует в Discovery response, SDK должен считать OIDC configuration некорректной и завершить authentication operation ошибкой.

---

# 4. Authorization Endpoint

Authorization endpoint по default issuer:

```http
GET https://oidc.authoriza.ru/oidc/auth
```

SDK должен перенаправлять браузер на authorization endpoint.

Для Authorization Code Flow SDK должен передавать следующие параметры:

```text
client_id
redirect_uri
response_type
scope
state
nonce
code_challenge
code_challenge_method
```

Значения:

```text
response_type=code
code_challenge_method=S256
```

Пример итогового authorization request:

```text
https://oidc.authoriza.ru/oidc/auth
  ?client_id=...
  &redirect_uri=...
  &response_type=code
  &scope=openid%20profile%20email%20offline_access
  &state=...
  &nonce=...
  &code_challenge=...
  &code_challenge_method=S256
```

SDK должен корректно URL-encode все параметры.

---

# 5. Client ID

`client_id` является идентификатором frontend application, зарегистрированным в Авторизе.

SDK получает `clientId` из конфигурации:

```ts
createAuthoriza({
  clientId: '...',
  ...
});
```

`client_id` передаётся:

* в authorization request;
* в token exchange;
* в refresh token request.

Frontend SDK не использует `client_secret`.

---

# 6. Redirect URI

`redirect_uri` является техническим OIDC callback URL.

Он передаётся SDK в конфигурации:

```ts
createAuthoriza({
  clientId: '...',
  redirectUri: 'https://example.com/auth/callback',
});
```

Один и тот же `redirect_uri` должен использоваться:

1. при authorization request;
2. при token exchange.

`redirect_uri` не является адресом, куда пользователь должен попасть после успешной авторизации.

Для этого используется отдельный параметр SDK:

```text
redirectAfterLoginTo
```

API Авторизы не знает о `redirectAfterLoginTo`.

---

# 7. Authorization Code

После успешной авторизации Авториза возвращает браузер на `redirect_uri`.

При успешном flow callback содержит:

```text
code
state
```

Пример:

```text
https://example.com/auth/callback?code=...&state=...
```

SDK должен:

1. получить `code`;
2. получить `state`;
3. сопоставить `state` с временным authentication flow;
4. выполнить token exchange.

Authorization code является одноразовым.

SDK не должен пытаться повторно использовать уже обменённый authorization code.

---

# 8. Authorization Error

Если пользователь или authorization server не завершил авторизацию успешно, callback может содержать стандартные OAuth error parameters.

Например:

```text
https://example.com/auth/callback
  ?error=access_denied
  &error_description=...
  &state=...
```

SDK должен обрабатывать стандартный OAuth error response.

Если callback содержит `state`, SDK должен использовать его для сопоставления с активным authentication flow.

Ошибка authorization endpoint должна передаваться через общий error handler SDK.

Список конкретных OAuth error codes соответствует стандартному поведению используемого `oidc-provider`.

SDK не должен зависеть от наличия только одного конкретного error code.

---

# 9. OAuth State

`state` генерируется SDK для каждого нового authentication flow.

`state` используется для защиты callback от подмены authentication flow.

SDK должен:

1. сгенерировать криптографически случайный `state`;
2. сохранить его во временном `AuthFlow`;
3. передать его в authorization request;
4. получить его из callback;
5. сравнить callback state с сохранённым значением;
6. продолжить authentication flow только при успешном совпадении.

При несовпадении SDK не должен выполнять token exchange.

Такая ошибка должна передаваться как:

```text
INVALID_STATE
```

---

# 10. Nonce

SDK должен генерировать криптографически случайный `nonce`.

`nonce` передаётся в authorization request и сохраняется во временном `AuthFlow`.

После получения ID Token SDK должен проверить соответствие:

```text
ID Token nonce
        ===
AuthFlow nonce
```

При отсутствии или несовпадении nonce SDK должен отклонить authentication flow.

Token exchange и создание сессии не должны считаться успешными при невалидном nonce.

---

# 11. PKCE

SDK должен использовать PKCE.

Поддерживаемый authorization server метод:

```text
S256
```

Для каждого authentication flow SDK должен создать:

```text
codeVerifier
codeChallenge
```

`codeChallenge` вычисляется из `codeVerifier` согласно RFC 7636 с использованием SHA-256 и Base64URL encoding.

Authorization request:

```text
code_challenge=<codeChallenge>
code_challenge_method=S256
```

Во время token exchange SDK передаёт исходный:

```text
code_verifier=<codeVerifier>
```

`codeVerifier` не должен передаваться authorization endpoint.

---

# 12. Token Endpoint

Token endpoint:

```http
POST https://oidc.authoriza.ru/oidc/token
```

SDK должен использовать:

```http
Content-Type: application/x-www-form-urlencoded
```

Frontend SDK использует token endpoint без client authentication.

Для frontend public client используется:

```text
token_endpoint_auth_method=none
```

`client_secret` не передаётся.

---

# 13. Authorization Code Token Exchange

После получения authorization code SDK выполняет:

```http
POST {token_endpoint}
```

с form-urlencoded параметрами:

```text
client_id
grant_type
code
redirect_uri
code_verifier
```

Значения:

```text
grant_type=authorization_code
```

Пример:

```text
client_id=CLIENT_ID
grant_type=authorization_code
code=AUTHORIZATION_CODE
redirect_uri=https://example.com/auth/callback
code_verifier=CODE_VERIFIER
```

SDK должен отправить `redirect_uri`, совпадающий с тем, который использовался в authorization request.

---

# 14. Token Response

При успешном token exchange Авториза возвращает стандартный OAuth/OIDC token response.

Минимально SDK должен учитывать:

```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "...",
  "id_token": "..."
}
```

Поля:

```text
access_token
token_type
expires_in
refresh_token
id_token
```

SDK должен корректно обрабатывать стандартный token response.

`refresh_token` ожидается при использовании:

```text
offline_access
```

---

# 15. Access Token

`access_token` используется SDK как credential для доступа к защищённым API.

SDK должен хранить access token в пользовательской сессии.

Access token не должен передаваться через URL.

SDK не должен самостоятельно декодировать access token для получения данных пользователя.

---

# 16. Refresh Token

Для обновления access token SDK использует тот же:

```text
token_endpoint
```

Запрос:

```http
POST {token_endpoint}
Content-Type: application/x-www-form-urlencoded
```

Параметры:

```text
client_id
grant_type
refresh_token
```

Значение:

```text
grant_type=refresh_token
```

Пример:

```text
client_id=CLIENT_ID
grant_type=refresh_token
refresh_token=REFRESH_TOKEN
```

Frontend SDK не передаёт `client_secret`.

---

# 17. Refresh Token Rotation

В текущей конфигурации Авториза может возвращать тот же refresh token после refresh.

Однако API должно считаться совместимым с refresh token rotation.

В будущем настройки client могут привести к выдаче нового refresh token.

Поэтому SDK должен обрабатывать оба варианта:

### Вариант 1

Token response содержит новый `refresh_token`.

SDK должен заменить сохранённый refresh token новым.

### Вариант 2

Token response не содержит новый `refresh_token`.

SDK должен продолжить использовать ранее сохранённый refresh token.

SDK не должен предполагать, что refresh token всегда неизменяем.

---

# 18. Истечение Access Token

Token response содержит:

```text
expires_in
```

SDK должен вычислять абсолютный момент истечения access token:

```text
expiresAt = receivedAt + expiresIn
```

где:

```text
receivedAt
```

— момент получения token response SDK.

`expiresAt` используется внутренним механизмом session/refresh.

---

# 19. Refresh после истечения Refresh Token

Если refresh token больше недействителен или истёк, refresh operation не должен пытаться бесконечно повторяться.

SDK должен считать пользовательскую сессию недействительной.

Публичный метод получения access token в этом случае должен вернуть:

```text
null
```

если refresh token недействителен/истёк.

Технический сбой refresh operation должен отличаться от штатной ситуации истёкшей сессии.

При технической ошибке SDK должен выбросить соответствующий `AuthorizaError`.

---

# 20. ID Token

ID Token является JWT.

SDK должен валидировать ID Token перед созданием пользовательской сессии.

SDK должен проверять как минимум:

```text
signature
iss
aud
exp
nonce
```

Подпись должна проверяться по ключам из:

```text
jwks_uri
```

Для default issuer:

```text
https://oidc.authoriza.ru/oidc/jwks
```

SDK не должен доверять claims ID Token до успешной проверки подписи и обязательных validation claims.

---

# 21. ID Token Signing Algorithms

Авториза сообщает следующие поддерживаемые алгоритмы подписи ID Token:

```text
PS256
RS256
ES256
```

SDK должен поддерживать алгоритмы, используемые Авторизой в соответствии с Discovery configuration.

SDK не должен без необходимости разрешать произвольные алгоритмы подписи, отсутствующие в OIDC Discovery.

---

# 22. JWKS

JWKS endpoint:

```http
GET https://oidc.authoriza.ru/oidc/jwks
```

SDK использует его для получения публичных ключей, необходимых для проверки подписи ID Token.

JWKS должен обрабатываться как стандартный JWK Set.

SDK должен учитывать rotation signing keys.

Полученные JWKS могут кэшироваться.

При обнаружении `kid`, отсутствующего в локальном наборе ключей, SDK должен иметь возможность получить актуальный JWKS повторно.

---

# 23. User Claims

Авториза поддерживает следующие claims, необходимые текущему SDK:

```text
sub
name
email
```

Также authorization server может возвращать:

```text
sid
auth_time
iss
```

SDK использует:

```text
sub
name
email
```

для формирования модели пользователя.

Модель:

```ts
interface User {
  id: string;
  email?: string;
  name?: string;
}
```

Соответствие:

```text
User.id    ← ID Token sub
User.email ← ID Token email
User.name  ← ID Token name
```

`email` и `name` являются необязательными.

Если соответствующий claim отсутствует, SDK не должен считать это ошибкой.

---

# 24. UserInfo

Discovery предоставляет:

```text
userinfo_endpoint
```

со значением:

```text
https://oidc.authoriza.ru/oidc/me
```

Однако первая версия frontend SDK не использует UserInfo endpoint.

Данные пользователя для текущей версии SDK берутся из ID Token.

SDK не должен выполнять дополнительный запрос UserInfo только для получения:

```text
sub
name
email
```

---

# 25. Scope

Авториза поддерживает:

```text
openid
profile
email
offline_access
```

Минимальный обязательный scope SDK:

```text
openid
```

Если приложение не передало `scope` в конфигурации, SDK использует набор по умолчанию:

```text
openid profile email offline_access
```

`openid` необходим для OIDC flow.

`profile` и `email` позволяют получать соответствующие claims.

`offline_access` используется для получения refresh token.

Если приложение передало `scope` в конфигурации, SDK добавляет к нему только обязательный `openid`; `profile`, `email` и `offline_access` включаются только при явной передаче приложением.

---

# 26. Endpoints, не используемые первой версией SDK

Следующие возможности присутствуют в OIDC Discovery, но не входят в текущий контракт frontend SDK:

```text
device_authorization_endpoint
pushed_authorization_request_endpoint
end_session_endpoint
revocation_endpoint
userinfo_endpoint
```

Также первая версия SDK не реализует:

```text
Device Authorization Grant
Pushed Authorization Requests
DPoP
OIDC RP-Initiated Logout
Token Revocation
UserInfo requests
```

Наличие соответствующих полей в Discovery document не должно приводить к их автоматической реализации SDK.

---

# 27. Полный authentication flow

Полный flow между SDK и Авторизой:

```text
Frontend
   │
   │ createAuthoriza()
   ▼
SDK
   │
   │ OIDC Discovery
   ▼
Авториза
   │
   │ Discovery document
   ▼
SDK
   │
   │ generate:
   │   state
   │   nonce
   │   codeVerifier
   │   codeChallenge
   ▼
Authorization Endpoint
   │
   │ client_id
   │ redirect_uri
   │ response_type=code
   │ scope
   │ state
   │ nonce
   │ code_challenge
   │ code_challenge_method=S256
   ▼
Авторизация пользователя
   │
   ▼
redirect_uri
   │
   │ code
   │ state
   ▼
SDK callback
   │
   ├── validate state
   ├── token exchange
   │
   │ POST /token
   │   grant_type=authorization_code
   │   client_id
   │   code
   │   redirect_uri
   │   code_verifier
   │
   ▼
Token Response
   │
   ├── access_token
   ├── refresh_token
   ├── id_token
   └── expires_in
   │
   ▼
SDK
   │
   ├── validate ID Token
   ├── create Session
   ├── persist Session
   ├── clear callback URL
   └── redirectAfterLoginTo
```

---

# 28. Требования к обработке API ошибок

SDK должен учитывать стандартные OAuth/OIDC ошибки, возвращаемые `node-oidc-provider`.

Для token endpoint SDK должен обрабатывать стандартный OAuth error response, например:

```json
{
  "error": "invalid_grant",
  "error_description": "..."
}
```

SDK не должен зависеть от конкретного текста `error_description`.

Для программной обработки SDK должен преобразовывать серверные ошибки в собственные стабильные `AuthorizaError.code`.

Тексты `error_description` могут использоваться как диагностическая информация, но не должны использоваться приложением как стабильный идентификатор ошибки.

---

# 29. Безопасность

SDK должен считать API Авторизы доверенным только после стандартных OIDC validation steps.

Обязательно:

* использовать HTTPS для production issuer;
* использовать PKCE S256;
* проверять OAuth state;
* проверять OIDC nonce;
* проверять подпись ID Token;
* проверять `iss`;
* проверять `aud`;
* проверять `exp`;
* не передавать токены через URL;
* не использовать client secret во frontend;
* не принимать ID Token без проверки подписи;
* не создавать сессию до завершения необходимых validation steps.

SDK не должен ослаблять security requirements authorization server ради упрощения интеграции.
