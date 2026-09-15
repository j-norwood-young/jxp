# Authentication

There are three ways of authenticating API requests:

* A Bearer Token
* An API Key
* A Javascript Web Token (JWT)

We always use `email` and `password` to identify the user. Passwords are one-way encrypted using bcrypt.

In a typical application, your front-end site would present a login page asking for the user's email and password. In addition, you would present a "Forgotten Password" link.

When the user submits their username and password, you would POST that data to the `/login` endpoint. If the login succeeds, the response includes bearer tokens. API keys are created and managed separately and are never returned by login.

## Login endpoints

### Login

Logging in will always delete the previous token and give you a new one.

POST `http://localhost:4001/login`

Data:

```json
{
    "email": "blah@blah.com",
    "password": "TopSecret"
}
```

Successful Response (Status 200):

```json
{
    "user_id": "5dadbd7e2384ad419975e4a1",
    "token": "<token>",
    "token_expires": "2025-11-21T21:26:20.671Z",
    "refresh_token": "<refresh_token>",
    "refresh_token_expires": "2025-12-21T21:26:20.671Z"
}
```

Failed Response (Status 401):

```json
{
    "status": "fail",
    "message": "Authentication failed",
    "err": "Incorrect email; email: <email>"
}
```

### Refresh Token

You can use your refresh_token to refresh a token, even if it's expired. By default, refresh tokens last 30 days, whereas tokens last 24 hours (configurable via `REFRESH_TOKEN_EXPIRY` and `TOKEN_EXPIRY`).

Note that the response is almost identical to the `/login` endpoint, except it doesn't have the `apikey`.

POST `http://localhost:4001/refresh`

Header:

```json
{
    "Authorization": "Bearer <refresh token>"
}
```

Successful Response (Status 200):

```json
{
    "user_id": "5dadbd7e2384ad419975e4a1",
    "token": "<token>",
    "token_expires": "2025-11-21T21:26:20.671Z",
    "refresh_token": "<refresh_token>",
    "refresh_token_expires": "2025-12-21T21:26:20.671Z"
}
```

Failed Response (Status 401):

```json
{
    "status": "fail",
    "message": "Authentication failed",
    "err": "Incorrect email; email: <email>"
}
```

### Logout

This will immediately expire the token. You must be authenticated (Bearer token or other method).

GET `http://localhost:4001/login/logout`

GET `http://localhost:4001/logout`

Successful Response (200):

```json
{
    "status": "ok",
    "message": "User logged out"
}
```

### Recover Password

Send the user an email with a JWT embedded so that they can reset their password. Requires SMTP settings on the `JXP()` config object (see [Configuration](configuration.md#smtp-and-password-recovery)).

POST `http://localhost:4001/login/recover`

Data:

```json
{
    "email": "blah@blah.com"
}
```

Successful Response (200):

```json
{
    "status": "ok",
    "message": "Sent recovery email"
}
```

Failed responses include 400 (missing email), 404 (user not found), or 401/500 depending on configuration errors.

***Note:*** You will still have to build the password reset page on your front end. The recovery link uses `password_recovery_url` from config plus the JWT token.

### JWT

A Javascript Web Token can be used to log the user in through a URL.

POST `http://localhost:4001/login/getjwt`

Data:

```json
{
    "email": "blah@blah.com"
}
```

Successful Response (200):

```json
{
    "status": "ok",
    "jwt": "<jwt>"
}
```

Failed Response (403 or 404):

```json
{
    "status": "fail",
    "message": "Unauthorized",
    "err": "Could not find email"
}
```

### OAuth2

OAuth login is configured programmatically (see [Configuration](configuration.md#oauth)).

- `GET /login/oauth/:provider` — redirects to the provider's authorization URL
- `GET /login/oauth/callback/:provider` — handles the callback and redirects to `oauth.success_uri` or `oauth.fail_uri` with a token or error

The provider name (`:provider`) must match a key under `oauth` in your config (excluding `success_uri` and `fail_uri`).

## Authenticating API requests

HTTP Basic Auth (`Authorization: Basic …`) is not supported. It only base64-encodes the password and is too easy to leak or replay. Use a bearer token or an API key instead.

### Bearer Token

_This is the preferred method of authenticating._

Bearer tokens are ephemeral tokens that will expire after a configured period. When a user logs out of a session, they are revoked.

Header: `Authorization: Bearer <your bearer token>`

### API Key

API keys are managed independently from login and can have an expiry, revocation state, and per-model CRUD permissions. They must be sent in the `X-API-Key` header:

```
X-API-Key: <apikey>
```

API keys in query parameters are rejected. This prevents credentials from leaking through access logs, browser history, Referer headers, caches, and monitoring systems. Upgrade `jxp-helper` to v3 for automatic header-based requests.

## Multi-factor authentication (TOTP)

Clients build their own enrollment and login UI. JXP exposes REST endpoints only.

Interactive password login (`POST /login` and docs `POST /docs/session`) requires a second factor when the user has TOTP enabled. Passkeys are passwordless only (see below) and are not offered as MFA after password. **API keys do not go through the MFA challenge** (machine credentials).

The docs browser includes Account → Settings for password change, TOTP, and passkeys (uses the ephemeral console API key), plus a **Login with Passkey** button on the sign-in page.

### Change password

```http
POST /login/password
Authorization: Bearer <token>
Content-Type: application/json

{ "current_password": "…", "new_password": "…" }
```

`new_password` must be at least 8 characters. X-API-Key auth also works.

### Enroll TOTP

All enrollment routes require a Bearer token.

1. `POST /login/totp/setup` — returns `{ secret, otpauth_url, qr_data_url, backup_codes }` once. Show `qr_data_url` as an `<img src>` (or generate a QR from `otpauth_url`). Store backup codes securely; they are not shown again.
2. `POST /login/totp/confirm` with `{ "code": "123456" }` — enables TOTP after the authenticator app confirms. Confirmation accepts only a live 6-digit code.
3. `GET /login/totp/status` — `{ "enabled": true|false }`
4. `POST /login/totp/disable` with `{ "code": "..." }` — TOTP or unused backup code.

YubiKey OATH-TOTP works through [Yubico Authenticator](https://www.yubico.com/products/yubico-authenticator/) by scanning the same QR / `otpauth_url`. For YubiKey as a FIDO2 hardware key, use the passkey endpoints instead.

### Login with TOTP

```http
POST /login
Content-Type: application/json

{ "email": "user@example.com", "password": "…" }
```

If MFA is required:

```json
{
  "status": "mfa_required",
  "challenge": "<jwt>",
  "methods": ["totp"]
}
```

Complete with:

```http
POST /login/mfa
Content-Type: application/json

{ "method": "totp", "challenge": "<jwt>", "code": "123456" }
```

Success returns the same token pair as a normal login.

### Browser example (TOTP login)

```javascript
async function loginWithTotp(email, password, getCodeFromUser) {
  const step1 = await fetch("/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  }).then((r) => r.json());

  if (step1.status !== "mfa_required") return step1;

  const code = await getCodeFromUser(); // prompt for authenticator / backup code
  return fetch("/login/mfa", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      method: "totp",
      challenge: step1.challenge,
      code,
    }),
  }).then((r) => r.json());
}
```

## Passkeys (WebAuthn)

Configure `webauthn.rp_id` and `webauthn.origins` to match your front-end origin (see [Configuration](configuration.md#mfa-and-passkeys)).

### Register a passkey (authenticated)

```javascript
async function registerPasskey(accessToken, name = "Passkey") {
  const { options, challenge_token } = await fetch("/login/webauthn/register/options", {
    method: "POST",
    headers: { Authorization: `Bearer ${accessToken}` },
  }).then((r) => r.json());

  const credential = await navigator.credentials.create({
    publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options),
  });

  return fetch("/login/webauthn/register/verify", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      challenge_token,
      name,
      response: credential.toJSON(),
    }),
  }).then((r) => r.json());
}
```

If `parseCreationOptionsFromJSON` / `toJSON` are unavailable, convert ArrayBuffers to base64url yourself (or use `@simplewebauthn/browser`).

List / delete:

- `GET /login/webauthn/credentials`
- `DELETE /login/webauthn/credentials/:id` — body `{ "password": "…" }` required when deleting the last passkey and TOTP is off

### Passwordless login

Passkeys are **passwordless only** — they are not a second factor after password. Use a dedicated “Login with Passkey” control (or call the endpoints below). After password, MFA is TOTP (authenticator / backup codes) only.

```javascript
async function loginWithPasskey(email) {
  const { options, challenge_token } = await fetch("/login/webauthn/options", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }), // optional; helps discoverability
  }).then((r) => r.json());

  const assertion = await navigator.credentials.get({
    publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options),
  });

  return fetch("/login/webauthn/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      challenge_token,
      response: assertion.toJSON(),
    }),
  }).then((r) => r.json());
}
```

Docs UI session equivalents: `POST /docs/session/webauthn/options` and `POST /docs/session/webauthn/verify` (same body shape; establishes the cookie session + console key).

### Apps that override `user_model`

If your app ships its own `user_model.js`, include the TOTP fields (`totp_enabled`, `totp_secret_enc`, `totp_pending_secret_enc`, `totp_backup_hashes`) when adopting MFA, or keep the built-in User model.
