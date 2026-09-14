# Upgrading to JXP 6

JXP 6 removes API keys from query parameters and adds multi-key management. It is a major version because `/login` no longer returns an API key and `?apikey=` is rejected.

## Recommended staged rollout

1. Set a stable `APIKEY_PEPPER` on every server. Do not use a value committed to source control.
2. Run `npx jxp-migrate-apikeys` against the shared database. This is additive: legacy plaintext `apikey` values are preserved.
3. Deploy JXP 6 alongside JXP 5. Existing keys work against both versions while the old servers remain live.
4. Update clients to send `X-API-Key`, or upgrade to `jxp-helper` 3.
5. Retire JXP 5 servers, then run `npx jxp-purge-legacy-apikeys --confirm`.

JXP 6 warns at startup while legacy plaintext values remain. The purge command is deliberately separate and refuses to run if migration left any key without a hash.

Do not revoke the last migrated legacy key for a user while JXP 5 is still live. JXP 5 cannot authenticate a new hash-only key.

## Client changes

Replace:

```http
GET /api/user?apikey=...
```

with:

```http
GET /api/user
X-API-Key: jxp_...
```

Use bearer authentication for interactive sessions:

```http
Authorization: Bearer <token>
```

API keys created with scopes are deny-by-default. Unscoped keys inherit the user's permissions.
