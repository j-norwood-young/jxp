# API keys

API keys are long-lived credentials for services and scripts. Create them through the authenticated docs browser or your application's own key-management endpoint. The raw value is shown only at creation time.

Send a key in a header:

```http
X-API-Key: jxp_...
```

Never put an API key in a query parameter. JXP 6 rejects `?apikey=` and explains how to migrate.

## Permissions

An API key can either inherit the user's permissions or have an explicit per-model CRUD scope:

```json
{
  "reader": "ru",
  "segment": "crud"
}
```

With no scopes, the key inherits the user's current permissions, including permissions for models added later. Once any scope is present, the key is deny-by-default: models not listed have no access. A scope can only narrow the user's permissions; it cannot grant more than the user already has.

The letters mean:

- `c` — create
- `r` — read
- `u` — update
- `d` — delete

Keys can also disable administrator privileges with `allow_admin: false`, expire at a specified time, and be revoked immediately.

Models whose schema grants unauthenticated access through `perms.all` remain public regardless of API key scopes.

## Dual-running JXP 5 and JXP 6

`jxp-migrate-apikeys` backfills a keyed hash and display metadata without changing the legacy `apikey` field. The same key therefore continues to authenticate against both versions. The migration also removes the one-key-per-user index and makes the legacy plaintext index sparse so JXP 6 can create multiple hash-only keys.

During dual-run, keep at least one migrated legacy key for every user that must still log in through JXP 5. JXP 5 cannot use a newly created hash-only key, and its login endpoint may select the newest key if all legacy keys for that user have been revoked.

While plaintext values remain, JXP prints a startup warning. To suppress it temporarily during a planned dual-run, set `APIKEY_LEGACY_DUAL_RUN=true`.

After every JXP 5 server is retired:

1. Run `npx jxp-purge-legacy-apikeys` to review the dry-run count.
2. Optionally use `--stale-only --days=90` to remove old values first.
3. Run `npx jxp-purge-legacy-apikeys --confirm`.

The purge refuses to run if any key has not been migrated.
