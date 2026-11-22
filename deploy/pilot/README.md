# Zekvar Control TLS pilot

This single-host deployment uses Caddy as the HTTPS entry point for two DNS names. The dashboard accepts connections from the configured administrator networks. The browser API exposes enrollment, browser reporting and policy routes, plus a readiness endpoint. Control's administrative API stays on loopback. PostgreSQL has a private network and a separate non-superuser role for the application.

## Set up the host

1. Choose distinct DNS hostnames for the dashboard and browser API and point both at the pilot host. Open ports 80 and 443 for Caddy. Put Caddy directly behind the network edge so its administrator allowlist evaluates the actual client IP.
2. From the repo root, run `umask 077` and copy `deploy/pilot/.env.example` to `deploy/pilot/.env`. Set the two hostnames, ACME contact, organization slug and administrator source CIDRs. Use the administrator's stable public egress address or VPN network. Generate a distinct value for each of the three empty secrets with `openssl rand -hex 32`.
3. Validate the Compose inputs without printing their values, then start the services.

```sh
docker compose --env-file deploy/pilot/.env -f deploy/pilot/compose.yaml config --quiet
docker compose --env-file deploy/pilot/.env -f deploy/pilot/compose.yaml up -d --build
```

4. Open the dashboard over HTTPS from an allowed network. Use the configured owner token to sign in and issue named Control credentials for pilot administrators. Verify `GET https://<browser-host>/health` from a managed device before enrolling it.

Caddy obtains certificates for public DNS names and keeps them in its data volume. The Compose network namespace holds the loopback listeners for the dashboard and API. Its database service listens only on the private database network. The initialization script creates the database-owner application role on a fresh PostgreSQL volume. [Caddy automatic HTTPS](https://caddyserver.com/docs/automatic-https) · [Docker Compose services](https://docs.docker.com/reference/compose-file/services/#network_mode)

## Configure Control single sign-on

1. Register a confidential OpenID Connect web application for the pilot organization. Register the exact HTTPS redirect URI `https://<dashboard-host>/auth/sso/callback`. Enable authorization code flow with PKCE S256, query responses, and RS256-signed ID tokens. Set sign-in and MFA requirements at the identity provider.
2. Set `ZEKVAR_OIDC_ISSUER` to the discovery document’s exact issuer, plus `ZEKVAR_OIDC_CLIENT_ID` and `ZEKVAR_OIDC_CLIENT_SECRET`. Set `ZEKVAR_OIDC_CLIENT_AUTH=basic` for `client_secret_basic` or `post` for `client_secret_post`. Generate `ZEKVAR_OIDC_EXCHANGE_TOKEN` with a separate `openssl rand -hex 32` and keep it in the restricted deployment secrets. Restart API and Web after changing these values.
3. Sign in to Control as the owner and open **Control access**. Add each person’s exact `sub` from this provider and app registration. Assign Administrator or Auditor and confirm they can use **Sign in with single sign-on**. Use the provider’s subject identifier for this app even when the same user has a different identifier in another app.

The pilot binds one configured issuer to one organization. The owner token remains available for recovery. Control sessions expire after an hour or at the ID token’s earlier expiry. Control sign-out ends its own session. The identity provider manages its separate session. Removing an identity in **Control access** revokes existing sessions. Disabling a user at the identity provider prevents future sign-ins according to provider policy. Revoke access in Control when an immediate cutoff is needed. Rotating the exchange token invalidates previous SSO sessions and requires updating both services. [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) · [OAuth security best practices](https://www.rfc-editor.org/rfc/rfc9700)

Run the hosted SSO lab before connecting a customer provider. It uses a disposable signed identity provider, Next.js standalone, Caddy, Chrome for Testing, the Release API, and PostgreSQL.

```sh
node scripts/verify-demo.mjs --sso --headed --artifacts /tmp/zekvar-sso
```

## Build and enroll Browser

Use the browser API hostname in the extension build and keep pilot output in its own directory.

```sh
cd apps/browser-extension
npm ci
ZEKVAR_CONTROL_ORIGIN=https://browser.example.com ZEKVAR_EXTENSION_OUTDIR=dist-pilot npm run build
```

For the pilot lab, load `dist-pilot` as an unpacked extension. Reload it from `chrome://extensions` when rebuilding in the same directory. Obtain a fresh enrollment grant from the dashboard. Managed enrollment uses both `ControlOrigin`, set to the exact browser API origin in the build, and the short-lived `EnrollmentGrant` for that profile. The popup shows the configured HTTPS destination. If the build moves to a different Control origin, enroll again with a grant from that destination. Update the managed origin and grant together.

## Back up and recover Control

Install `age` and `age-keygen` on the appropriate operator machines. Generate a recovery identity in the recovery environment with `age-keygen -o pilot-identity.txt`. Derive its public recipient with `age-keygen -y pilot-identity.txt > pilot-recipients.txt`. Store the private identity separately from the host and backup storage. Copy the public recipient file to the backup host. [age command reference](https://github.com/FiloSottile/age/blob/main/doc/age.1.ronn)

Run a daily backup from a restricted location. The host streams a consistent PostgreSQL snapshot through encryption and publishes the archive only after both commands succeed. It refuses to replace an existing file. Copy the encrypted result to access-controlled off-host storage. Record its creation time, Control release, size, checksum, and recovery key identifier in the backup job record. Check job failures and keep a retention schedule approved for the pilot's data. Store deployment configuration and secrets in the operator's secret store so they can be recovered separately. [PostgreSQL logical backup](https://www.postgresql.org/docs/18/backup-dump.html)

```sh
deploy/pilot/database-backup.sh backup zekvar-pilot deploy/pilot/.env \
  /srv/backups/zekvar/2026-11-22T0000Z.age /etc/zekvar/pilot-recipients.txt
```

Rehearse recovery using a new Compose project on an isolated host or network. Use a separate environment file, the same organization slug, and fresh owner and database credentials. Verify the archive checksum against the backup job record and use an archive from the trusted job. Start only PostgreSQL in the new project. Restore requires an empty application database. SQL failures roll back the transaction so the recovery database can be retried. [PostgreSQL restore options](https://www.postgresql.org/docs/18/app-pgrestore.html)

```sh
docker compose --project-name zekvar-recovery --env-file /secure/recovery.env \
  -f deploy/pilot/compose.yaml up -d --wait postgres
deploy/pilot/database-backup.sh restore zekvar-recovery /secure/recovery.env \
  /srv/backups/zekvar/2026-11-22T0000Z.age /secure/pilot-identity.txt
```

Restore revokes previous browser enrollments and named Control credentials, including SSO identities. It deletes SSO sessions, expires unused grants, and cancels pending policy reviews in the same transaction. This prevents an older snapshot from reactivating revoked access or leaving a browser on a newer cached policy from before the outage. Start Control with the new owner token. Issue fresh delegated tokens, reauthorize current SSO identities, and re-enroll Chrome with fresh grants. Reassign re-enrolled browsers to their rollout groups before restoring normal access.

Keep both origins on the recovery network while verifying policies, event export, enrollment, and retention. Reconcile post-backup policy changes, retention changes, and data deletions against the independent operator record before exposing the recovered environment. For an actual switch, keep the original environment offline to avoid divergent writes and measure data loss and recovery time from the backup and drill timestamps.

Run the disposable recovery drill with Bash, Docker Compose, age, .NET, Node, and Chrome for Testing available. It uses generated keys, synthetic events, and two disposable PostgreSQL databases.

```sh
npm --prefix apps/browser-extension ci
npm --prefix apps/browser-extension exec -- playwright install chromium --no-shell
node --test apps/browser-extension/test/database-backup.test.mjs
```

## Verify the deployment

The hosted verifier builds the standalone dashboard and Release API, then exercises real TLS, managed enrollment, publishing, and enforcement from an isolated Chrome profile. The verifier needs Docker for its disposable database, plus Caddy and OpenSSL on the host. It uses a test certificate and leaves the system trust store alone.

```sh
node scripts/verify-demo.mjs --hosted --headed --artifacts /tmp/zekvar-hosted
```

For a customer rollout, verify certificate issuance and renewal on the intended host, browser distribution through customer management, database backup and restore, monitoring, incident response, and identity requirements. Restarting the single dashboard process expires its active sessions. Keep the database and Caddy data volumes when updating services. [Zekvar hosted pilot gates](../../product_plan.md#delivery-roadmap)
