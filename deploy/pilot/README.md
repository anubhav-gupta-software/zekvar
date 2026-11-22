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

## Build and enroll Browser

Use the browser API hostname in the extension build and keep pilot output in its own directory.

```sh
cd apps/browser-extension
npm ci
ZEKVAR_CONTROL_ORIGIN=https://browser.example.com ZEKVAR_EXTENSION_OUTDIR=dist-pilot npm run build
```

For the pilot lab, load `dist-pilot` as an unpacked extension. Reload it from `chrome://extensions` when rebuilding in the same directory. Obtain a fresh enrollment grant from the dashboard. Managed enrollment uses both `ControlOrigin`, set to the exact browser API origin in the build, and the short-lived `EnrollmentGrant` for that profile. The popup shows the configured HTTPS destination. If the build moves to a different Control origin, enroll again with a grant from that destination. Update the managed origin and grant together.

## Verify the deployment

The hosted verifier builds the standalone dashboard and Release API, then exercises real TLS, managed enrollment, publishing, and enforcement from an isolated Chrome profile. The verifier needs Docker for its disposable database, plus Caddy and OpenSSL on the host. It uses a test certificate and leaves the system trust store alone.

```sh
node scripts/verify-demo.mjs --hosted --headed --artifacts /tmp/zekvar-hosted
```

For a customer rollout, verify certificate issuance and renewal on the intended host, browser distribution through customer management, database backup and restore, monitoring, incident response, and identity requirements. Restarting the single dashboard process expires its active sessions. Keep the database and Caddy data volumes when updating services. [Zekvar hosted pilot gates](../../product_plan.md#delivery-roadmap)
