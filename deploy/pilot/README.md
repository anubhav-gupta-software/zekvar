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

### Distribute signed Browser releases

Use this path for managed devices that allow self-hosted Chrome extensions. Run the packager on Linux or macOS with a current trusted Chrome or Chrome for Testing executable. Generate an RSA signing key on a restricted signing machine. Keep the key and its recoverable backup outside the checkout and web root. Pin the resulting extension ID in your release records and device manager. Subsequent versions of the same extension require the same key. [Chrome self-hosting and update requirements](https://developer.chrome.com/docs/extensions/how-to/distribute/host-on-linux)

```sh
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out /secure/zekvar-browser.pem
node apps/browser-extension/package-pilot.mjs --print-id --key /secure/zekvar-browser.pem
```

Set `ZEKVAR_EXTENSION_ID` to the pinned ID and `CHROME_BINARY` to the absolute executable path. Start a channel with `--first`. For later builds, increase the version in `apps/browser-extension/manifest.json`, use a fresh output directory, and replace `--first` with `--previous /secure/releases/<last-release>/release.json`. The packager checks the key, extension ID, version, previous update URL, and Control origin before signing. Use the same Control origin throughout a channel. [Chrome extension version format](https://developer.chrome.com/docs/extensions/reference/manifest/version)

```sh
npm --prefix apps/browser-extension ci
npm --prefix apps/browser-extension run package:pilot -- \
  --key /secure/zekvar-browser.pem --id "$ZEKVAR_EXTENSION_ID" --chrome "$CHROME_BINARY" \
  --control-origin https://browser.example.com --update-origin https://updates.example.com \
  --channel pilot --first --output /secure/releases/pilot-0.21.0
```

1. Serve the package and `updates.xml` from the output's `public/pilot/` directory at `https://updates.example.com/pilot/`. Serve CRX files as `application/x-chrome-extension` and XML as `application/xml`. Deploy the new versioned CRX first, verify the downloaded SHA-256 against `release.json`, and replace the HTTPS `updates.xml` atomically. Keep versioned CRX files immutable and let clients revalidate `updates.xml` on every check. Keep the update path accessible to managed Chrome without browser cookies or interactive sign-in. [Chrome update manifest and hosting](https://developer.chrome.com/docs/extensions/how-to/distribute/host-on-linux#update)
2. Merge `chrome-policy.json` into the policy for the pilot device group. Its `ExtensionSettings` entry force-installs the pinned ID and keeps subsequent updates on the assigned channel. On Linux use the managed-policy JSON directory for Chrome or Chromium. macOS requires MDM, domain management, or Chrome Enterprise Core for self-hosted force install. Windows requires eligible domain or Chrome Enterprise Core management. Confirm the deployment mechanism and eligibility with the partner admin. [Chrome ExtensionSettings](https://support.google.com/chrome/a/answer/9867568) · [Chrome enterprise force-install requirements](https://chromium.googlesource.com/chromium/src/+/HEAD/components/policy/resources/templates/policy_definitions/Extensions/ExtensionInstallForcelist.yaml) · [Managed extension settings on Linux](https://www.chromium.org/administrators/configuring-policy-for-extensions/#linux)
   Use **Chrome extension deployment** in Control to review and export additional rules for the pilot group. Merge against the effective device group's `ExtensionSettings` and keep the signed Zekvar Browser entry. Apply the downloaded `ExtensionSettings` through the device manager and retain the rollback file. [Deploy Chrome extension rules](../../apps/control-web/README.md#deploy-chrome-extension-rules)
3. In Control, open **Enroll browsers in group** to generate a batch of fresh grants for the pilot. Deliver one `EnrollmentGrant` per browser profile through restricted device management, alongside the exact `ControlOrigin` from the package. Group grants require Browser v0.21.0 or later. Remove the grant from management after enrollment. Confirm the extension version in `chrome://extensions`, the assigned policy in its popup, and the installation in Control. Open **Review browser rollout** to compare release reports across the pilot group. Grant values belong in per-profile settings. The generated release contains the shared origin and distribution policy. [Enroll a rollout group](../../apps/control-web/README.md#enroll-a-rollout-group)
4. Verify an upgrade with a test device before updating the wider channel. Reload any AI tabs that were already open and confirm the active Zekvar policy before testing submissions. If Control still shows an older version after Chrome shows the upgrade, relaunch the managed browser and check for a fresh version report. An installed browser will ignore an older package version. To restore known-good extension code, rebuild that source with a higher manifest version, sign with the same key, and repeat the staged rollout. For removal, apply `installation_mode: removed` for the pinned ID, remove its managed configuration, and revoke the corresponding Control installation. If the signing key is compromised or lost, coordinate removal and enroll devices with a new extension ID after switching keys. [Chrome update and removal policies](https://support.google.com/chrome/a/answer/9867568)

The package test creates disposable signed versions without customer credentials. Run it with Chrome for Testing and `unzip` installed. Optional `ZEKVAR_SIGNED_PILOT_ARTIFACTS` saves its three signed outputs in a new directory for the Linux test. The Linux test needs a disposable VM with Chromium, Node, OpenSSL, passwordless `sudo`, and `npm ci` in the checkout. It writes one named managed browser policy file and removes it at teardown. Point `ZEKVAR_SIGNED_PILOT_API` at a disposable Control API backed by PostgreSQL and reachable on the VM's loopback address, and set `ZEKVAR_DEMO_TOKEN` to the test owner's token. The test serves the update and browser hosts through local HTTPS on port 9443. Set `ZEKVAR_DEMO_HEADED=1` with a display or Xvfb to use a browser window. Set `ZEKVAR_SIGNED_PILOT_SCREENSHOT` to save the blocked submission after the upgrade.

```sh
ZEKVAR_SIGNED_PILOT_ARTIFACTS=/tmp/zekvar-signed-test \
  node --test apps/browser-extension/test/package-pilot.test.mjs

ZEKVAR_SIGNED_PILOT_ARTIFACTS=/tmp/zekvar-signed-test \
  node --test apps/browser-extension/test/signed-pilot.test.mjs
```

## Back up and recover Control

Install `age` and `age-keygen` on the appropriate operator machines. Generate a recovery identity in the recovery environment with `age-keygen -o pilot-identity.txt`. Derive its public recipient with `age-keygen -y pilot-identity.txt > pilot-recipients.txt`. Store the private identity separately from the host and backup storage. Copy the public recipient file to the backup host. [age command reference](https://github.com/FiloSottile/age/blob/main/doc/age.1.ronn)

Run the [scheduled off-host backup](#schedule-off-host-backups) or make a manual snapshot from a restricted location. The host streams a consistent PostgreSQL snapshot through encryption and publishes the archive only after both commands succeed. It refuses to replace an existing file. For manual backups, copy the encrypted result to access-controlled off-host storage and record its creation time, Control release, size, SHA-256 checksum, and recovery key identifier. Store deployment configuration and secrets in the operator's secret store so they can be recovered separately. [PostgreSQL logical backup](https://www.postgresql.org/docs/18/backup-dump.html)

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

### Schedule off-host backups

1. Create a private, general purpose Amazon S3 bucket with a name without dots and a dedicated prefix for the pilot. Enable Block Public Access, require TLS and conditionally created objects, and choose a lifecycle policy consistent with your retention agreement. If you enable versioning, set retention for previous versions too. Use a separate backup account where available. Configure the host's writer identity to allow only `s3:PutObject` for the prefix. Give the recovery identity `s3:GetObject` for the same prefix and give independent monitoring `s3:ListBucket` restricted to that prefix. Keep the decryption identity in the recovery environment and use separate access for modifying bucket policy or retention. [S3 bucket policy examples](https://docs.aws.amazon.com/AmazonS3/latest/userguide/amazon-s3-policy-keys.html) · [Enforce conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes-enforce.html) · [S3 lifecycle expiration](https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-expire-general-considerations.html)
2. Install AWS CLI v2 with support for `put-object --if-none-match` on the Linux pilot host, alongside Bash, OpenSSL, age, and Docker Compose. Set up writer credentials for the system service, preferably using the host's workload role. Give the service a root-owned copy of the deployed scripts at `/opt/zekvar` or change `ExecStart` to match your protected install path. Copy [`backup.env.example`](systemd/backup.env.example) to `/etc/zekvar/backup.env` with mode `0600`. Set the bucket, region, owner account ID, prefix, Compose settings, release ID, and public recovery key identifier. Update the release ID on each deploy and the key identifier when rotating recipients. The encrypted scratch archive needs up to 5 GB of free space on the service's temporary filesystem. [AWS CLI configuration](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html) · [S3 upload integrity and single-upload limit](https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity-upload.html)
3. From the repository root, install the service and timer. Run the first backup and check the journal before relying on the schedule. The timer starts a job daily at 02:00 UTC and catches up a missed run after downtime. The job retries temporary storage errors and fails if S3 cannot confirm the archive's SHA-256 checksum. Forward journal records off-host so the recovery operator can retrieve the object key, checksum, size, release, key identifier, and start time after host loss. [systemd timer reference](https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html)

```sh
sudo install -m 0644 deploy/pilot/systemd/zekvar-backup.service \
  deploy/pilot/systemd/zekvar-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start zekvar-backup.service
sudo journalctl -u zekvar-backup.service -n 30
sudo systemctl enable --now zekvar-backup.timer
sudo systemctl list-timers zekvar-backup.timer
```

Set `AWS_REGION`, `ZEKVAR_BACKUP_BUCKET`, `ZEKVAR_BACKUP_BUCKET_OWNER`, and `ZEKVAR_BACKUP_PREFIX` on a separate monitor with its list-only credentials. Run `deploy/pilot/s3-backup.sh check 30` hourly and alert the operator on a nonzero exit. This checks for a nonempty archive started and stored within the last 30 hours, including when the Control host is offline. Confirm recoverability with a downloaded restore drill.

Configure the same bucket settings with the recovery identity. Fetch the chosen key and use the Base64 SHA-256 from the trusted off-host job record. The helper writes the local `.age` file only after the cloud checksum and local bytes both match the record. Continue with the isolated [restore commands](#back-up-and-recover-control).

```sh
deploy/pilot/s3-backup.sh fetch "$BACKUP_OBJECT_KEY" /secure/pilot-snapshot.age "$BACKUP_SHA256"
```

To include off-host storage in the disposable recovery drill, use AWS CLI v2 and enable the loopback S3 protocol fixture. The test uses synthetic data and makes no requests to an AWS account.

```sh
ZEKVAR_BACKUP_TEST_OFFSITE=1 ZEKVAR_BACKUP_TEST_HEADED=1 \
  node --test apps/browser-extension/test/database-backup.test.mjs
```

## Verify the deployment

Run the deployment preflight after publishing the HTTPS hosts and the signed Browser update channel. Use Node 22.14 or later and the original protected packager output as `--release-dir`. The command checks the two HTTP-to-HTTPS redirects, certificate trust, API readiness, anonymous access boundaries, and public update delivery. It compares the served manifest and CRX with the trusted release and checks that the update manifest requires revalidation. It sends anonymous GET requests and prints a JSON result. A failed check produces a nonzero exit code.

Run once from your allowed administrator network. Repeat the command with `--admin-network denied` from a separate network outside the allowlist, such as a managed test device on its usual connection. Use the same release directory on both runs. Record both results with the release before assigning the signed extension to pilot devices. [Chrome update hosting requirements](https://developer.chrome.com/docs/extensions/how-to/distribute/host-on-linux#update) · [Caddy automatic HTTPS](https://caddyserver.com/docs/automatic-https)

```sh
node deploy/pilot/preflight.mjs \
  --dashboard https://control.example.com --browser https://browser.example.com \
  --admin-network allowed --release-dir /secure/releases/pilot-0.21.0
```

The hosted verifier builds the standalone dashboard and Release API, then exercises real TLS, managed enrollment, publishing, and enforcement from an isolated Chrome profile. The verifier needs Docker for its disposable database, plus Caddy and OpenSSL on the host. It uses a test certificate and leaves the system trust store alone.

```sh
node scripts/verify-demo.mjs --hosted --headed --artifacts /tmp/zekvar-hosted
```

For a customer rollout, verify certificate issuance and renewal on the intended host, browser distribution through customer management, database backup and restore, monitoring, incident response, and identity requirements. Restarting the single dashboard process expires its active sessions. Keep the database and Caddy data volumes when updating services. [Zekvar hosted pilot gates](../../product_plan.md#delivery-roadmap)
