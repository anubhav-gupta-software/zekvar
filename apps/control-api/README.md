# Zekvar Control API local demo

This ASP.NET Core API issues enrollment grants, publishes policy versions, tracks browser health, and stores metadata-only fixture and ChatGPT decisions in PostgreSQL. It runs in the Development environment at `http://127.0.0.1:5187`. Use a disposable database and synthetic data.

Use the [Control dashboard](../control-web/README.md) to sign in and publish a policy. The [Zekvar Browser extension](../browser-extension/README.md#run-the-demo) can redeem a grant, apply the policy, and report fixture events automatically.

## Start the API

In your terminal, `cd` into your `zekvar` checkout before running these commands. `pwd` should end in `/zekvar`, and `ls apps/control-api/Control.Api.csproj` should find the project. A prompt showing `~` is in your home directory.

With the .NET 10 SDK and a local PostgreSQL instance, set `ConnectionStrings__Control` to a connection string for your demo database. If your `zekvar-control-db` container is already running on port `55432`, reuse it and skip this Docker command.

```sh
docker run -d --rm --name zekvar-control-db -p 127.0.0.1:55432:5432 \
  -e POSTGRES_PASSWORD=local-demo-only -e POSTGRES_DB=zekvar postgres:18
```

Then start the API. Startup applies the schema migration and seeds the named organization with an initial monitor policy. Keep the generated admin token in this shell for API calls.

```sh
export DOTNET_ENVIRONMENT=Development
export ConnectionStrings__Control='Host=127.0.0.1;Port=55432;Database=zekvar;Username=postgres;Password=local-demo-only'
export Control__Organizations__0__Slug=local-demo
export Control__Organizations__0__AdminToken="$(openssl rand -hex 32)"
dotnet run --project apps/control-api/Control.Api.csproj --no-launch-profile
```

Wait for `Now listening on: http://127.0.0.1:5187`. On a first run, .NET may print a welcome banner and links before that line. In a second terminal, `curl -f http://127.0.0.1:5187/health` confirms the API is ready. Stop the API with Ctrl+C. `docker stop zekvar-control-db` removes the disposable container started with `--rm`.

## Exercise the workflow

Use `Authorization: Bearer …` with the admin token for `/v1/admin` routes and the installation token for `/v1/browser` routes. Send JSON bodies with `Content-Type: application/json`. Credentials are stored as hashes.

| Order | Request | Result |
| --- | --- | --- |
| 1 | `POST /v1/admin/enrollment-grants` | An enrollment grant that expires in 10 minutes |
| 2 | `POST /v1/enroll` with `{"grant":"…"}` | An installation ID and its token. Redemption uses up the grant. |
| 3 | `GET /v1/browser/policy` | The current policy, initially version `1` in monitor mode |
| 4 | `POST /v1/browser/heartbeat` with `{"policyVersion":1}` | An acknowledgment of the applied policy |
| 5 | `POST /v1/browser/events` with the `event` object from the shared fixture | An acknowledgment. Sending the same event ID again for the same installation stores one row. |
| 6 | `GET /v1/admin/events` and `GET /v1/admin/installations` | The organization’s events and installation health |
| 7 | `POST /v1/admin/policies` with `{"mode":"block"}` | A new immutable policy version. `GET /v1/admin/policies` returns version history. |
| 8 | `POST /v1/admin/policies/1/restore` | A new version that restores the initial monitor mode |
| 9 | `POST /v1/admin/installations/{id}/revoke` | The installation credential is revoked. |

Policies advertise the available app IDs in `appIds`. Publish requests accept `mode` for the test marker and an optional `githubPatMode` for the GitHub classic PAT rule. The GitHub rule starts `off`. Omitting `githubPatMode` preserves its current setting, and restoring a version restores both modes. Event ingestion accepts the fixed app IDs `local-prompt-fixture` and `chatgpt` and the rule and category pairs `fixture-secret` with `synthetic-secret` and `github-classic-pat` with `credential`. Each decision must match the named policy version and rule. Heartbeats can include `chatGptCoverage` set to `ready` or `unsupported`. The event list supports `appId`, `decision`, and `since` query filters. [Shared example payloads](../../contracts/control/demo-v1.json)

Publish requests also accept an optional `discoveryEnabled` boolean. Discovery is Off on existing and new policies. Omitting the setting keeps its latest value. Policy restore brings back the stored setting. `POST /v1/browser/ai-app-observations` accepts `appId`, `observedAt`, and `policyVersion` from enrolled browsers. Control stores the latest timestamp for each browser and catalog app and rejects observations from before the most recent Off policy.

`GET /v1/admin/ai-apps` returns ChatGPT, Claude, and Gemini with their classifications, distinct browser counts over 30 days, and latest observation times. `POST /v1/admin/ai-apps/{appId}/classification` accepts a `status` of `unreviewed`, `approved`, or `unapproved`. Classifications apply to the signed-in organization and remain in place when a policy is restored.

Publish requests can also supply `domainRules` with `allow` and `block` hostname arrays. A domain-only publish can omit `mode` and preserve the current prompt and discovery settings. Omitting `domainRules` preserves the lists. Sending two empty lists clears them. Control normalizes accepted names and rejects paths, ports, IPs, wildcards, and entries that appear in both lists. Restore applies the earlier lists as part of a new policy version.

Baseline and group publishes accept an optional positive integer `expectedVersion`. Control compares it with the effective current version for that scope in the same transaction as the publish. A group following the baseline uses the current baseline version. A mismatch returns HTTP 409.

For a version with domain rules, the heartbeat must include `domainRulesApplied: true`. Browser v0.7.0 acknowledges this after Chrome applies the list. Earlier browsers stay at their last acknowledged version in Browser health.

## Audit log

`GET /v1/admin/audit` returns the authenticated organization's activity as `{ entries, next }`. Use `action` to filter by `policy_published`, `policy_restored`, `grant_issued`, `browser_enrolled`, `browser_revoked`, `app_classified`, `retention_changed`, or `retention_cleanup`. `since` is inclusive and `until` is exclusive. `limit` defaults to 100 and accepts up to 1,000. When `next` is present, send its `occurredAt` as `beforeAt` and its `id` as `beforeId` with the same filters to get older entries.

Audited changes and their records are written together. Repeating a revocation or saving the same classification preserves one entry for the change. Migration 006 restores the policy and installation history that already had timestamps. Grant issuance and classification activity are tracked from the migration forward. Records identify the organization-admin or browser-enrollment actor category. Credentials, prompts, grant values, and policy content stay out of the audit payload.

## Data retention

`GET /v1/admin/retention` reads the authenticated organization's settings. `POST /v1/admin/retention` replaces the three windows and requires `securityEventDays`, `aiObservationDays`, and `auditDays`. Each value is a whole number from 1 to 3,650 or `null` for no expiry. Organizations start with no expiry until an administrator sets a window. The 30-day AI inventory view still caps the date range for observations it displays.

Windows use 24-hour periods. Security events age from the earlier of occurrence and server receipt. Observations age from the last observed time, and audit records from their recorded time. Expired records are excluded immediately from results. A subsequent policy change preserves the former cutoff so widening or clearing a window cannot revive records. The browser API rejects queued events and observations whose timestamps are outside the active cutoff.

`POST /v1/admin/retention/cleanup` deletes up to 1,000 expired rows per dataset for the authenticated organization. The service also runs at startup and on a timer set by `Control__RetentionSweepSeconds`, which defaults to 3,600. It drains expired rows in batches. Successful removal produces an audit entry with counts and a manual or scheduled source. Database backup expiry, previously downloaded files, and customer deletion requests follow their own lifecycle.

## Policy groups

`GET /v1/admin/policy-groups` lists the organization's groups and their effective versions. `POST /v1/admin/policy-groups` creates a group from a `name`. The group follows the baseline until its first scoped publish. Use `POST /v1/admin/installations/{id}/policy-group` with `groupId` to assign a browser. Send `null` to return it to the organization baseline.

`GET` and `POST /v1/admin/policy-groups/{groupId}/policies` read and publish scoped versions. `POST /v1/admin/policy-groups/{groupId}/policies/{version}/restore` restores a version from the same group. `POST /v1/admin/policy-groups/{groupId}/promote` takes `expectedVersion` and copies that snapshot into a new organization baseline version if it is still the group's current version. Versions remain unique within the organization. The baseline and each group have separate history and current pointers.

Browser v0.8.0 advertises assignment support with `X-Zekvar-Assignment-Aware: 1` when it requests policy. Control enables assignment after that capability is observed. After a move, the response includes `assignmentVersion`. Browsers send it with heartbeats, decisions, and AI observations. Heartbeats require the current assignment and a delivered version. Queued decisions preserve the assignment that produced them and can arrive after a move. AI observations use the current assignment. The audit log includes `policy_group_created` and `policy_group_assigned`, with group context on publishes, restores, and promotion.

For isolated API or browser tests, `Control__Port` selects a different loopback port. The default dashboard and extension use `5187`.

## Verify the workflow

The tests start and stop their own API process. Leave port `5187` free and use a disposable PostgreSQL database. They seed two temporary organizations and verify enrollment, policy and rollback, installation health, privacy, retry deduplication, tenant isolation, and persistence after restart.

```sh
dotnet build apps/control-api/Control.Api.csproj
ZEKVAR_TEST_DATABASE="$ConnectionStrings__Control" node --test apps/control-api/test/control.test.mjs
```
