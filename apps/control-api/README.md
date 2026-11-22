# Zekvar Control API local demo

This ASP.NET Core API issues enrollment grants, publishes policy versions, tracks browser health, and stores metadata-only fixture and ChatGPT decisions in PostgreSQL. It runs in the Development environment at `http://127.0.0.1:5187`. Use a disposable database and synthetic data.

Use the [Control dashboard](../control-web/README.md) to sign in and publish a policy. The [Zekvar Browser extension](../browser-extension/README.md#run-the-demo) can redeem a grant, apply the policy, and report fixture events automatically.

The [TLS pilot](../../deploy/pilot/README.md) runs the API in Production with `Control__HostedPilot=true`. The API listens on loopback and verifies the database on its readiness route.

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

Use `Authorization: Bearer …` with a Control token for `/v1/admin` routes and an installation token for `/v1/browser` routes. Send JSON bodies with `Content-Type: application/json`. Credentials are stored as hashes.

## Named Control access

The configured organization token has the `owner` role. Owners can issue and revoke expiring tokens with an `administrator` or `auditor` role. Administrators can change policy, browser enrollment, app classification, and retention within their organization. Auditors can read and export the same retained records and use policy preview. Only owners can list, issue, or revoke delegated credentials.

| Request | Result |
| --- | --- |
| `GET /v1/admin/session` | Returns the organization and role. For delegated access, `access` contains its ID, name, and role. |
| `POST /v1/admin/access` | Owner supplies `name` (2 to 64 characters), `role`, and `hours` (1 to 720). Returns credential metadata in `access` and the new `token` in the issuance response. |
| `GET /v1/admin/access` | Returns active credentials and the 100 most recently issued inactive credentials for the owner’s organization. The response contains dates and status. |
| `POST /v1/admin/access/{id}/revoke` | Returns HTTP 204 for a credential in the owner’s organization, including a repeat revocation. Revocation clears the token hash and is recorded once. |

Control evaluates expiry and revocation on each request. Invalid, expired, or revoked tokens receive HTTP 401. Authenticated requests outside the caller’s role receive HTTP 403. Use a new credential for rotation and revoke the previous credential when replacement is complete. Requests already authorized may finish after revocation. Credential names are assigned by the owner and should correspond to individual recipients.

## Hosted OpenID Connect access

In the configured organization, `GET /v1/admin/access/sso` returns the issuer to the owner. `POST /v1/admin/access/sso` accepts `name`, an `administrator` or `auditor` role, and the provider's exact `subject`. An active duplicate returns HTTP 409. The existing access revocation route ends the identity's sessions and future Control sign-ins. Successful SSO sign-ins are recorded as `control_sso_signed_in` with named Control identity metadata.

The dashboard verifies the provider response and uses a separate configured loopback credential to exchange the verified subject for an opaque Control token. The API caps the resulting session to one hour and evaluates live role, expiry, and revocation on each request. Caddy keeps the exchange route and administrative API private. [Hosted setup and verification](../../deploy/pilot/README.md#configure-control-single-sign-on)

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

Policies advertise the available app IDs in `appIds`. Publish requests accept `mode` for the test marker and an optional `githubPatMode` for the GitHub classic PAT rule. The GitHub rule starts `off`. Omitting `githubPatMode` preserves its current setting, and restoring a version restores both modes. Event ingestion accepts `local-prompt-fixture`, `chatgpt`, `gemini`, and `claude` for eligible text rules. Each decision must match the named policy version and rule. Heartbeats can report composer coverage as `ready` or `unsupported`. Each status and its last checked timestamp are stored independently. The event list supports `appId`, `decision`, and `since` query filters. [Shared example payloads](../../contracts/control/demo-v1.json)

`claudePromptEnabled` is a versioned baseline or rollout-group setting and defaults to `false`. Browsers send `X-Zekvar-Claude-Prompt: 1` when fetching a policy and acknowledge its application with `claudePromptApplied: true`. Older browsers receive the remaining settings and cannot mark a Claude-enabled version current. Claude text events and optional `claudeCoverage` require a recorded delivery of that policy to the installation. Control shows Claude coverage for the currently assigned version.

Publish requests accept an optional `discoveryEnabled` boolean and `customApps` array with up to 25 `{ "host": "workspace.example.test", "name": "Example Workspace" }` entries. Hostnames are normalized, require unique exact matches, and reserve the three built-in hosts. Omitting an array preserves its settings and an empty array clears it. Approval, promotion, and restore copy the full catalog. Disabling discovery keeps the configured catalog. A scoped policy with active custom apps requires `customDiscoveryApplied: true` in the heartbeat before Control marks it current.

`POST /v1/browser/ai-app-observations` accepts `appId`, `observedAt`, `policyVersion`, and optional `assignmentVersion`. Custom IDs are derived from the normalized hostname and verified against the tenant's versioned catalog. Control preserves the latest timestamp per browser and app and rejects late reports from before the most recent removal or Off policy. `GET /v1/admin/ai-apps` returns the built-ins and custom apps on the organization's current baseline or rollout groups, together with classifications, distinct browser counts over 30 days, and latest observation times. `POST /v1/admin/ai-apps/{appId}/classification` accepts `unreviewed`, `approved`, or `unapproved` and returns 404 for a valid custom ID outside the active catalog. Names and classifications can change while the app ID stays stable.

Publish requests can also supply `domainRules` with `allow` and `block` hostname arrays. A domain-only publish can omit `mode` and preserve the current prompt and discovery settings. Omitting `domainRules` preserves the lists. Sending two empty lists clears them. Control normalizes accepted names and rejects paths, ports, IPs, wildcards, and entries that appear in both lists. Restore applies the earlier lists as part of a new policy version.

`pathRules` follows the same publish and clear semantics, with `allow` and `block` arrays of hostname/path prefixes such as `example.com/work`. Paths are case-sensitive, use literal segments of up to 64 characters total including the leading slash, and may have one trailing slash that Control removes. Baseline and group snapshots can include up to 50 domain and path rules combined. This limit is enforced even when only one set of lists is replaced. Existing versions start with empty path lists. Restore and promotion copy the saved lists.

Baseline and group publishes accept an optional positive integer `expectedVersion`. Control compares it with the effective current version for that scope in the same transaction as the publish. A group following the baseline uses the current baseline version. A mismatch returns HTTP 409.

For a version with domain rules, the heartbeat must include `domainRulesApplied: true`. Versions containing path rules also require `pathRulesApplied: true` to count as applied. Browser v0.13.0 sends the path acknowledgment after updating Chrome. Older browsers still report liveness and remain at their last acknowledged version in Browser health.

Browser v0.20.0 sends its manifest version in `X-Zekvar-Extension-Version` on authenticated policy fetches. Control accepts one to four integers in Chrome's version format and ignores absent or invalid values. The last valid version and its server receipt time are visible on `GET /v1/admin/installations`. The tenant-scoped `GET /v1/admin/browser-releases` route counts active installations across the fleet, including releases grouped under `other` and browsers with no recorded version under `unreported`. Recent version reports use a 90-second window. Policy acknowledgments and browser liveness have their own fields. [Chrome extension version format](https://developer.chrome.com/docs/extensions/reference/manifest/version)

`GET /v1/admin/browser-health` reads the organization’s active-installation count, release summary, and installation details from one database snapshot. Use `rolloutGroup=baseline` for unassigned installations or pass a rollout group UUID from the same organization. Apply `browserVersion` to the detail rows using the exact version or `unreported`. The detail limit is 100 matching installations, ordered newest first. The release summary covers all active installations in the group. Repeated or malformed filters return HTTP 400. Unavailable group IDs return HTTP 404.

`POST /v1/admin/enrollment-batches` accepts `requestId`, nullable `groupId`, and `count` from 1 to 25. Keep the same UUID when retrying a transport failure. The first accepted request returns the 10-minute codes. A duplicate UUID in the same organization returns HTTP 409 and leaves the original batch available to inspect or cancel. `GET /v1/admin/enrollment-batches` returns recent batch metadata. `POST /v1/admin/enrollment-batches/{id}/cancel` invalidates unused grants. A browser presenting a group grant sends `X-Zekvar-Scoped-Enrollment: 1` when redeeming. Its installation starts in the assigned group, and policy delivery requires assignment capability as usual. Single grants and baseline batches retain compatibility with older browsers.

The independent `paymentCardMode` setting accepts `off`, `monitor`, `warn`, or `block` on baseline and group policies. Existing versions start with the detector Off. Omitting the setting preserves the current value. Restoring or promoting a policy copies the saved setting. A browser heartbeat without `paymentCardModeApplied: true` still reports liveness but cannot acknowledge a version that enables this detector. Event ingestion accepts the `payment-card-number` rule with category `payment-card` and validates the decision against that version's setting.

The `uploadModes` policy object accepts `chatgpt` and `gemini` settings with `off`, `monitor`, or `block`. An upload-only publish may supply either destination and preserves omitted settings. Older snapshots default to Off for both. Restoring or promoting a policy copies both settings. A heartbeat must supply `uploadControlsApplied: true` to acknowledge a version that enables either destination.

The optional `uploadTypes` object accepts an array of up to 25 selectors per destination. Each selector can be a filename suffix, a media type, or a media type group, such as `[".tar.gz", "application/pdf", "image/*"]`. An empty array applies that mode to every file. An omitted array preserves the previous setting. Off retains the selectors for later use. Control trims, lowercases, deduplicates, and sorts selectors before storing them in the snapshot. Restore, group promotion, and approval preserve the snapshot.

For each active scoped destination, browser policy delivery sets its legacy `uploadModes` entry to `off` and returns its actual mode and selectors in `targetedUploads`. Scoped policies need both `uploadControlsApplied: true` and `uploadTypesApplied: true` in heartbeats to count as applied. Administrative policy responses include the configured modes and selectors.

Upload attempt events use `ai-file-upload` and category `file-upload`. They require an `uploadMethod` of `picker`, `drop`, or `paste` and a decision matching the app's setting on the named policy version. The method appears on retained history and exports. Chrome evaluates the match locally and submits the same event metadata for scoped and unscoped matches.

### Temporary prompt exceptions

Publish `promptExceptions` as an array of `{ appId, ruleId, expiresAt, reason }` objects. Supported app IDs are `chatgpt`, `gemini`, and `claude`, with one entry per existing prompt detector. Claude grants are delivered when the adapter is enabled and the browser supports it. Use an absolute expiry within 24 hours and a 3 to 120 character reason. Omit the array to preserve the scope's entries or send an empty array to remove them. Reviews freeze expiry and reject an approval after a new or changed exception's deadline. Restoring or promoting a policy keeps the target scope's current entries.

Browser policy responses for the exact assigned scope deliver active `promptExceptionLease` grants with `serverTimeMs` and `expiresAtMs` timestamps. The response excludes the reason. A browser reports `promptExceptionsApplied` in its heartbeat when it can use the grant. Older Chrome builds continue normal prompt enforcement. Control verifies `exception_applied` events against the app, detector, already delivered assignment and policy, and event time before expiry. Audit and export retain the policy attribution and decision.

## Policy reviews

Policy reviews are optional by default. The owner can enable the requirement with `POST /v1/admin/policy-reviews/setting` and `{ "required": true }`. `GET /v1/admin/session` includes `reviewRequired`. When required, a publish, restore, or promotion submitted by a named administrator returns HTTP 202 and `{ "reviewId": "…" }`. A request queues the exact candidate policy and its current reference version. It does not advance the policy version. Owners and auditors cannot submit or approve requests while review is required.

- `GET /v1/admin/policy-reviews` returns the tenant requirement, pending reviews, and the latest 100 closed or expired reviews. Each record includes the policy snapshots to compare.
- `POST /v1/admin/policy-reviews/{id}/decision` accepts `{ "approve": true }` from a different administrator with a distinct credential and name. Success returns HTTP 200 and the published policy. An approval checks that both credentials are active, the reference and promotion source versions still match, and the request is within 24 hours of submission.
- A named administrator can send `{ "approve": false }` to close the request. The requester's decision is recorded as a withdrawal. A different administrator's decision is recorded as a rejection. A successful close returns HTTP 204.
- An expired or already decided request returns HTTP 409. If the reference policy, promotion source, or requesting credential changed, Control records a stale decision without publishing.
- Send `X-Zekvar-Expect-Review: 1` when a caller intends to request review. If the owner disabled the requirement while the caller was editing, the server returns HTTP 409. Disabling also cancels active pending requests.

Approved publication and its review decision commit in the same transaction. Audit records include reviewer identity, request ID, status, reference version, and the version published when applicable. Audit payloads exclude the before and candidate policy snapshots.

## Extension inventory

Policy publishes accept `extensionInventoryEnabled` as an optional boolean. Existing policies start with it Off. Restore, promotion, and the policy review queue preserve the setting.

- `POST /v1/browser/extension-inventory` accepts the current `policyVersion`, `assignmentVersion`, `capturedAt`, `status`, `entries`, and `omitted` count from an enrolled browser. The effective policy must enable inventory. A stale policy, scope change, or disabled setting returns HTTP 409.
- `reported` accepts up to 100 entries. Entries describe identifiers, names, versions, enabled states, install types, site-access categories, and selected API permissions. `permission_required` and `unavailable` use empty entry lists. Reports may be up to 128 KiB. The general API request limit stays at 16 KiB.
- Reports replace the latest per-installation snapshot. Older reports and replays cannot replace a more recent snapshot. Browsers resend changed reports on sync and periodically refresh identical reports.
- `GET /v1/admin/extension-inventory` lists status and counts for the latest 100 active installations in the organization. `GET /v1/admin/extension-inventory/{id}` includes entries for one active installation. The response shows data only for the current effective policy and assignment. Control hides reports after 30 days and clears revoked installations or expired and disabled snapshots as part of the documented retention lifecycle.

## Security event history and export

- `GET /v1/admin/events` returns an array of up to 100 events for existing clients.
- `GET /v1/admin/events/history` returns `{ entries, next }` with up to 100 entries. If `next` is present, pass its `receivedAt`, `eventId`, and `installationId` as `beforeAt`, `beforeEventId`, and `beforeInstallationId` with the same filters. Keep the timestamp as returned to retain sub-millisecond precision.
- `GET /v1/admin/events/export` streams a single JSON download with the organization, export time, applied filters, and all matching retained entries as of the database query. The result contains policy decision metadata and installation and event IDs.

History and export accept `appId`, `decision`, `installationId`, and occurrence timestamps `since` (inclusive) and `until` (exclusive). Results are sorted by server receipt time, with event ID and installation ID as tie-breakers. Retention applies immediately, and each history page reads the rows still retained when requested. Both endpoints require a Control credential for the organization.

## AI enforcement report

`GET /v1/admin/reports/ai-enforcement` accepts `days=7` (default) or `days=30` and an optional `appId` of `chatgpt`, `claude`, or `gemini`. The authenticated organization determines the scope. The report covers UTC calendar days including the current partial day. `startOn` is the first date. `asOf` is the inclusive cutoff for both occurrence and server receipt. Pass that value as Unix milliseconds in `asOf` to reuse the cutoff for up to 24 hours. Each request applies current retention and reads all counts from one PostgreSQL statement.

`counts`, `daily`, `byApp`, and `byRule` report policy events per decision. The daily series has one row per date, including empty days. The app and rule breakdowns include categories with matching events. A warning and a later override are separate events. The local prompt fixture is excluded. The response contains aggregate counts and report filters. Use the event export for individual decision records.

## Audit log

`GET /v1/admin/audit` returns the authenticated organization's activity as `{ entries, next }`. Use `action` to filter by `policy_published`, `policy_restored`, `grant_issued`, `browser_enrolled`, `browser_revoked`, `app_classified`, `retention_changed`, `retention_cleanup`, `policy_group_created`, `policy_group_assigned`, `access_issued`, `access_revoked`, `policy_review_setting_changed`, `policy_review_requested`, or `policy_review_decided`. `since` is inclusive and `until` is exclusive. `limit` defaults to 100 and accepts up to 1,000. When `next` is present, send its `occurredAt` as `beforeAt` and its `id` as `beforeId` with the same filters to get older entries.

Audited changes and their records are written together. Repeating a revocation or saving the same classification preserves one entry for the change. Migration 006 backfills policy and installation history. Migration 014 adds `actorAccess` for named administrator activity and `subjectAccess` for issuance and revocation. Both objects contain an ID, name, and role. Earlier records keep their original actor category. Credential values, hashes, prompts, grant values, and policy content stay out of the audit payload.

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
