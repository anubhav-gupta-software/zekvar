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

The versioned `presetDiscoveryEnabled` setting defaults to `false` and takes effect when `discoveryEnabled` is on. A scoped Browser that sends `X-Zekvar-Preset-Discovery: 1` receives the setting while discovery is on. Observation IDs `copilot`, `perplexity`, `grok`, `meta-ai`, and `deepseek` require a policy delivery with preset discovery enabled for the installation and assignment. Control rejects queued preset observations across intervening Off versions. Preset hostnames configured as custom entries use their custom IDs.

`POST /v1/browser/ai-app-observations` accepts `appId`, `observedAt`, `policyVersion`, and optional `assignmentVersion`. Custom IDs are derived from the normalized hostname and verified against the tenant's versioned catalog. Control preserves the latest timestamp per browser and app and rejects late reports from before the most recent removal or Off policy. `GET /v1/admin/ai-apps` returns the built-ins and custom apps on the organization's current baseline or rollout groups, together with classifications, distinct browser counts over 30 days, and latest observation times. `POST /v1/admin/ai-apps/{appId}/classification` accepts `unreviewed`, `approved`, or `unapproved` and returns 404 for a valid custom ID outside the active catalog. Names and classifications can change while the app ID stays stable.

Publish requests can also supply `domainRules` with `allow` and `block` hostname arrays. A domain-only publish can omit `mode` and preserve the current prompt and discovery settings. Omitting `domainRules` preserves the lists. Sending two empty lists clears them. Control normalizes accepted names and rejects paths, ports, IPs, wildcards, and entries that appear in both lists. Restore applies the earlier lists as part of a new policy version.

`pathRules` follows the same publish and clear semantics, with `allow` and `block` arrays of hostname/path prefixes such as `example.com/work`. Paths are case-sensitive, use literal segments of up to 64 characters total including the leading slash, and may have one trailing slash that Control removes. Baseline and group snapshots can include up to 50 domain, path, and AI app access rules combined. This limit is enforced even when only one set of lists is replaced. Existing versions start with empty path lists. Restore and promotion copy the saved lists.

Baseline and group publishes accept an optional positive integer `expectedVersion`. Control compares it with the effective current version for that scope in the same transaction as the publish. A group following the baseline uses the current baseline version. A mismatch returns HTTP 409.

For a version with domain rules, the heartbeat must include `domainRulesApplied: true`. Versions containing path rules also require `pathRulesApplied: true` to count as applied. Browser v0.13.0 sends the path acknowledgment after updating Chrome. Older browsers still report liveness and remain at their last acknowledged version in Browser health.

Publish `blockedAiAppHosts` as a list of distinct hostnames from the preset AI sites or the policy's resulting custom app catalog. Use `[]` to clear the list. Include changes to the list when removing a blocked hostname from the custom catalog. Each block matches exact hostnames in new top-level HTTP and HTTPS requests and takes precedence over domain and path rules. The Browser receives the list when it sends `X-Zekvar-AI-App-Access: 1`. A nonempty list requires delivery to the same installation and assignment followed by `aiAppAccessApplied: true`. [Chrome declarative network rules](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest)

Browser v0.20.0 sends its manifest version in `X-Zekvar-Extension-Version` on authenticated policy fetches. Control accepts one to four integers in Chrome's version format and ignores absent or invalid values. The last valid version and its server receipt time are visible on `GET /v1/admin/installations`. The tenant-scoped `GET /v1/admin/browser-releases` route counts active installations across the fleet, including releases grouped under `other` and browsers with no recorded version under `unreported`. Recent version reports use a 90-second window. Policy acknowledgments and browser liveness have their own fields. [Chrome extension version format](https://developer.chrome.com/docs/extensions/reference/manifest/version)

`GET /v1/admin/browser-health` reads the organization’s active-installation count, release summary, and installation details from one database snapshot. Use `rolloutGroup=baseline` for unassigned installations or pass a rollout group UUID from the same organization. Apply `browserVersion` to the detail rows using the exact version or `unreported`. The detail limit is 100 matching installations, ordered newest first. The release summary covers all active installations in the group. Repeated or malformed filters return HTTP 400. Unavailable group IDs return HTTP 404.

The same response includes `composerReadiness.activeInstallations` and `composerReadiness.apps` for all active browsers that match both filters. Each app count breaks down into `detected`, `unsupported`, `stale`, `unobserved`, `policy_pending`, or `off`. Active rows include the same state and the receipt time of the matching observation when available. Legacy coverage fields remain available on `/installations`.

`GET /v1/admin/reports/composer-readiness` uses the same rollout and version filters and covers the full matching cohort, including an empty cohort. Owners, administrators, and auditors can read it for their organization. Schema version 1 includes `asOf` in UTC, the normalized scope, freshness limits in seconds, the active installation count, and aggregate status counts for each app. The scope carries the target policy version for a selected group or the baseline, including groups following the baseline. An all-groups report can span several policy versions, so its target version is null. Unknown or repeated query parameters return HTTP 400. Missing and foreign groups both return HTTP 404.

Browser v0.22.0 sends `X-Zekvar-Composer-Coverage: 1` on heartbeats. Control uses validated coverage from those heartbeats for readiness and checks that it matches the browser's current assignment and applied policy. Observations become stale after 24 hours or 90 seconds without a heartbeat. Control stores up to one observation per supported app and browser. Reassignment and revocation remove the scoped observations.

`POST /v1/admin/enrollment-batches` accepts `requestId`, nullable `groupId`, and `count` from 1 to 25. Keep the same UUID when retrying a transport failure. The first accepted request returns the 10-minute codes. A duplicate UUID in the same organization returns HTTP 409 and leaves the original batch available to inspect or cancel. `GET /v1/admin/enrollment-batches` returns recent batch metadata. `POST /v1/admin/enrollment-batches/{id}/cancel` invalidates unused grants. A browser presenting a group grant sends `X-Zekvar-Scoped-Enrollment: 1` when redeeming. Its installation starts in the assigned group, and policy delivery requires assignment capability as usual. Single grants and baseline batches retain compatibility with older browsers.

The independent `paymentCardMode` setting accepts `off`, `monitor`, `warn`, or `block` on baseline and group policies. Existing versions start with the detector Off. Omitting the setting preserves the current value. Restoring or promoting a policy copies the saved setting. A browser heartbeat without `paymentCardModeApplied: true` still reports liveness but cannot acknowledge a version that enables this detector. Event ingestion accepts the `payment-card-number` rule with category `payment-card` and validates the decision against that version's setting.

The versioned `ssnMode` setting accepts `off`, `monitor`, `warn`, or `block` and defaults to Off. Browser v0.30.0 requests it with `X-Zekvar-SSN: 1` and sends `ssnModeApplied: true` to acknowledge a policy that enables it. SSN events require matching delivery and use rule ID `us-social-security-number` and category `government-identifier`. The API checks prompt events against the detector mode and app-specific exceptions. File content events follow the destination's file content policy and require the corresponding delivery capability.

The `privateKeyMode` setting also accepts `off`, `monitor`, `warn`, or `block`. Browser v0.23.0 declares support with `X-Zekvar-Private-Key: 1` on its policy request. Control records delivery for that browser and assignment. It requires `privateKeyModeApplied: true` to acknowledge a policy that enables the detector. Older releases receive Off and continue to apply other supported controls. Private key decisions use rule ID `pem-private-key` and category `credential`. Control validates the delivered version, assignment, action, and any applicable temporary exception before accepting a decision.

`identifierProtection` sets an independent mode of `off`, `monitor`, `warn`, or `block` and a complete `formats` array. Each entry has `prefix` and `digits`. Submit up to 16 distinct prefixes, each of 3 to 16 ASCII characters. A prefix begins with a letter, then uses letters or digits, and ends in `-` or `_`. Choose a digit count from 4 to 12. Control trims and uppercases prefixes and stores them in sorted order. An enabled mode requires at least one format. Omit the entire setting to preserve the active configuration. Schema 033 defaults earlier policies to Off and preserves existing events and exceptions.

Browser v0.28.0 sends `X-Zekvar-Identifiers: 1`. Versions that enable the detector require matching delivery and `identifiersApplied: true` before the browser counts as current. Events use rule ID `organization-identifier` and category `internal-identifier`. File-content decisions follow the app's separate file mode. The active prompt detector can have a temporary per-app exception. Event exports exclude matched values and prefixes.

The `uploadModes` policy object accepts `chatgpt` and `gemini` settings with `off`, `monitor`, or `block`. An upload-only publish may supply either destination and preserves omitted settings. Older snapshots default to Off for both. Restoring or promoting a policy copies both settings. A heartbeat must supply `uploadControlsApplied: true` to acknowledge a version that enables either destination.

`fileContentModes` accepts independent `chatgpt` and `gemini` values of `off`, `monitor`, or `block`. An omitted app keeps its current mode. Schema 032 preserves older `fileInspection` booleans as Off or Monitor. A legacy `true` enables Monitor when the setting is Off and preserves an already enabled mode. A legacy `false` turns it Off. An explicit mode takes precedence.

Browser v0.24.0 declares support for Monitor with `X-Zekvar-File-Inspection: 1`. Browser v0.27.0 sends both that header and `X-Zekvar-File-Content-Block: 1`. Control requires a matching per-installation delivery and `fileInspectionApplied: true` for an enabled inspection policy, plus `fileContentBlockApplied: true` for Block. Earlier builds can continue monitoring apps still set to Monitor. Control keeps a version that requires Block unacknowledged until a capable build applies it.

A file-content match uses its detector's rule ID and an `uploadMethod`. Control checks the delivered policy, app, enabled detector, and matching `monitor` or `block` decision. Incomplete checks that prevented an upload use rule `file-inspection-unavailable` and category `file-upload`, with decision `block`. The `ai-file-upload` rule identifies file-type and destination decisions.

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

## Chrome extension deployment plans

Read `extensionDeployment` in the organization or group policy history. Publish it through `POST /v1/admin/policies` or `POST /v1/admin/policy-groups/{groupId}/policies` with `expectedVersion` set to the current effective Control version. `unlisted` is `preserve` or `block`. `rules` accepts up to 100 distinct 32-character Chrome IDs using the letters `a` through `p`. Set `mode` to `allow`, `block`, or `force`. Force installs require an HTTPS `updateUrl` with no credentials, query, or fragment. URLs may use up to 512 characters each and 7,000 total.

Changes use the same audit, approvals, promotion, and restore workflow as other versioned policy. Migration 029 starts earlier policy versions with an empty plan that preserves the native default. The browser policy endpoint keeps the Control agent's existing policy shape. Device managers apply the Chrome policy downloaded from Control. [Export a Chrome deployment plan](../control-web/README.md#deploy-chrome-extension-rules)

## Security event history and export

- `GET /v1/admin/events` returns an array of up to 100 events for existing clients.
- `GET /v1/admin/events/history` returns `{ entries, next }` with up to 100 entries. If `next` is present, pass its `receivedAt`, `eventId`, and `installationId` as `beforeAt`, `beforeEventId`, and `beforeInstallationId` with the same filters. Keep the timestamp as returned to retain sub-millisecond precision.
- `GET /v1/admin/events/export` streams a single JSON download with the organization, export time, applied filters, and all matching retained entries as of the database query. The result contains policy decision metadata and installation and event IDs.

History and export accept `appId`, `decision`, `installationId`, `rolloutGroup`, and occurrence timestamps `since` (inclusive) and `until` (exclusive). Results are sorted by server receipt time, with event ID and installation ID as tie-breakers. Retention applies immediately, and each history page reads the rows still retained when requested. Both endpoints require a Control credential for the organization.

Pass `rolloutGroup=baseline`, `rolloutGroup=unattributed`, or a rollout group UUID. All three event routes support this filter. A valid group ID outside the current organization yields no entries. Each decision includes a `rollout.kind` of `baseline`, `unattributed`, or `group`, with `groupId` and `groupName` for group assignments. Events keep their recorded scope after reassignment, revocation, or retry. Migration 028 backfills cases where a group-specific policy or a never-reassigned installation identifies the scope. Other older events remain unattributed. History and export advertise this support with `X-Zekvar-Event-Rollout: 1`.

### Security event triage

Filter any of the three event routes with `triageStatus=needs_review|investigating|resolved` and `triageAssignee=unassigned` or a named administrator UUID. A record with no saved triage starts at revision 0, needs review, and is unassigned. History and export advertise filter support with `X-Zekvar-Event-Triage: 1`.

- `GET /v1/admin/events/{installationId}/{eventId}` returns the retained event and up to 50 retained changes. Use both identifiers because each browser can report its own event IDs.
- `GET /v1/admin/events/triage-assignees` lists active named administrators in the authenticated organization.
- `POST /v1/admin/events/{installationId}/{eventId}/triage` accepts `expectedRevision`, `status`, `assigneeId` (UUID or null), and `disposition`. Use `confirmed_violation`, `false_positive`, `expected_activity`, or `insufficient_evidence` for a resolved event. Use null for other statuses. Owners and administrators can write, including retaining an inactive assignment or selecting a new active assignee. An auditor can read and export.

Each accepted change increments the revision and writes one `event_triage_changed` audit entry atomically. Repeating the identical update against the current or immediately preceding revision returns the current state without another write. A conflicting revision returns HTTP 409 with `event_triage_stale`. An invalid new assignee returns HTTP 400 with `event_assignee_unavailable`. Unknown, foreign, or expired events return HTTP 404. Migration 031 adds triage without modifying earlier event records. Event cleanup cascades to current triage, and audit changes follow the independent audit retention window.

## Security event feed

Poll `GET /v1/integrations/events` with `Authorization: Bearer <event-feed-key>`. In the hosted pilot, use the dashboard HTTPS origin from a source network in the administrator allowlist. The route reads one organization's retained events and sends `Cache-Control: no-store` on each response.

- Start without `after` to read retained records in stream order. `limit` defaults to 100 and accepts 1–500. Send `nextCursor` from the last processed page as `after`. Keep polling the checkpoint even when `entries` is empty. `hasMore: true` means another page was available when the query ran.
- Every page contains `{ schemaVersion, entries, nextCursor, hasMore }`. Version 1 entries contain the event and installation IDs, occurrence and receipt timestamps, app, rule, detector category, policy version, decision, recorded rollout kind and optional group ID, and optional upload method. Payloads exclude inspected content and triage. Records can expire before collection under the configured event retention policy.
- Commit the checkpoint after the collector durably processes the whole page. Use the pair `(installationId, eventId)` to deduplicate replays. A well-formed cursor for a different tenant, an earlier recovery generation, or a sequence ahead of the stream returns HTTP 409 with `event_feed_cursor_invalid`. After confirming which stream you intend to read, start again without `after` and deduplicate any retained events you already imported.

Owners can list keys with `GET /v1/admin/access/event-feed` and issue one with `POST` to the same path. Send `{ requestId, name, days }` with a fresh UUID and a lifetime from 1 to 90 days. A successful response returns `{ key, token }` once. A retry with the same request ID returns HTTP 409. The list shows up to 100 keys with active keys first. An organization can have up to 20 active keys. `POST /v1/admin/access/event-feed/{id}/revoke` clears the hash, succeeds again on a repeat, and returns 404 for unknown and foreign IDs. Audit records report the key ID and name. Key expiry and revocation return HTTP 401 on subsequent feed reads.

## AI enforcement report

`GET /v1/admin/reports/ai-enforcement` accepts `days=7` (default) or `days=30`, an optional `appId` of `chatgpt`, `claude`, or `gemini`, and the same `rolloutGroup` filter as security events. The authenticated organization determines the scope. The report covers UTC calendar days including the current partial day. `startOn` is the first date. `asOf` is the inclusive cutoff for both occurrence and server receipt. Pass that value as Unix milliseconds in `asOf` to reuse the cutoff for up to 24 hours. Each request applies current retention and reads all counts from one PostgreSQL statement.

`counts`, `daily`, `byApp`, `byRule`, and `bySource` report policy events per decision. The daily series has one row per date, including empty days. The app, rule, and source breakdowns include categories with matching events. The source IDs are `prompt`, `file_policy`, and `file_content`. A warning and a later override are separate events. The local prompt fixture is excluded. The response contains aggregate counts and report filters. Use the event export for individual decision records.

## Security alerts

`GET /v1/admin/alerts/settings` returns the current mode, threshold, and revision. Owners and administrators can post `{ "enabled": true, "threshold": 5, "expectedRevision": 0 }` to that path. Thresholds range from 2 to 100. Stale conflicting settings return HTTP 409. An identical retry produces one audited change.

After enablement, each newly stored AI Block decision contributes once to its app, recorded rollout group, settings revision, and 15-minute UTC window of server receipt. Control stores the count and references to existing event metadata. It opens an alert at the threshold and keeps the alert acknowledged for the rest of its window if an operator reviews it. Duplicate deliveries preserve the count. The local prompt fixture stays outside the rule.

`GET /v1/admin/alerts` accepts optional `appId` and `status` filters and a `beforeAt` and `beforeId` cursor pair. `GET /v1/admin/alerts/{id}` returns the alert and up to 100 retained events, with the event cursor when more remain. Supply that cursor as `beforeAt`, `beforeEventId`, and `beforeInstallationId`. Owners and administrators acknowledge at `POST /v1/admin/alerts/{id}/acknowledge`. A retry returns HTTP 204 and keeps one audit entry. Auditors can read settings, alerts, evidence, and the audit log. Missing, foreign, and expired alerts return HTTP 404.

Alert windows expire after 30 days or when the first receipt in the window crosses the configured event cutoff, whichever comes first. Evidence follows the underlying event retention cutoff. Untriggered windows are eligible for cleanup an hour after the start of their window. Manual and scheduled cleanup report removed alert windows when applicable. Audit entries follow the audit retention window.

For a configured webhook, the alert detail includes a `webhook` object with delivery status, attempt count, timestamps, and a categorized failure where applicable. Route configuration and signing keys remain in the deployment configuration. Jobs inherit the parent alert's visibility and retention.

## Incident cases

- `GET /v1/admin/cases` lists up to 100 retained cases for the organization, newest first by creation time. Filter by `status` or `openOnly=true`. Use the returned `createdAt` and `id` as `beforeAt` and `beforeId` for the next page.
- `POST /v1/admin/cases` opens a case and links the supplied `installationId` and `eventId`. Supply a UUID `requestId` and a `category` of `suspected_data_exposure`, `repeated_policy_blocks`, `unexpected_ai_use`, or `other`. Reuse the same request ID and payload on retry. The response contains `caseId`.
- `GET /v1/admin/cases/{id}` returns the case, retained linked events, and up to 50 retained changes. The `/export` suffix downloads the same scope as JSON.
- `POST /v1/admin/cases/{id}/triage` accepts `expectedRevision`, `status`, `assigneeId`, and `disposition` using the same values as event triage. New cases start at revision 1.
- `POST /v1/admin/cases/{id}/membership` accepts `expectedRevision`, `installationId`, `eventId`, and `linked`. An event can join one case. Reopen a resolved case before changing links. Each case can contain up to 100 retained events.

Owners and named administrators can make changes, and auditors can read and export. Mutations write an `incident_case_changed` audit record atomically with state changes and advance the revision. Repeating an identical update using the current or immediately preceding revision is idempotent. Conflicting or stale changes return HTTP 409. Missing, expired, or foreign case and event references return HTTP 404. Event detail includes `incidentCase` when the event is linked to a retained case.

## Audit log

`GET /v1/admin/audit` returns the authenticated organization's activity as `{ entries, next }`. Use `action` to filter by `policy_published`, `policy_restored`, `grant_issued`, `browser_enrolled`, `browser_revoked`, `app_classified`, `retention_changed`, `retention_cleanup`, `policy_group_created`, `policy_group_assigned`, `access_issued`, `access_revoked`, `control_sso_signed_in`, `policy_review_setting_changed`, `policy_review_requested`, `policy_review_decided`, `enrollment_batch_issued`, `enrollment_batch_cancelled`, `event_triage_changed`, `incident_case_changed`, `security_alert_settings_changed`, `security_alert_acknowledged`, `event_feed_key_issued`, or `event_feed_key_revoked`. `since` is inclusive and `until` is exclusive. `limit` defaults to 100 and accepts up to 1,000. When `next` is present, send its `occurredAt` as `beforeAt` and its `id` as `beforeId` with the same filters to get older entries.

Audited changes and their records are written together. Repeating a revocation or saving the same classification preserves one entry for the change. Migration 006 backfills policy and installation history. Migration 014 adds `actorAccess` for named administrator activity and `subjectAccess` for issuance and revocation. Both objects contain an ID, name, and role. Earlier records keep their original actor category. Credential values, hashes, prompts, grant values, and policy content stay out of the audit payload.

## Data retention

`GET /v1/admin/retention` reads the authenticated organization's settings. `POST /v1/admin/retention` replaces the three windows and requires `securityEventDays`, `aiObservationDays`, and `auditDays`. Each value is a whole number from 1 to 3,650 or `null` for no expiry. Organizations start with no expiry until an administrator sets a window. The 30-day AI inventory view still caps the date range for observations it displays.

Windows use 24-hour periods. Security events age from the earlier of occurrence and server receipt. Observations age from the last observed time, and audit records from their recorded time. Expired records are excluded immediately from results. A subsequent policy change preserves the former cutoff so widening or clearing a window cannot revive records. The browser API rejects queued events and observations whose timestamps are outside the active cutoff.

`auditDays` also applies to resolved incident cases based on their last case update. Linked events keep their normal retention windows. Expired event and case links are removed on cleanup, and audit records follow their own recorded time. Open cases stay visible when linked events expire.

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
