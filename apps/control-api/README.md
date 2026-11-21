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

For isolated API or browser tests, `Control__Port` selects a different loopback port. The default dashboard and extension use `5187`.

## Verify the workflow

The tests start and stop their own API process. Leave port `5187` free and use a disposable PostgreSQL database. They seed two temporary organizations and verify enrollment, policy and rollback, installation health, privacy, retry deduplication, tenant isolation, and persistence after restart.

```sh
dotnet build apps/control-api/Control.Api.csproj
ZEKVAR_TEST_DATABASE="$ConnectionStrings__Control" node --test apps/control-api/test/control.test.mjs
```
