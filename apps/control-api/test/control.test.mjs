import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const db = process.env.ZEKVAR_TEST_DATABASE;
assert.ok(db, 'Set ZEKVAR_TEST_DATABASE to a disposable PostgreSQL connection string.');
const contract = JSON.parse(await readFile(new URL('../../../contracts/control/demo-v1.json', import.meta.url)));
const app = fileURLToPath(new URL('../bin/Debug/net10.0/Control.Api.dll', import.meta.url));
const port = process.env.ZEKVAR_TEST_API_PORT ?? '5187';
const baseUrl = `http://127.0.0.1:${port}`;
const suffix = randomBytes(8).toString('hex');
const first = randomBytes(32).toString('hex');
const second = randomBytes(32).toString('hex');
const retentionAdmin = randomBytes(32).toString('hex');
const releaseAdmin = randomBytes(32).toString('hex');
const groupViewAdmin = randomBytes(32).toString('hex');
const batchAdmin = randomBytes(32).toString('hex');
const reportAdmin = randomBytes(32).toString('hex');
const coverageAdmin = randomBytes(32).toString('hex');
const keyAdmin = randomBytes(32).toString('hex');
const fileAdmin = randomBytes(32).toString('hex');
const rolloutHistoryAdmin = randomBytes(32).toString('hex');
const deploymentAdmin = randomBytes(32).toString('hex');
const aiAppAccessAdmin = randomBytes(32).toString('hex');
const eventTriageAdmin = randomBytes(32).toString('hex');
const identifiersAdmin = randomBytes(32).toString('hex');
const casesAdmin = randomBytes(32).toString('hex');
const presetsAdmin = randomBytes(32).toString('hex');
const ssnAdmin = randomBytes(32).toString('hex');
const alertsAdmin = randomBytes(32).toString('hex');
const webhooksAdmin = randomBytes(32).toString('hex');
const eventFeedAdmin = randomBytes(32).toString('hex');
const hardeningAdmin = randomBytes(32).toString('hex');
const clipboardAdmin = randomBytes(32).toString('hex');
const fleetAdmin = randomBytes(32).toString('hex');
const templateAdmin = randomBytes(32).toString('hex');
const githubTokenAdmin = randomBytes(32).toString('hex');
const impactAdmin = randomBytes(32).toString('hex');
const promptRequestAdmin = randomBytes(32).toString('hex');
const promptAppModesAdmin = randomBytes(32).toString('hex');
const inventoryChangesAdmin = randomBytes(32).toString('hex');
const extensionAlertsAdmin = randomBytes(32).toString('hex');
const composerGateAdmin = randomBytes(32).toString('hex');
const detectionRulesAdmin = randomBytes(32).toString('hex');
const rolloutAdmin = randomBytes(32).toString('hex');
const adapterAdmin = randomBytes(32).toString('hex');
const logsAdmin = randomBytes(32).toString('hex');
const saasAdmin = randomBytes(32).toString('hex');
const enrollmentKeyAdmin = randomBytes(32).toString('hex');
const healthAdmin = randomBytes(32).toString('hex');
const eraseAdmin = randomBytes(32).toString('hex');
const purgeAdmin = randomBytes(32).toString('hex');
const offboardCancelAdmin = randomBytes(32).toString('hex');
const offboardAdmin = randomBytes(32).toString('hex');
const raceAdmin = randomBytes(32).toString('hex');
const exportAdmin = randomBytes(32).toString('hex');
const deletionKey = randomBytes(32).toString('hex');
const postgres = process.env.ZEKVAR_TEST_POSTGRES_CONTAINER;
const sql = promisify(execFile);

const undoSsoSchema = `
  DELETE FROM schema_migrations WHERE version = 55;
  DELETE FROM schema_migrations WHERE version = 21;
  DROP TABLE control_sso_sessions;
  ALTER TABLE control_access DROP CONSTRAINT control_access_type_check,
      DROP COLUMN oidc_issuer, DROP COLUMN oidc_subject, ALTER COLUMN expires_at SET NOT NULL,
      ADD CONSTRAINT control_access_check1 CHECK ((revoked_at IS NULL) = (token_hash IS NOT NULL));
`;
const healthRuleIds = `'us-national-provider-identifier', 'dea-registration-number', 'medicare-beneficiary-identifier', 'medical-record-number'`;
const undoHealthSchema = `
  DELETE FROM schema_migrations WHERE version = 58;
  DELETE FROM security_events WHERE rule_id IN (${healthRuleIds});
  ALTER TABLE security_events DROP CONSTRAINT security_events_rule_id_check,
    ADD CONSTRAINT security_events_rule_id_check CHECK (rule_id IN (
      'fixture-secret', 'github-classic-pat', 'payment-card-number', 'ai-file-upload', 'pem-private-key',
      'file-inspection-unavailable', 'organization-identifier', 'us-social-security-number', 'clipboard-inspection-unavailable',
      'github-app-or-fine-grained-token', 'aws-access-key-id', 'slack-token', 'stripe-live-secret-key', 'google-api-key',
      'openai-api-key', 'anthropic-api-key', 'organization-classification-rule'));
  ALTER TABLE policy_versions DROP COLUMN health_protection;
  ALTER TABLE policy_deliveries DROP COLUMN health_identifiers;
`;
const undoSaasInventorySchema = `
  ${undoHealthSchema}
  DELETE FROM schema_migrations WHERE version = 56;
  DELETE FROM control_audit WHERE action = 'saas_app_classified';
  ALTER TABLE control_audit DROP CONSTRAINT control_audit_saas_record_check, DROP COLUMN saas_classification;
  DROP TABLE saas_app_observations;
  DROP TABLE saas_app_classifications;
  ALTER TABLE policy_versions DROP COLUMN saas_discovery_enabled;
  ALTER TABLE policy_deliveries DROP COLUMN saas_discovery;
`;
const undoEnrollmentKeysSchema = `
  ${undoSaasInventorySchema}
  DELETE FROM schema_migrations WHERE version = 55;
  DELETE FROM schema_migrations WHERE version = 54;
  DELETE FROM control_audit WHERE action IN ('enrollment_key_issued', 'enrollment_key_revoked');
  ALTER TABLE control_audit DROP CONSTRAINT control_audit_enrollment_key_check, DROP COLUMN enrollment_key_change;
  DROP TABLE enrollment_key_redemptions;
  DROP TABLE enrollment_keys;
`;
const undoAdapterControlsSchema = `
  ${undoEnrollmentKeysSchema}
  DELETE FROM schema_migrations WHERE version = 53;
  DELETE FROM composer_observations WHERE coverage = 'disabled';
  UPDATE installations SET chatgpt_coverage = NULLIF(chatgpt_coverage, 'disabled'),
    gemini_coverage = NULLIF(gemini_coverage, 'disabled'), claude_coverage = NULLIF(claude_coverage, 'disabled');
  ALTER TABLE composer_observations DROP CONSTRAINT composer_observations_coverage_check,
    ADD CONSTRAINT composer_observations_coverage_check CHECK (coverage IN ('ready', 'unsupported'));
  ALTER TABLE installations
    DROP CONSTRAINT installations_chatgpt_coverage_check,
    ADD CONSTRAINT installations_chatgpt_coverage_check CHECK (chatgpt_coverage IN ('ready', 'unsupported')),
    DROP CONSTRAINT installations_gemini_coverage_check,
    ADD CONSTRAINT installations_gemini_coverage_check CHECK (gemini_coverage IN ('ready', 'unsupported')),
    DROP CONSTRAINT installations_claude_coverage_check,
    ADD CONSTRAINT installations_claude_coverage_check CHECK (claude_coverage IN ('ready', 'unsupported'));
  ALTER TABLE policy_versions DROP COLUMN adapter_controls;
  ALTER TABLE policy_deliveries DROP COLUMN adapter_controls;
`;
const undoRolloutSchema = `
  ${undoAdapterControlsSchema}
  DELETE FROM schema_migrations WHERE version = 52;
  DELETE FROM control_audit WHERE action = 'rollout_plan_changed';
  DROP TABLE rollout_stages;
  DROP TABLE rollout_plans;
  ALTER TABLE control_audit DROP COLUMN rollout_change;
`;
const undoDetectionRulesSchema = `
  ${undoRolloutSchema}
  DELETE FROM schema_migrations WHERE version = 51;
  ALTER TABLE policy_versions DROP COLUMN cloud_credential_mode, DROP COLUMN classification_protection;
  ALTER TABLE policy_deliveries DROP COLUMN detection_rules;
`;
const undoPromptAppModesSchema = `
  ${undoDetectionRulesSchema}
  DELETE FROM schema_migrations WHERE version = 46;
  ALTER TABLE policy_versions DROP COLUMN prompt_app_modes;
  ALTER TABLE policy_deliveries DROP COLUMN prompt_app_modes;
`;
const undoExtensionAccessAlertsSchema = `
  DELETE FROM schema_migrations WHERE version = 55;
  DELETE FROM schema_migrations WHERE version = 48;
  DROP TABLE extension_access_alert_settings;
  ALTER TABLE extension_inventory_change_batches DROP COLUMN alert_acknowledged_at, DROP COLUMN alert_id;
`;
const undoPromptRequestSchema = `
  ${undoPromptAppModesSchema}
  DELETE FROM schema_migrations WHERE version = 45;
  DROP TABLE prompt_exception_requests;
`;
const undoGithubTokenSchema = `
  ${undoPromptRequestSchema}
  DELETE FROM schema_migrations WHERE version = 44;
  ALTER TABLE policy_versions DROP COLUMN github_token_mode;
  ALTER TABLE policy_deliveries DROP COLUMN github_token;
`;
const undoClipboardSchema = `
  ${undoGithubTokenSchema}
  DELETE FROM schema_migrations WHERE version = 41;
  ALTER TABLE policy_versions DROP COLUMN clipboard_mode;
  ALTER TABLE policy_deliveries DROP COLUMN clipboard_paste;
  ALTER TABLE security_events DROP COLUMN clipboard_paste;
`;
const undoSsnSchema = `
  ${undoClipboardSchema}
  DELETE FROM schema_migrations WHERE version = 36;
  ALTER TABLE policy_versions DROP COLUMN ssn_mode;
  ALTER TABLE policy_deliveries DROP COLUMN ssn;
`;
const undoIdentifierSchema = `
  ${undoSsnSchema}
  DELETE FROM schema_migrations WHERE version = 33;
  ALTER TABLE policy_versions DROP COLUMN identifier_protection;
  ALTER TABLE policy_deliveries DROP COLUMN identifiers;
`;
const undoTemplateSchema = `
  ${undoGithubTokenSchema}
  DELETE FROM schema_migrations WHERE version = 43;
  DROP TABLE policy_template_revisions;
  DROP TABLE policy_templates;
  ALTER TABLE control_audit DROP COLUMN template_change;
`;
const undoFleetSchema = `
  ${undoTemplateSchema}
  DELETE FROM schema_migrations WHERE version = 42;
  DROP INDEX installations_active_fleet_page;
  ALTER TABLE control_audit DROP COLUMN fleet_change, DROP COLUMN fleet_request_hash;
`;
const undoEventFeedSchema = `
  ${undoFleetSchema}
  DELETE FROM schema_migrations WHERE version = 39;
  DROP TRIGGER security_event_feed_sequence ON security_events;
  DROP FUNCTION assign_security_event_sequence();
  ALTER TABLE security_events DROP COLUMN stream_sequence;
  DROP TABLE event_feed_keys;
  DROP TABLE organization_event_streams;
  ALTER TABLE control_audit DROP COLUMN event_feed_key_change;
`;
const undoAlertSchema = `
  ${undoEventFeedSchema}
  DELETE FROM schema_migrations WHERE version = 38;
  DROP TABLE alert_webhook_deliveries;
  DELETE FROM schema_migrations WHERE version = 37;
  DROP TABLE security_alert_events;
  DROP TABLE security_alert_windows;
  DROP TABLE security_alert_settings;
  ALTER TABLE control_audit DROP COLUMN security_alert_change;
`;
const undoIncidentSchema = `
  ${undoAlertSchema}
  DELETE FROM schema_migrations WHERE version = 34;
  DROP TABLE incident_case_events;
  DROP TABLE incident_cases;
  ALTER TABLE control_audit DROP COLUMN incident_case_change;
`;
const undoPresetSchema = `
  DELETE FROM schema_migrations WHERE version = 55;
  DELETE FROM schema_migrations WHERE version = 35;
  ALTER TABLE policy_versions DROP COLUMN preset_discovery_enabled;
  ALTER TABLE policy_deliveries DROP COLUMN preset_discovery;
`;

async function retentionFixture(query) {
  assert.match(postgres ?? '', /^zekvar-demo-[a-f0-9]{10}$/);
  const { stdout } = await sql('docker', ['exec', postgres, 'psql', '-XAtq', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'zekvar', '-c', query]);
  return stdout.trim();
}

function browserPolicyOnly({ extensionDeployment: _extensionDeployment, browserHardening: _browserHardening, blockedAiAppHosts: _blockedAiAppHosts,
  fileContentModes: _fileContentModes, identifierProtection: _identifierProtection, presetDiscoveryEnabled: _presetDiscovery,
  ssnMode: _ssnMode, clipboardMode: _clipboardMode, githubTokenMode: _githubTokenMode, promptAppModes: _promptAppModes,
  cloudCredentialMode: _cloudCredentialMode, classificationProtection: _classificationProtection, adapterControls: _adapterControls,
  saasDiscoveryEnabled: _saasDiscoveryEnabled, healthProtection: _healthProtection, ...browserPolicy }) {
  return browserPolicy;
}

async function call(path, { token, method = 'GET', body, expect = 200, assignmentAware = false, expectReview = false, claudeAware = false,
  extensionVersion, scopedEnrollment = false, composerAware = false, privateKeyAware = false, fileInspectionAware = false,
  aiAppAccessAware = false, fileBlockAware = false, identifiersAware = false, presetAware = false, ssnAware = false, clipboardAware = false,
  githubTokenAware = false, promptAppModesAware = false, detectionRulesAware = false, adapterControlsAware = false, saasAware = false,
  healthAware = false } = {}) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (claudeAware) headers['X-Zekvar-Claude-Prompt'] = '1';
  if (assignmentAware) headers['X-Zekvar-Assignment-Aware'] = '1';
  if (expectReview) headers['X-Zekvar-Expect-Review'] = '1';
  if (extensionVersion !== undefined) headers['X-Zekvar-Extension-Version'] = extensionVersion;
  if (scopedEnrollment) headers['X-Zekvar-Scoped-Enrollment'] = '1';
  if (composerAware) headers['X-Zekvar-Composer-Coverage'] = '1';
  if (privateKeyAware) headers['X-Zekvar-Private-Key'] = '1';
  if (fileInspectionAware) headers['X-Zekvar-File-Inspection'] = '1';
  if (aiAppAccessAware) headers['X-Zekvar-AI-App-Access'] = '1';
  if (fileBlockAware) headers['X-Zekvar-File-Content-Block'] = '1';
  if (identifiersAware) headers['X-Zekvar-Identifiers'] = '1';
  if (presetAware) headers['X-Zekvar-Preset-Discovery'] = '1';
  if (ssnAware) headers['X-Zekvar-SSN'] = '1';
  if (clipboardAware) headers['X-Zekvar-Clipboard-Paste'] = '1';
  if (githubTokenAware) headers['X-Zekvar-GitHub-Token'] = '1';
  if (promptAppModesAware) headers['X-Zekvar-Prompt-App-Modes'] = '1';
  if (detectionRulesAware) headers['X-Zekvar-Detection-Rules'] = '1';
  if (adapterControlsAware) headers['X-Zekvar-Adapter-Controls'] = '1';
  if (saasAware) headers['X-Zekvar-SaaS-Discovery'] = '1';
  if (healthAware) headers['X-Zekvar-Health-Identifiers'] = '1';
  const response = await fetch(`${baseUrl}${path}`, {
    method, headers, body: body !== undefined ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(5_000),
  }).catch((error) => {
    throw new Error(`${method} ${path} failed: ${error.message}`, { cause: error });
  });
  const text = await response.text();
  assert.equal(response.status, expect, `${method} ${path}: ${text.slice(0, 500)}`);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  return text ? JSON.parse(text) : undefined;
}

let processHandle;
let exited;
// Everything the current API process wrote to stdout and stderr, for the log redaction checks.
let apiLogs = '';

async function start(sweepSeconds = 3600, overrides = {}) {
  processHandle = spawn('dotnet', [app], {
    env: {
      ...process.env,
      DOTNET_ENVIRONMENT: 'Development',
      ASPNETCORE_ENVIRONMENT: 'Development',
      ConnectionStrings__Control: db,
      Control__Port: port,
      Control__RetentionSweepSeconds: String(sweepSeconds),
      Control__Organizations__0__Slug: `first-${suffix}`,
      Control__Organizations__0__AdminToken: first,
      Control__Organizations__1__Slug: `second-${suffix}`,
      Control__Organizations__1__AdminToken: second,
      Control__Organizations__2__Slug: `retention-${suffix}`,
      Control__Organizations__2__AdminToken: retentionAdmin,
      Control__Organizations__3__Slug: `release-${suffix}`,
      Control__Organizations__3__AdminToken: releaseAdmin,
      Control__Organizations__4__Slug: `group-view-${suffix}`,
      Control__Organizations__4__AdminToken: groupViewAdmin,
      Control__Organizations__5__Slug: `enrollment-batch-${suffix}`,
      Control__Organizations__5__AdminToken: batchAdmin,
      Control__Organizations__6__Slug: `report-${suffix}`,
      Control__Organizations__6__AdminToken: reportAdmin,
      Control__Organizations__7__Slug: `coverage-${suffix}`,
      Control__Organizations__7__AdminToken: coverageAdmin,
      Control__Organizations__8__Slug: `private-key-${suffix}`,
      Control__Organizations__8__AdminToken: keyAdmin,
      Control__Organizations__9__Slug: `private-file-${suffix}`,
      Control__Organizations__9__AdminToken: fileAdmin,
      Control__Organizations__10__Slug: `rollout-history-${suffix}`,
      Control__Organizations__10__AdminToken: rolloutHistoryAdmin,
      Control__Organizations__11__Slug: `extension-deployment-${suffix}`,
      Control__Organizations__11__AdminToken: deploymentAdmin,
      Control__Organizations__12__Slug: `ai-app-access-${suffix}`,
      Control__Organizations__12__AdminToken: aiAppAccessAdmin,
      Control__Organizations__13__Slug: `event-triage-${suffix}`,
      Control__Organizations__13__AdminToken: eventTriageAdmin,
      Control__Organizations__14__Slug: `identifiers-${suffix}`,
      Control__Organizations__14__AdminToken: identifiersAdmin,
      Control__Organizations__15__Slug: `incident-cases-${suffix}`,
      Control__Organizations__15__AdminToken: casesAdmin,
      Control__Organizations__16__Slug: `presets-${suffix}`,
      Control__Organizations__16__AdminToken: presetsAdmin,
      Control__Organizations__17__Slug: `ssn-${suffix}`,
      Control__Organizations__17__AdminToken: ssnAdmin,
      Control__Organizations__18__Slug: `alerts-${suffix}`,
      Control__Organizations__18__AdminToken: alertsAdmin,
      Control__Organizations__19__Slug: `webhooks-${suffix}`,
      Control__Organizations__19__AdminToken: webhooksAdmin,
      Control__Organizations__20__Slug: `event-feed-${suffix}`,
      Control__Organizations__20__AdminToken: eventFeedAdmin,
      Control__Organizations__21__Slug: `hardening-${suffix}`,
      Control__Organizations__21__AdminToken: hardeningAdmin,
      Control__Organizations__22__Slug: `clipboard-${suffix}`,
      Control__Organizations__22__AdminToken: clipboardAdmin,
      Control__Organizations__23__Slug: `browser-fleet-${suffix}`,
      Control__Organizations__23__AdminToken: fleetAdmin,
      Control__Organizations__24__Slug: `policy-templates-${suffix}`,
      Control__Organizations__24__AdminToken: templateAdmin,
      Control__Organizations__25__Slug: `github-tokens-${suffix}`,
      Control__Organizations__25__AdminToken: githubTokenAdmin,
      Control__Organizations__26__Slug: `policy-impact-${suffix}`,
      Control__Organizations__26__AdminToken: impactAdmin,
      Control__Organizations__27__Slug: `prompt-requests-${suffix}`,
      Control__Organizations__27__AdminToken: promptRequestAdmin,
      Control__Organizations__28__Slug: `prompt-app-modes-${suffix}`,
      Control__Organizations__28__AdminToken: promptAppModesAdmin,
      Control__Organizations__29__Slug: `inventory-history-${suffix}`,
      Control__Organizations__29__AdminToken: inventoryChangesAdmin,
      Control__Organizations__30__Slug: `extension-alerts-${suffix}`,
      Control__Organizations__30__AdminToken: extensionAlertsAdmin,
      Control__Organizations__31__Slug: `composer-gate-${suffix}`,
      Control__Organizations__31__AdminToken: composerGateAdmin,
      Control__Organizations__32__Slug: `detection-rules-${suffix}`,
      Control__Organizations__32__AdminToken: detectionRulesAdmin,
      Control__Organizations__33__Slug: `rollout-plans-${suffix}`,
      Control__Organizations__33__AdminToken: rolloutAdmin,
      Control__Organizations__34__Slug: `adapter-controls-${suffix}`,
      Control__Organizations__34__AdminToken: adapterAdmin,
      Control__Organizations__35__Slug: `logs-${suffix}`,
      Control__Organizations__35__AdminToken: logsAdmin,
      Control__Organizations__36__Slug: `saas-inventory-${suffix}`,
      Control__Organizations__36__AdminToken: saasAdmin,
      Control__Organizations__37__Slug: `enrollment-keys-${suffix}`,
      Control__Organizations__37__AdminToken: enrollmentKeyAdmin,
      Control__Organizations__38__Slug: `health-identifiers-${suffix}`,
      Control__Organizations__38__AdminToken: healthAdmin,
      Control__EnrollmentKeyAttemptsPerMinute: '40',
      Control__Organizations__39__Slug: `erase-installation-${suffix}`,
      Control__Organizations__39__AdminToken: eraseAdmin,
      Control__Organizations__40__Slug: `purge-history-${suffix}`,
      Control__Organizations__40__AdminToken: purgeAdmin,
      Control__Organizations__41__Slug: `offboard-cancel-${suffix}`,
      Control__Organizations__41__AdminToken: offboardCancelAdmin,
      Control__Organizations__42__Slug: `offboard-delete-${suffix}`,
      Control__Organizations__42__AdminToken: offboardAdmin,
      Control__Organizations__43__Slug: `offboard-race-${suffix}`,
      Control__Organizations__43__AdminToken: raceAdmin,
      Control__Organizations__44__Slug: `export-${suffix}`,
      Control__Organizations__44__AdminToken: exportAdmin,
      Control__OrganizationDeletion__ReceiptKey: deletionKey,
      Control__OrganizationDeletion__SweepSeconds: '1',
      Control__OrganizationDeletion__BatchSize: '25',
      Control__RolloutEvaluationSeconds: '3600',
      ...overrides,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  exited = once(processHandle, 'exit');
  let logs = '';
  let ready = false;
  apiLogs = '';
  const capture = (chunk) => { if (apiLogs.length < 8_000_000) apiLogs += chunk; };
  processHandle.stdout.on('data', (chunk) => {
    capture(chunk);
    logs = (logs + chunk).slice(-4000);
    ready ||= logs.includes(`Now listening on: ${baseUrl}`);
  });
  processHandle.stderr.on('data', (chunk) => { capture(chunk); logs = (logs + chunk).slice(-4000); });
  for (let attempt = 0; attempt < 200 && processHandle.exitCode === null && !ready; attempt++) {
    await delay(50);
  }
  assert.ok(ready, `Control API did not start.\n${logs}`);
  assert.deepEqual(await call('/health'), { status: 'ready' });
}

async function stop() {
  if (!processHandle) return;
  processHandle.kill('SIGTERM');
  await exited;
  processHandle = undefined;
}

// The full suite takes about 100 to 130 seconds on a developer laptop and more under load, so the budget leaves headroom
// for a slow machine while still failing a hung run.
test('Control persists tenant-scoped policies, enrollment and metadata in PostgreSQL', { timeout: 300_000 }, async (t) => {
  t.after(stop);
  await start();
  let client;
  let current;
  const event = { ...contract.event, eventId: randomUUID() };

  await t.test('only an admin can issue a short-lived grant, and only one redemption succeeds', async () => {
    await call('/v1/admin/session', { expect: 401 });
    assert.deepEqual(await call('/v1/admin/session', { token: first }), {
      organization: `first-${suffix}`, role: 'owner', access: null, reviewRequired: false,
    });
    await call('/v1/admin/enrollment-grants', { method: 'POST', expect: 401 });
    const { grant, expiresAt } = await call('/v1/admin/enrollment-grants', { method: 'POST', token: first });
    assert.ok(Date.parse(expiresAt) > Date.now());
    const redemption = () => fetch(`${baseUrl}/v1/enroll`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ grant }),
      signal: AbortSignal.timeout(5_000),
    });
    const responses = await Promise.all([redemption(), redemption()]);
    assert.deepEqual(responses.map((response) => response.status).sort(), [200, 401]);
    client = await responses.find((response) => response.ok).json();
    await call('/v1/admin/policies', { token: client.token, expect: 401 });
    await call('/v1/browser/policy', { token: first, expect: 401 });
  });

  await t.test('API logs are structured JSON and omit credentials, grants, bodies, query strings, and policy terms', async () => {
    const canary = `zkvlogcanary${randomBytes(6).toString('hex')}`;
    const secrets = [logsAdmin, canary];
    const { grant } = await call('/v1/admin/enrollment-grants', { method: 'POST', token: logsAdmin });
    const browser = await call('/v1/enroll', { method: 'POST', body: { grant } });
    secrets.push(grant, browser.token);
    await call('/v1/enroll', { method: 'POST', body: { grant }, expect: 401 });
    const term = `Project ${canary}`;
    const published = await call('/v1/admin/policies', { method: 'POST', token: logsAdmin,
      body: { classificationProtection: { mode: 'warn', terms: [term] } } });
    assert.deepEqual(published.classificationProtection.terms, [term]);
    const restored = await call(`/v1/admin/policies/${published.version - 1}/restore`, { method: 'POST', token: logsAdmin });
    assert.deepEqual(restored.classificationProtection, { mode: 'off', terms: [] });
    await call('/v1/browser/policy', { token: browser.token });
    const event = { ...contract.event, eventId: randomUUID(), timestamp: new Date().toISOString(), policyVersion: restored.version };
    await call('/v1/browser/events', { method: 'POST', token: browser.token, body: event, expect: 204 });
    await call('/v1/browser/events', { method: 'POST', token: browser.token, body: { ...event, prompt: `${canary} prompt` }, expect: 400 });
    await call('/v1/admin/events', { token: `${canary}bearer`, expect: 401 });
    await call(`/v1/admin/events?appId=${canary}query&since=${canary}`, { token: logsAdmin, expect: 400 });
    await call(`/v1/integrations/events?after=${canary}cursor&code=${canary}code`, { token: `zf_${canary}feedkey`, expect: 401 });
    await call('/v1/internal/sso/session', { method: 'POST', token: `${canary}sso`,
      body: { issuer: 'https://idp.example.test', subject: `${canary}subject`, expiresAt: new Date(Date.now() + 60_000).toISOString() },
      expect: 404 });
    for (const body of [`{"grant":"${canary}malformed`, `{"${canary}unknown":1}`, `{"grant":["${canary}array"]}`]) {
      const response = await fetch(`${baseUrl}/v1/enroll`, { method: 'POST', headers: { 'Content-Type': 'application/json',
        Cookie: `session=${canary}cookie` }, body, signal: AbortSignal.timeout(5_000) });
      assert.equal(response.status, 400);
    }
    const oversized = await fetch(`${baseUrl}/v1/browser/events`, { method: 'POST', headers: { 'Content-Type': 'application/json',
      Authorization: `Bearer ${browser.token}` }, body: JSON.stringify({ ...event, prompt: canary.repeat(2000) }), signal: AbortSignal.timeout(5_000) });
    assert.ok([400, 413].includes(oversized.status), `oversized body returned ${oversized.status}`);
    await delay(300);

    for (const secret of secrets) assert.ok(!apiLogs.includes(secret), 'a synthetic secret reached the API logs');
    assert.ok(!apiLogs.toLowerCase().includes(canary), 'a synthetic value reached the API logs');
    assert.doesNotMatch(apiLogs, /\/v1\/(enroll|admin|browser|integrations|internal)/);
    const lines = apiLogs.split('\n').filter((line) => line.trim());
    assert.ok(lines.some((line) => line.includes('Now listening on')), 'the capture saw the startup log');
    for (const line of lines) {
      const entry = JSON.parse(line);
      assert.equal(typeof entry.LogLevel, 'string');
      assert.equal(typeof entry.Category, 'string');
      if (entry.Category.startsWith('Microsoft.') && entry.Category !== 'Microsoft.Hosting.Lifetime')
        assert.ok(['Warning', 'Error', 'Critical'].includes(entry.LogLevel), line);
    }
  });

  await t.test('the browser sees published policies and a rollback creates a new version', async () => {
    const initial = await call('/v1/browser/policy', { token: client.token });
    for (const [key, value] of Object.entries(contract.policy)) assert.equal(initial[key], value);
    const policies = await Promise.all(['warn', 'block'].map((mode) =>
      call('/v1/admin/policies', { method: 'POST', token: first, body: { mode } })));
    assert.deepEqual(policies.map((policy) => policy.version).sort(), [2, 3]);
    await call('/v1/admin/policies/999/restore', { method: 'POST', token: first, expect: 404 });
    current = await call('/v1/admin/policies/1/restore', { method: 'POST', token: first });
    assert.equal(current.version, 4);
    assert.equal(current.mode, 'monitor');
    assert.equal(current.restoredFrom, 1);
    const history = await call('/v1/admin/policies', { token: first });
    assert.deepEqual(history.map((policy) => policy.version), [4, 3, 2, 1]);
    assert.deepEqual(current.extensionDeployment, { unlisted: 'preserve', rules: [] });
    assert.deepEqual(await call('/v1/browser/policy', { token: client.token }), browserPolicyOnly(current));
    assert.equal((await call('/v1/admin/policies', { token: second })).length, 1);
  });

  await t.test('installation heartbeat records an applied version and ignores an older report', async () => {
    for (const policyVersion of [current.version, 1]) {
      await call('/v1/browser/heartbeat', {
        method: 'POST', token: client.token, body: { policyVersion }, expect: 204,
      });
    }
    await call('/v1/browser/heartbeat', {
      method: 'POST', token: client.token, body: { policyVersion: 999 }, expect: 400,
    });
    const [installation] = await call('/v1/admin/installations', { token: first });
    assert.equal(installation.installationId, client.installationId);
    assert.equal(installation.appliedPolicyVersion, current.version);
    assert.ok(Date.parse(installation.lastSeenAt) >= Date.parse(installation.enrolledAt));
  });

  await t.test('event retries are idempotent and content or mismatched versions are rejected', async () => {
    const post = (body, expect = 204) => call('/v1/browser/events', { method: 'POST', token: client.token, body, expect });
    await Promise.all([post(event), post(event)]);
    for (const invalid of [
      { ...event, prompt: 'sensitive synthetic text' },
      { ...event, ruleId: 'sensitive synthetic text' },
      { ...event, policyVersion: 999 },
      { ...event, decision: 'block' },
    ]) await post(invalid, 400);
    const stored = await call('/v1/admin/events?decision=monitor', { token: first });
    assert.equal(stored.length, 1);
    const { installationId, receivedAt, ...metadata } = stored[0];
    assert.equal(installationId, client.installationId);
    assert.ok(Number.isFinite(Date.parse(receivedAt)));
    assert.deepEqual(metadata, { ...event, rollout: { kind: 'baseline' } });
    assert.deepEqual(await call('/v1/admin/events?appId=local-prompt-fixture&decision=monitor', { token: first }), stored);
    assert.deepEqual(await call('/v1/admin/events?appId=other-app', { token: first }), []);
    assert.deepEqual(await call('/v1/admin/events?decision=block', { token: first }), []);
    const afterEvent = new Date(Date.parse(event.timestamp) + 1000).toISOString();
    assert.deepEqual(await call(`/v1/admin/events?since=${encodeURIComponent(afterEvent)}`, { token: first }), []);
  });

  await t.test('another tenant cannot read or revoke this installation', async () => {
    assert.deepEqual(await call('/v1/admin/events', { token: second }), []);
    assert.deepEqual(await call('/v1/admin/installations', { token: second }), []);
    await call(`/v1/admin/installations/${client.installationId}/revoke`, { method: 'POST', token: second, expect: 404 });
    assert.deepEqual(await call('/v1/browser/policy', { token: client.token }), browserPolicyOnly(current));
  });

  await t.test('the migration is repeatable and revocation survives an API restart', async () => {
    await call(`/v1/admin/installations/${client.installationId}/revoke`, { method: 'POST', token: first, expect: 204 });
    await stop();
    await start();
    await call('/v1/browser/policy', { token: client.token, expect: 401 });
    await call('/v1/browser/events', { method: 'POST', token: client.token, body: event, expect: 401 });
    assert.equal((await call('/v1/admin/events', { token: first })).length, 1);
    assert.equal((await call('/v1/admin/policies', { token: first }))[0].version, current.version);
  });

  await t.test('credential mode is independently versioned and events must match the historical rule', async () => {
    const { grant } = await call('/v1/admin/enrollment-grants', { method: 'POST', token: second });
    const { token } = await call('/v1/enroll', { method: 'POST', body: { grant } });
    const publish = (body, expect = 200) => call('/v1/admin/policies', { method: 'POST', token: second, body, expect });
    const post = (body, expect = 204) => call('/v1/browser/events', { method: 'POST', token, body, expect });
    const credential = {
      ...event, eventId: randomUUID(), ruleId: 'github-classic-pat', detectorCategory: 'credential',
      decision: 'monitor', policyVersion: 1,
    };
    assert.equal((await call('/v1/browser/policy', { token })).githubPatMode, 'off');
    await post(credential, 400);
    await publish({ mode: 'block', githubPatMode: 'allow' }, 400);
    const enabled = await publish({ mode: 'block', githubPatMode: 'monitor' });
    const published = await Promise.all(['warn', 'block'].map((mode) => publish({ mode })));
    for (const policy of [enabled, ...published]) assert.equal(policy.githubPatMode, 'monitor');
    const restored = await call('/v1/admin/policies/1/restore', { method: 'POST', token: second });
    assert.equal(restored.githubPatMode, 'off');
    assert.equal(restored.mode, 'monitor');
    const history = await call('/v1/admin/policies', { token: second });
    assert.deepEqual(history.map(({ githubPatMode }) => githubPatMode), ['off', 'monitor', 'monitor', 'monitor', 'off']);

    const historical = { ...credential, policyVersion: enabled.version };
    for (const invalid of [
      { ...historical, detectorCategory: 'synthetic-secret' },
      { ...historical, decision: 'block' },
      { ...historical, prompt: 'sensitive synthetic text' },
      { ...historical, policyVersion: restored.version },
    ]) await post(invalid, 400);
    await Promise.all([post(historical), post(historical)]);
    const [stored, ...duplicates] = await call('/v1/admin/events', { token: second });
    const { installationId, receivedAt, ...metadata } = stored;
    assert.deepEqual(duplicates, []);
    assert.deepEqual(metadata, { ...historical, rollout: { kind: 'baseline' } });
  });

  await t.test('AI discovery is opt-in, tenant scoped, monotonic, and revocable', async () => {
    const enroll = async () => {
      const { grant } = await call('/v1/admin/enrollment-grants', { method: 'POST', token: second });
      return call('/v1/enroll', { method: 'POST', body: { grant } });
    };
    const browser = await enroll();
    const another = await enroll();
    const inventory = (token = second) => call('/v1/admin/ai-apps', { token });
    const classify = (appId, status, token = second, expect = 204) =>
      call(`/v1/admin/ai-apps/${appId}/classification`, { method: 'POST', token, body: { status }, expect });
    const publish = (body) => call('/v1/admin/policies', { method: 'POST', token: second, body });
    const observe = (body, expect = 204, token = browser.token) =>
      call('/v1/browser/ai-app-observations', { method: 'POST', token, body, expect });
    const initial = await call('/v1/browser/policy', { token: browser.token });
    const observedAt = new Date();
    const observation = { appId: 'claude', observedAt: observedAt.toISOString(), policyVersion: initial.version };

    assert.equal(initial.discoveryEnabled, false);
    assert.deepEqual((await inventory()).map((app) => app.appId), ['chatgpt', 'claude', 'gemini', 'copilot', 'perplexity', 'grok', 'meta-ai', 'deepseek']);
    await call('/v1/admin/ai-apps', { token: browser.token, expect: 401 });
    await classify('claude', 'approved', browser.token, 401);
    await classify('claude', 'unknown', second, 400);
    await classify('unknown', 'approved', second, 400);
    await observe(observation, 401, second);
    await observe(observation, 400);
    const enabled = await publish({ mode: 'monitor', discoveryEnabled: true });
    assert.equal((await publish({ mode: 'block' })).discoveryEnabled, true);
    const permitted = { ...observation, policyVersion: enabled.version };
    await observe({ ...permitted, url: 'https://claude.ai/private?value=synthetic' }, 400);
    await observe({ ...permitted, appId: 'other' }, 400);
    await observe({ ...permitted, policyVersion: 999 }, 400);
    await observe({ ...permitted, observedAt: new Date(observedAt.getTime() + 600_000).toISOString() }, 400);
    await observe({ ...permitted, observedAt: new Date(observedAt.getTime() - 32 * 86_400_000).toISOString() }, 400);
    await Promise.all([observe(permitted), observe(permitted),
      observe({ ...permitted, observedAt: new Date(observedAt.getTime() - 2000).toISOString() })]);
    const { lastObservedAt, ...app } = (await inventory())[1];
    assert.deepEqual(app, { appId: 'claude', status: 'unreviewed', browsersSeen: 1 });
    assert.equal(Date.parse(lastObservedAt), observedAt.getTime());
    await observe(permitted, 204, another.token);
    await classify('claude', 'approved');
    const [ours, theirs] = await Promise.all([inventory(), inventory(first)]);
    assert.equal(ours[1].browsersSeen, 2);
    assert.equal(ours[1].status, 'approved');
    assert.deepEqual(theirs[1], { appId: 'claude', status: 'unreviewed', browsersSeen: 0, lastObservedAt: null });

    const restored = await call('/v1/admin/policies/1/restore', { method: 'POST', token: second });
    assert.equal(restored.discoveryEnabled, false);
    await observe(permitted, 400);
    const reenabled = await call(`/v1/admin/policies/${enabled.version}/restore`, { method: 'POST', token: second });
    assert.equal(reenabled.discoveryEnabled, true);
    await observe(permitted, 400);
    await observe({ ...permitted, policyVersion: reenabled.version });
    await call(`/v1/admin/installations/${browser.installationId}/revoke`, { method: 'POST', token: second, expect: 204 });
    await observe({ ...permitted, policyVersion: reenabled.version }, 401);
    await stop();
    await start();
    assert.deepEqual(await inventory(), ours);
  });

  await t.test('domain policies validate, preserve other settings, and require an enforcing browser acknowledgment', async () => {
    const { grant } = await call('/v1/admin/enrollment-grants', { method: 'POST', token: first });
    const browser = await call('/v1/enroll', { method: 'POST', body: { grant } });
    const history = (token = first) => call('/v1/admin/policies', { token });
    const publish = (body, expect = 200, token = first) => call('/v1/admin/policies', { method: 'POST', token, body, expect });
    const restore = (version) => call(`/v1/admin/policies/${version}/restore`, { method: 'POST', token: first });
    const fetchPolicy = () => call('/v1/browser/policy', { token: browser.token });
    const heartbeat = (body, expect = 204) => call('/v1/browser/heartbeat', { method: 'POST', token: browser.token, body, expect });
    const installedVersion = async () => (await call('/v1/admin/installations', { token: first }))
      .find(({ installationId }) => installationId === browser.installationId).appliedPolicyVersion;
    const empty = { allow: [], block: [] };
    const initial = await fetchPolicy();
    assert.deepEqual(initial.domainRules, empty);
    await heartbeat({ policyVersion: initial.version });

    const candidate = { allow: [' Work.Example.test. ', 'work.example.test'], block: ['EXAMPLE.TEST'] };
    for (const block of [
      ['https://example.test/login'], ['*.example.test'], ['127.0.0.1'], ['example.test:443'],
      ['example.test?debug=yes'], ['example.test..'], ['evil..test'], ['.example.test'], ['-starts-with-dash.test'],
      ['x.123'], ['éxample.test'], ['example.' + 'a'.repeat(64)], [null], ['work.example.test.'],
      Array.from({ length: 51 }, (_, index) => `app${index}.test`),
    ]) await publish({ domainRules: { allow: candidate.allow, block } }, 400);
    await publish({ domainRules: { allow: [] } }, 400);
    await publish({ domainRules: candidate }, 401, browser.token);
    assert.equal((await history())[0].version, initial.version);

    const expectedRules = { allow: ['work.example.test'], block: ['example.test'] };
    const [, withRules] = await Promise.all([
      publish({ mode: 'warn', githubPatMode: 'monitor', discoveryEnabled: true }),
      publish({ domainRules: candidate }),
    ]);
    const active = await fetchPolicy();
    assert.deepEqual(active.domainRules, expectedRules);
    assert.equal(active.mode, 'warn');
    assert.equal(active.githubPatMode, 'monitor');
    assert.equal(active.discoveryEnabled, true);
    assert.deepEqual((await history(second))[0].domainRules, empty);
    await heartbeat({ policyVersion: active.version }, 400);
    assert.equal(await installedVersion(), initial.version);
    await heartbeat({ policyVersion: active.version, domainRulesApplied: true });
    assert.equal(await installedVersion(), active.version);

    const clearing = await publish({ domainRules: empty });
    assert.deepEqual(clearing.domainRules, empty);
    assert.equal(clearing.mode, 'warn');
    assert.deepEqual((await restore(withRules.version)).domainRules, expectedRules);
    assert.deepEqual((await restore(initial.version)).domainRules, empty);
    await stop();
    await start();
    assert.deepEqual((await history()).find(({ version }) => version === withRules.version).domainRules, expectedRules);
    assert.deepEqual((await fetchPolicy()).domainRules, empty);
  });

  await t.test('audit records successful scoped changes once and supports stable date and cursor filters', async () => {
    const audit = (query = '', token = first, expect = 200) => call(`/v1/admin/audit${query ? `?${query}` : ''}`, { token, expect });
    const auditBefore = await audit();
    const otherBefore = await audit('', second);
    await call('/v1/admin/audit', { expect: 401 });
    for (const query of ['action=invalid', 'limit=0', 'limit=1001', 'beforeId=00000000-0000-0000-0000-000000000000',
      'beforeAt=2026-01-01T00%3A00%3A00Z', 'since=2026-01-02&until=2026-01-01']) await audit(query, first, 400);
    const { grant } = await call('/v1/admin/enrollment-grants', { method: 'POST', token: first });
    const enrollment = await call('/v1/enroll', { method: 'POST', body: { grant } });
    await call('/v1/enroll', { method: 'POST', body: { grant }, expect: 401 });
    await audit('', enrollment.token, 401);
    const domain = 'synthetic-internal.audit.test';
    const published = await call('/v1/admin/policies', { method: 'POST', token: first,
      body: { mode: 'monitor', domainRules: { allow: [], block: [domain] } } });
    await call('/v1/admin/policies/999/restore', { method: 'POST', token: first, expect: 404 });
    const restored = await call('/v1/admin/policies/1/restore', { method: 'POST', token: first });
    const classify = (status, expect = 204) => call('/v1/admin/ai-apps/gemini/classification',
      { method: 'POST', token: first, body: { status }, expect });
    await Promise.all([classify('unapproved'), classify('unapproved')]);
    await classify('invalid', 400);
    const revoke = (token, expect) => call(`/v1/admin/installations/${enrollment.installationId}/revoke`,
      { method: 'POST', token, expect });
    await revoke(second, 404);
    await Promise.all([revoke(first, 204), revoke(first, 204)]);

    const all = await audit();
    const newer = all.entries.slice(0, 6);
    assert.deepEqual(all.entries.slice(6), auditBefore.entries);
    assert.deepEqual(newer.map(({ action }) => action).sort(),
      ['app_classified', 'browser_enrolled', 'browser_revoked', 'grant_issued', 'policy_published', 'policy_restored']);
    assert.equal(newer.find(({ action }) => action === 'policy_published').policyVersion, published.version);
    assert.equal(newer.find(({ action }) => action === 'policy_restored').policyVersion, restored.version);
    assert.equal(newer.find(({ action }) => action === 'policy_restored').restoredFrom, 1);
    assert.equal(newer.find(({ action }) => action === 'browser_enrolled').actor, 'browser_enrollment');
    assert.equal(newer.find(({ action }) => action === 'browser_revoked').installationId, enrollment.installationId);
    assert.equal(newer.find(({ action }) => action === 'app_classified').classification, 'unapproved');
    assert.deepEqual(await audit('', second), otherBefore);
    const serialized = JSON.stringify(all);
    assert.ok(![first, grant, enrollment.token, domain].some((value) => serialized.includes(value)));

    const pages = [];
    for (let cursor = null, count = 0; count < 30; count++) {
      const query = new URLSearchParams({ limit: '2' });
      if (cursor) {
        query.set('beforeAt', cursor.occurredAt);
        query.set('beforeId', cursor.id);
      }
      const page = await audit(query.toString());
      assert.ok(page.entries.length <= 2);
      pages.push(...page.entries);
      if (!page.next) break;
      cursor = page.next;
    }
    assert.deepEqual(pages, all.entries);
    const publishedAudit = newer.find(({ action }) => action === 'policy_published');
    const eventQuery = new URLSearchParams({ action: 'policy_published', since: publishedAudit.occurredAt });
    assert.deepEqual((await audit(eventQuery.toString())).entries, [publishedAudit]);
    await stop();
    await start();
    assert.deepEqual(await audit(), all);
  });

  await t.test('retention immediately expires tenant records, rejects replay, and physically deletes only expired rows', {
    skip: !postgres && 'The isolated demo runner supplies the disposable PostgreSQL fixture for timestamp aging.',
  }, async () => {
    const indefinite = { securityEventDays: null, aiObservationDays: null, auditDays: null };
    const window = { securityEventDays: 1, aiObservationDays: 1, auditDays: 1 };
    const admin = (path, options = {}) => call(`/v1/admin/${path}`, { token: retentionAdmin, ...options });
    const save = (body, expect = 204) => admin('retention', { method: 'POST', body, expect });
    const cleanup = (token = retentionAdmin, expect = 200) => admin('retention/cleanup', { token, method: 'POST', expect });
    const { grant } = await admin('enrollment-grants', { method: 'POST' });
    const { token, installationId } = await call('/v1/enroll', { method: 'POST', body: { grant } });
    assert.match(installationId, /^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/i);
    const publish = await admin('policies', { method: 'POST', body: { mode: 'monitor', discoveryEnabled: true } });
    const browser = (path, body, expect = 204) => call(`/v1/browser/${path}`, { token, method: 'POST', body, expect });
    const hoursFromNow = (hours) => new Date(Date.now() + hours * 3_600_000).toISOString();
    const recent = { ...event, eventId: randomUUID(), timestamp: hoursFromNow(0), policyVersion: publish.version };
    const old = { ...recent, eventId: randomUUID(), timestamp: hoursFromNow(-72) };
    const future = { ...recent, eventId: randomUUID(), timestamp: hoursFromNow(72) };
    for (const entry of [recent, old, future]) await browser('events', entry);
    for (const appId of ['chatgpt', 'claude']) {
      await browser('ai-app-observations', { appId, observedAt: hoursFromNow(0), policyVersion: publish.version });
    }
    const org = `(SELECT organization_id FROM installations WHERE id = '${installationId}')`;
    await retentionFixture(`
      UPDATE security_events SET received_at = now() - interval '3 days' WHERE event_id = '${future.eventId}';
      UPDATE ai_app_observations SET observed_at = now() - interval '3 days' WHERE installation_id = '${installationId}' AND app_id = 'claude';
      UPDATE control_audit SET occurred_at = now() - interval '3 days' WHERE organization_id = ${org} AND action = 'grant_issued';
    `);
    const physicalCounts = () => retentionFixture(`SELECT
      (SELECT count(*) FROM security_events WHERE organization_id = ${org}),
      (SELECT count(*) FROM ai_app_observations WHERE organization_id = ${org}),
      (SELECT count(*) FROM control_audit WHERE organization_id = ${org} AND action = 'grant_issued');`);
    assert.equal(await physicalCounts(), '3|2|1');
    assert.deepEqual(await admin('retention'), indefinite);
    await admin('retention', { token, expect: 401 });
    await cleanup(token, 401);
    for (const invalid of [{}, { ...window, auditDays: 0 }, { ...window, aiObservationDays: 3651 },
      { ...window, securityEventDays: 1.5 }, { ...window, organizationId: randomUUID() }]) await save(invalid, 400);
    const otherHistory = await admin('events', { token: second });
    assert.ok(otherHistory.length);

    await Promise.all([save(window), save(window)]);
    assert.deepEqual(await admin('retention'), window);
    assert.deepEqual((await admin('events')).map(({ eventId }) => eventId), [recent.eventId]);
    assert.deepEqual((await admin('events/history')).entries.map(({ eventId }) => eventId), [recent.eventId]);
    assert.deepEqual((await admin('events/export')).entries.map(({ eventId }) => eventId), [recent.eventId]);
    assert.deepEqual((await admin('ai-apps')).map(({ browsersSeen }) => browsersSeen), [1, 0, 0, 0, 0, 0, 0, 0]);
    assert.deepEqual((await admin('audit?action=grant_issued')).entries, []);
    const retentionChanges = (await admin('audit?action=retention_changed')).entries;
    assert.equal(retentionChanges.length, 1);
    assert.deepEqual(retentionChanges[0].retention, window);
    await browser('events', old, 400);

    await save(indefinite);
    assert.deepEqual(await admin('retention'), indefinite);
    assert.deepEqual((await admin('events')).map(({ eventId }) => eventId), [recent.eventId]);
    assert.deepEqual((await admin('events/export')).entries.map(({ eventId }) => eventId), [recent.eventId]);
    assert.equal(await physicalCounts(), '3|2|1');
    const runs = await Promise.all([cleanup(), cleanup()]);
    assert.deepEqual(runs.sort((a, b) => a.securityEvents - b.securityEvents), [
      { securityEvents: 0, aiObservations: 0, auditEntries: 0, source: 'manual' },
      { securityEvents: 2, aiObservations: 1, auditEntries: 1, source: 'manual' },
    ]);
    assert.equal(await physicalCounts(), '1|1|0');
    assert.deepEqual(await admin('events', { token: second }), otherHistory);
    assert.deepEqual(await admin('retention', { token: second }), indefinite);
    const recorded = (await admin('audit?action=retention_cleanup')).entries;
    assert.equal(recorded.length, 1);
    assert.equal(recorded[0].actor, 'organization_admin');
    assert.deepEqual(recorded[0].cleanup, runs[1]);
    await browser('events', old, 400);

    await save(window);
    await stop();
    await start(1);
    assert.deepEqual(await admin('retention'), window);
    await retentionFixture(`INSERT INTO security_events (organization_id, installation_id, event_id, occurred_at, policy_version, decision)
      SELECT ${org}, '${installationId}', gen_random_uuid(), now() - interval '3 days', ${publish.version}, 'monitor'
      FROM generate_series(1, 1001);`);
    for (let attempt = 0; attempt < 40 && await physicalCounts() !== '1|1|0'; attempt++) await delay(100);
    assert.equal(await physicalCounts(), '1|1|0');
    const scheduled = (await admin('audit?action=retention_cleanup')).entries.filter(({ actor }) => actor === 'system');
    assert.deepEqual(scheduled.map(({ cleanup: { securityEvents, source } }) => [securityEvents, source]).sort((a, b) => a[0] - b[0]),
      [[1, 'scheduled'], [1000, 'scheduled']]);
  });

  await t.test('rollout groups isolate policies, validate deliveries, and survive assignment and publication changes', async () => {
    const enroll = async () => {
      const { grant } = await call('/v1/admin/enrollment-grants', { token: first, method: 'POST' });
      return call('/v1/enroll', { method: 'POST', body: { grant } });
    };
    const [canary, control] = await Promise.all([enroll(), enroll()]);
    const admin = (path, options = {}) => call(`/v1/admin/${path}`, { token: first, ...options });
    const groups = (options = {}) => admin('policy-groups', options);
    const create = (name, expect = 200, token = first) => groups({ method: 'POST', body: { name }, expect, token });
    const assign = (installation, groupId, expect = 204) => admin(`installations/${installation.installationId}/policy-group`,
      { method: 'POST', body: { groupId }, expect });
    const fetchPolicy = (installation, assignmentAware = true, expect = 200) =>
      call('/v1/browser/policy', { token: installation.token, assignmentAware, expect });
    const browserPost = (path, installation, body, expect = 204) => call(`/v1/browser/${path}`,
      { token: installation.token, method: 'POST', body, expect });
    const before = await fetchPolicy(canary, false);
    await groups({ token: canary.token, expect: 401 });
    await create(' ', 400);
    const pilot = await create('  Browser Pilot  ');
    const foreign = await create('Browser Pilot', 200, second);
    await create('browser pilot', 409);
    assert.equal(pilot.name, 'Browser Pilot');
    assert.equal(pilot.effectiveVersion, before.version);
    assert.equal(pilot.publishedVersion, null);
    assert.deepEqual((await groups()).map(({ id }) => id), [pilot.id]);
    const groupPath = `policy-groups/${pilot.id}`;
    const scoped = (path = '', options = {}) => admin(`${groupPath}/policies${path}`, options);
    await admin(`${groupPath}/promote`, { method: 'POST', body: { expectedVersion: before.version }, expect: 409 });
    await assign(canary, foreign.id, 404);
    await assign(canary, pilot.id, 409);
    await fetchPolicy(canary);
    await fetchPolicy(canary, false);
    await assign(canary, pilot.id, 409);
    await fetchPolicy(canary);
    await assign(canary, pilot.id);
    await assign(canary, pilot.id);
    await fetchPolicy(canary, false, 409);
    assert.deepEqual(await fetchPolicy(canary), { ...before, assignmentVersion: 1 });
    assert.equal((await groups())[0].browsers, 1);

    const domainRules = { allow: ['work.pilot.test'], block: ['pilot.test'] };
    const candidate = await scoped('', { method: 'POST', body: { mode: 'block', githubPatMode: 'warn', discoveryEnabled: true, domainRules } });
    assert.deepEqual(await scoped('', { token: second }), []);
    await scoped('', { method: 'POST', body: { mode: 'monitor' }, token: second, expect: 404 });
    await admin(`policies/${candidate.version}/restore`, { method: 'POST', expect: 404 });
    await scoped(`/${before.version}/restore`, { method: 'POST', expect: 404 });
    const acknowledgment = { policyVersion: candidate.version, assignmentVersion: 1, domainRulesApplied: true };
    await browserPost('heartbeat', canary, acknowledgment, 400);
    assert.deepEqual(await fetchPolicy(canary), { ...browserPolicyOnly(candidate), assignmentVersion: 1 });
    assert.deepEqual(await fetchPolicy(control), before);
    await browserPost('heartbeat', canary, { ...acknowledgment, assignmentVersion: 0 }, 400);
    await browserPost('heartbeat', canary, acknowledgment);
    const scopedEvent = { ...event, eventId: randomUUID(), policyVersion: candidate.version, decision: 'block', assignmentVersion: 1 };
    await browserPost('events', control, scopedEvent, 400);
    const observation = { appId: 'gemini', observedAt: new Date().toISOString(), policyVersion: candidate.version, assignmentVersion: 1 };
    const newBaseline = await admin('policies', { method: 'POST', body: { mode: 'monitor', discoveryEnabled: false } });
    await browserPost('ai-app-observations', canary, observation);
    const warn = await scoped('', { method: 'POST', body: { mode: 'warn', discoveryEnabled: false } });
    await browserPost('ai-app-observations', canary, observation, 400);
    const restored = await scoped(`/${candidate.version}/restore`, { method: 'POST' });
    assert.ok(restored.version > warn.version && restored.version > newBaseline.version);
    assert.deepEqual(restored.domainRules, domainRules);
    const active = await fetchPolicy(canary);
    assert.equal(active.version, restored.version);
    assert.equal(active.assignmentVersion, 1);
    await assign(canary, null);
    assert.deepEqual(await fetchPolicy(canary), { ...browserPolicyOnly(newBaseline), assignmentVersion: 2 });
    await browserPost('heartbeat', canary, { ...acknowledgment, policyVersion: restored.version }, 400);
    await browserPost('heartbeat', canary, { policyVersion: newBaseline.version, assignmentVersion: 2 });
    await browserPost('events', canary, scopedEvent);
    await browserPost('ai-app-observations', canary, observation, 400);
    assert.equal((await admin('events')).find(({ eventId }) => eventId === scopedEvent.eventId).policyVersion, candidate.version);
    await admin(`${groupPath}/promote`, { method: 'POST', body: { expectedVersion: candidate.version }, expect: 409 });
    assert.deepEqual(await fetchPolicy(control), browserPolicyOnly(newBaseline));
    const promoted = await admin(`${groupPath}/promote`, { method: 'POST', body: { expectedVersion: restored.version } });
    assert.equal(promoted.mode, restored.mode);
    assert.equal(promoted.githubPatMode, restored.githubPatMode);
    assert.equal(promoted.discoveryEnabled, restored.discoveryEnabled);
    assert.deepEqual(promoted.domainRules, restored.domainRules);
    assert.deepEqual(await fetchPolicy(control), browserPolicyOnly(promoted));
    const actions = await admin('audit?action=policy_group_assigned');
    assert.deepEqual(actions.entries.map(({ groupChange }) => groupChange.groupId), [null, pilot.id]);
    assert.ok((await admin('audit?action=policy_published')).entries.some(({ policyVersion, groupChange }) =>
      policyVersion === promoted.version && groupChange.groupId === pilot.id && groupChange.sourceVersion === restored.version));
    await stop();
    await start();
    assert.deepEqual(await fetchPolicy(canary), { ...browserPolicyOnly(promoted), assignmentVersion: 2 });
    assert.deepEqual((await scoped()).map(({ version }) => version), [restored.version, warn.version, candidate.version]);
  });

  await t.test('previewed publishes apply exactly one snapshot against the effective reference version', async () => {
    const admin = (path, options = {}) => call(`/v1/admin/${path}`, { token: first, ...options });
    const baseline = async () => (await admin('policies'))[0];
    const reference = await baseline();
    const proposal = { mode: 'warn', githubPatMode: 'block', discoveryEnabled: true,
      domainRules: { allow: ['WORK.PREVIEW.TEST.'], block: ['preview.test'] } };
    const publish = (path, body, expect = 200) => admin(path, { method: 'POST', body, expect });
    await publish('policies', { ...proposal, expectedVersion: 0 }, 400);
    const priorAudit = (await admin('audit?action=policy_published')).entries.length;
    const copies = await Promise.all([1, 2].map(() => fetch(`${baseUrl}/v1/admin/policies`, {
      method: 'POST', headers: { Authorization: `Bearer ${first}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...proposal, expectedVersion: reference.version }), signal: AbortSignal.timeout(5000),
    })));
    assert.deepEqual(copies.map(({ status }) => status).sort(), [200, 409]);
    const current = await copies.find((response) => response.ok).json();
    assert.equal(current.mode, proposal.mode);
    assert.equal(current.githubPatMode, proposal.githubPatMode);
    assert.equal(current.discoveryEnabled, proposal.discoveryEnabled);
    assert.deepEqual(current.domainRules, { allow: ['work.preview.test'], block: ['preview.test'] });
    assert.deepEqual(await baseline(), current);
    assert.equal((await admin('audit?action=policy_published')).entries.length, priorAudit + 1);

    const group = await publish('policy-groups', { name: 'Preview cohort' });
    const scopedPath = `policy-groups/${group.id}/policies`;
    const advanced = await publish('policies', { mode: 'monitor' });
    await publish(scopedPath, { ...proposal, expectedVersion: current.version }, 409);
    assert.deepEqual(await admin(scopedPath), []);
    const scoped = await publish(scopedPath, { ...proposal, expectedVersion: advanced.version });
    assert.equal(scoped.mode, proposal.mode);
    assert.deepEqual(await baseline(), advanced);
    const newerBaseline = await publish('policies', { mode: 'block' });
    const nextScoped = await publish(scopedPath, { mode: 'monitor', expectedVersion: scoped.version });
    assert.deepEqual(nextScoped.domainRules, scoped.domainRules);
    assert.deepEqual(await baseline(), newerBaseline);
  });

  await t.test('pages and exports all matching retained metadata with tenant isolation and stable ties', async () => {
    const admin = (path, options = {}) => call(`/v1/admin/${path}`, { token: first, ...options });
    const [policy] = await admin('policies');
    async function enroll() {
      const { grant } = await admin('enrollment-grants', { method: 'POST' });
      return call('/v1/enroll', { method: 'POST', body: { grant } });
    }
    const [one, two] = await Promise.all([enroll(), enroll()]);
    const timestamp = new Date().toISOString();
    const until = new Date(Date.parse(timestamp) + 60_000).toISOString();
    const core = { ...event, timestamp, appId: 'chatgpt', policyVersion: policy.version, decision: policy.mode };
    const submit = (browser, body, expect = 204) => call('/v1/browser/events', { method: 'POST', token: browser.token, body, expect });
    const rows = Array.from({ length: 100 }, () => ({ ...core, eventId: randomUUID() }));
    for (let index = 0; index < rows.length; index += 10)
      await Promise.all(rows.slice(index, index + 10).map((row) => submit(one, row)));
    const duplicate = { ...core, eventId: randomUUID() };
    await Promise.all([submit(one, duplicate), submit(two, duplicate), submit(two, duplicate)]);
    await submit(one, { ...core, eventId: randomUUID(), timestamp: until });
    await submit(one, { ...core, eventId: randomUUID(), appId: 'local-prompt-fixture' });
    await submit(one, { ...core, eventId: randomUUID(), prompt: 'private-synthetic-export-sample' }, 400);

    if (postgres) {
      await retentionFixture(`UPDATE security_events SET received_at = CASE WHEN event_id = '${duplicate.eventId}'
        THEN '2026-01-03T01:02:03.123456Z'::timestamptz ELSE '2026-01-03T01:02:04.123456Z'::timestamptz END
        WHERE (installation_id = '${one.installationId}' OR installation_id = '${two.installationId}') AND occurred_at = '${timestamp}'
          AND app_id = 'chatgpt';`);
      await retentionFixture(`UPDATE security_events SET received_at = '2026-01-03T01:02:01.123456Z'::timestamptz
        WHERE installation_id = '${one.installationId}' AND event_id = '${rows.at(-1).eventId}';`);
    }
    const params = new URLSearchParams({ since: timestamp, until, appId: 'chatgpt', decision: policy.mode });
    const history = (filters = params) => admin(`events/history?${filters}`);
    const firstPage = await history();
    assert.equal(firstPage.entries.length, 100);
    const last = firstPage.entries.at(-1);
    assert.equal(Date.parse(firstPage.next.receivedAt), Date.parse(last.receivedAt));
    assert.equal(firstPage.next.eventId, last.eventId);
    assert.equal(firstPage.next.installationId, last.installationId);
    if (postgres) assert.equal(last.eventId, duplicate.eventId);

    const next = new URLSearchParams(params);
    next.set('beforeAt', firstPage.next.receivedAt);
    next.set('beforeEventId', firstPage.next.eventId);
    next.set('beforeInstallationId', firstPage.next.installationId);
    const inserted = { ...core, eventId: randomUUID() };
    await submit(one, inserted);
    const older = await history(next);
    assert.equal(older.next, null);
    assert.equal(older.entries.length, 2);
    const paged = [...firstPage.entries, ...older.entries];
    assert.equal(new Set(paged.map(({ installationId, eventId }) => `${installationId}:${eventId}`)).size, 102);
    assert.equal(paged.filter(({ eventId }) => eventId === duplicate.eventId).length, 2);
    assert.equal(paged.some(({ eventId }) => eventId === inserted.eventId), false);

    const exported = await fetch(`${baseUrl}/v1/admin/events/export?${params}`, {
      headers: { Authorization: `Bearer ${first}` }, signal: AbortSignal.timeout(5000),
    });
    assert.equal(exported.status, 200);
    assert.match(exported.headers.get('content-disposition'), /attachment; filename="zekvar-security-events\.json"/);
    assert.equal(exported.headers.get('cache-control'), 'no-store');
    const json = await exported.text();
    const { organization, exportedAt, filters, entries } = JSON.parse(json);
    assert.equal(organization, `first-${suffix}`);
    assert.ok(Number.isFinite(Date.parse(exportedAt)));
    assert.equal(Date.parse(filters.since), Date.parse(timestamp));
    assert.equal(Date.parse(filters.until), Date.parse(until));
    assert.deepEqual(entries.slice(1), paged);
    assert.equal(entries[0].eventId, inserted.eventId);
    assert.deepEqual(Object.keys(entries[0]).sort(), [
      'appId', 'decision', 'detectorCategory', 'eventId', 'installationId', 'policyVersion', 'receivedAt', 'rollout', 'ruleId', 'timestamp',
    ]);
    assert.equal([first, one.token, two.token, 'private-synthetic-export-sample'].some((value) => json.includes(value)), false);

    const single = new URLSearchParams(params);
    single.set('installationId', two.installationId);
    assert.deepEqual((await admin(`events/export?${single}`)).entries, entries.filter(({ installationId }) => installationId === two.installationId));
    assert.deepEqual((await admin(`events/export?${single}`, { token: second })).entries, []);
    assert.deepEqual((await admin(`events/history?${next}`, { token: second })).entries, []);
    await call('/v1/admin/events/history', { expect: 401 });
    await call('/v1/admin/events/export', { expect: 401 });
    await admin('events/export', { token: one.token, expect: 401 });
    await admin('events/history?beforeAt=2026-01-03T01:02:03Z', { expect: 400 });
    await admin('events/history?installationId=invalid', { expect: 400 });
    await admin('events/export?decision=invalid', { expect: 400 });
    await admin('events/export?since=2026-02-01T00:00:00Z&until=2026-01-01T00:00:00Z', { expect: 400 });

    if (postgres) {
      // Recreate schema 8's original index around existing records and let the application upgrade it.
      await stop();
      await retentionFixture(`
        DELETE FROM schema_migrations WHERE version = 9;
        DROP INDEX events_by_organization_recency;
        CREATE INDEX events_by_organization_recency ON security_events (organization_id, received_at DESC, event_id);
      `);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 9'), '1');
      assert.deepEqual((await admin(`events/export?${params}`)).entries, entries);
    }
  });

  await t.test('stores Gemini coverage and decisions independently and preserves previous ChatGPT records on upgrade', async () => {
    const admin = (path, options = {}) => call(`/v1/admin/${path}`, { token: first, ...options });
    const { grant } = await admin('enrollment-grants', { method: 'POST' });
    const browser = await call('/v1/enroll', { method: 'POST', body: { grant } });
    const [policy] = await admin('policies');
    assert.deepEqual(policy.appIds, ['local-prompt-fixture', 'chatgpt', 'gemini']);
    const send = (path, body, expect = 204) => call(`/v1/browser/${path}`, { token: browser.token, method: 'POST', body, expect });
    const installation = async () => (await admin('installations')).find(({ installationId }) => installationId === browser.installationId);
    const scoped = (appId) => new URLSearchParams({ appId, installationId: browser.installationId }).toString();
    const sample = { ...event, eventId: randomUUID(), appId: 'chatgpt', decision: policy.mode, policyVersion: policy.version };
    await send('events', sample);
    await send('heartbeat', { policyVersion: policy.version, chatGptCoverage: 'ready', domainRulesApplied: true });
    const original = await installation();
    const legacyRows = (await admin(`events/history?${scoped('chatgpt')}`)).entries;
    assert.equal(legacyRows.length, 1);
    assert.equal(original.chatGptCoverage, 'ready');
    assert.equal(original.geminiCoverage, null);

    if (postgres) {
      await stop();
      await retentionFixture(`
        DELETE FROM schema_migrations WHERE version = 10;
        ALTER TABLE security_events DROP CONSTRAINT security_events_app_id_check,
            ADD CONSTRAINT security_events_app_id_check CHECK (app_id IN ('local-prompt-fixture', 'chatgpt'));
        ALTER TABLE installations DROP COLUMN gemini_coverage, DROP COLUMN gemini_checked_at;
      `);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 10'), '1');
      assert.deepEqual(await installation(), original);
      assert.deepEqual((await admin(`events/history?${scoped('chatgpt')}`)).entries, legacyRows);
    }

    await send('heartbeat', { policyVersion: policy.version, geminiCoverage: 'draft content', domainRulesApplied: true }, 400);
    await send('heartbeat', { policyVersion: 2147483647, geminiCoverage: 'ready', domainRulesApplied: true }, 400);
    await send('heartbeat', { policyVersion: policy.version, assignmentVersion: 1, geminiCoverage: 'ready', domainRulesApplied: true }, 400);
    assert.equal((await installation()).geminiCoverage, null);
    await send('heartbeat', { policyVersion: policy.version, geminiCoverage: 'unsupported', domainRulesApplied: true });
    assert.equal((await installation()).geminiCoverage, 'unsupported');
    await send('heartbeat', { policyVersion: policy.version, geminiCoverage: 'ready', domainRulesApplied: true });
    assert.equal((await installation()).geminiCoverage, 'ready');
    assert.equal((await installation()).chatGptCheckedAt, original.chatGptCheckedAt);
    assert.ok(Number.isFinite(Date.parse((await installation()).geminiCheckedAt)));

    const gemini = { ...sample, eventId: randomUUID(), appId: 'gemini' };
    await send('events', { ...gemini, prompt: 'Private synthetic Gemini prompt' }, 400);
    await send('events', { ...gemini, appId: 'claude' }, 400);
    await send('events', gemini);
    await send('events', gemini);
    const history = (await admin(`events/history?${scoped('gemini')}`)).entries;
    assert.equal(history.length, 1);
    assert.equal(history[0].eventId, gemini.eventId);
    assert.equal(history[0].appId, 'gemini');
    assert.deepEqual((await admin(`events/export?${scoped('gemini')}`)).entries, history);
    assert.deepEqual((await admin(`events/export?${scoped('gemini')}`, { token: second })).entries, []);
  });

  await t.test('requires payment detector acknowledgment and validates decision metadata against historical policy', async () => {
    const admin = (path, options = {}) => call(`/v1/admin/${path}`, { token: first, ...options });
    const publish = (body, expect = 200) => admin('policies', { method: 'POST', body, expect });
    const [initial] = await admin('policies');
    assert.equal(initial.paymentCardMode, 'off');
    const { grant } = await admin('enrollment-grants', { method: 'POST' });
    const browser = await call('/v1/enroll', { method: 'POST', body: { grant } });
    const post = (path, body, expect = 204) => call(`/v1/browser/${path}`, { method: 'POST', token: browser.token, body, expect });
    const installation = async () => (await admin('installations')).find(({ installationId }) => installationId === browser.installationId);
    const legacyEvents = await admin('events');
    if (postgres) {
      await stop();
      await retentionFixture(`
        ${undoSsnSchema}
        DELETE FROM schema_migrations WHERE version IN (11, 12);
        ALTER TABLE policy_versions DROP COLUMN payment_card_mode, DROP COLUMN chatgpt_upload_mode, DROP COLUMN gemini_upload_mode;
        ALTER TABLE security_events DROP CONSTRAINT security_events_upload_method_check, DROP COLUMN upload_method;
        ALTER TABLE security_events DROP CONSTRAINT security_events_rule_id_check,
            ADD CONSTRAINT security_events_rule_id_check CHECK (rule_id IN ('fixture-secret', 'github-classic-pat'));
      `);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 11'), '1');
      assert.deepEqual((await admin('policies'))[0], initial);
      assert.deepEqual(await admin('events'), legacyEvents);
    }

    const heartbeat = (policyVersion, extra) => post('heartbeat', { policyVersion, domainRulesApplied: true, ...extra });
    await heartbeat(initial.version);
    const card = { ...event, timestamp: new Date().toISOString(), eventId: randomUUID(), appId: 'gemini',
      decision: 'block', policyVersion: initial.version, ruleId: 'payment-card-number', detectorCategory: 'payment-card' };
    await post('events', card, 400);
    await publish({ paymentCardMode: 'allow' }, 400);
    const block = await publish({ paymentCardMode: 'block', expectedVersion: initial.version });
    assert.equal(block.mode, initial.mode);
    assert.equal(block.githubPatMode, initial.githubPatMode);
    assert.deepEqual(block.domainRules, initial.domainRules);
    await heartbeat(block.version);
    assert.equal((await installation()).appliedPolicyVersion, initial.version);
    assert.equal((await installation()).expectedPolicyVersion, block.version);
    await heartbeat(block.version, { paymentCardModeApplied: true });
    assert.equal((await installation()).appliedPolicyVersion, block.version);
    await heartbeat(initial.version);
    assert.equal((await installation()).appliedPolicyVersion, block.version);
    await heartbeat(block.version);
    assert.equal((await installation()).appliedPolicyVersion, null);
    await heartbeat(block.version, { paymentCardModeApplied: true });
    assert.equal((await installation()).appliedPolicyVersion, block.version);

    const blocked = { ...card, policyVersion: block.version };
    await post('events', { ...blocked, cardNumber: '4242424242424242' }, 400);
    await post('events', { ...blocked, detectorCategory: 'credential' }, 400);
    await post('events', { ...blocked, decision: 'warn_override' }, 400);
    await post('events', blocked);
    await post('events', blocked);
    const warned = await publish({ paymentCardMode: 'warn' });
    const restored = await admin(`policies/${initial.version}/restore`, { method: 'POST' });
    assert.equal(restored.paymentCardMode, 'off');
    await heartbeat(restored.version);
    assert.equal((await installation()).appliedPolicyVersion, restored.version);
    await post('events', { ...card, eventId: randomUUID(), policyVersion: warned.version, decision: 'warn_override' });
    await post('events', { ...card, eventId: randomUUID(), policyVersion: restored.version }, 400);
    const query = new URLSearchParams({ installationId: browser.installationId });
    const { entries } = await admin(`events/export?${query}`);
    assert.equal(entries.length, 2);
    assert.ok(entries.every((entry) => entry.detectorCategory === 'payment-card' && entry.ruleId === 'payment-card-number'));
    assert.deepEqual(entries.map(({ decision }) => decision).sort(), ['block', 'warn_override']);
    assert.ok(!JSON.stringify(entries).includes('4242424242424242'));
    assert.deepEqual((await admin(`events/export?${query}`, { token: second })).entries, []);
  });

  await t.test('versions and validates file upload policy by destination and exports the attempt method', async () => {
    const admin = (path, options = {}) => call(`/v1/admin/${path}`, { token: first, ...options });
    const publish = (body, expect = 200) => admin('policies', { method: 'POST', body, expect });
    const [before] = await admin('policies');
    assert.deepEqual(before.uploadModes, { chatgpt: 'off', gemini: 'off' });
    const history = await admin('events');
    if (postgres) {
      await stop();
      await retentionFixture(`
        ${undoSsnSchema}
        DELETE FROM schema_migrations WHERE version = 12;
        ALTER TABLE policy_versions DROP COLUMN chatgpt_upload_mode, DROP COLUMN gemini_upload_mode;
        ALTER TABLE security_events DROP CONSTRAINT security_events_upload_method_check, DROP COLUMN upload_method,
            DROP CONSTRAINT security_events_rule_id_check,
            ADD CONSTRAINT security_events_rule_id_check CHECK (rule_id IN ('fixture-secret', 'github-classic-pat', 'payment-card-number'));
      `);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 12'), '1');
      assert.deepEqual((await admin('policies'))[0], before);
      assert.deepEqual(await admin('events'), history);
    }
    const { grant } = await admin('enrollment-grants', { method: 'POST' });
    const client = await call('/v1/enroll', { method: 'POST', body: { grant } });
    const submit = (path, body, expect = 204) => call(`/v1/browser/${path}`, { token: client.token, method: 'POST', body, expect });
    const applied = async () => (await admin('installations')).find(({ installationId }) => installationId === client.installationId).appliedPolicyVersion;
    const heartbeat = (policyVersion, flags) => submit('heartbeat', { policyVersion, domainRulesApplied: true, ...flags });
    await heartbeat(before.version);
    await publish({ uploadModes: {} }, 400);
    await publish({ uploadModes: { chatgpt: 'warn' } }, 400);
    await publish({ uploadModes: { copilot: 'block' } }, 400);
    await publish({ uploadModes: { claude: 'warn' } }, 400);
    const monitor = await publish({ uploadModes: { chatgpt: 'monitor' }, expectedVersion: before.version });
    const block = await publish({ uploadModes: { gemini: 'block' }, expectedVersion: monitor.version });
    await publish({ uploadModes: { gemini: 'off' }, expectedVersion: monitor.version }, 409);
    assert.deepEqual(block.uploadModes, { chatgpt: 'monitor', gemini: 'block' });
    assert.equal(block.paymentCardMode, before.paymentCardMode);
    await heartbeat(block.version);
    assert.equal(await applied(), before.version);
    await heartbeat(block.version, { uploadControlsApplied: true });
    assert.equal(await applied(), block.version);

    const attempt = { ...event, eventId: randomUUID(), timestamp: new Date().toISOString(), policyVersion: block.version,
      appId: 'gemini', decision: 'block', ruleId: 'ai-file-upload', detectorCategory: 'file-upload', uploadMethod: 'picker' };
    for (const invalid of [
      { ...attempt, appId: 'chatgpt' }, { ...attempt, appId: 'local-prompt-fixture' }, { ...attempt, policyVersion: monitor.version },
      { ...attempt, detectorCategory: 'credential' }, { ...attempt, decision: 'warn_override' }, { ...attempt, uploadMethod: null },
      { ...attempt, uploadMethod: 'unknown' }, { ...attempt, fileName: 'private-attachment.txt' },
    ]) await submit('events', invalid, 400);
    await submit('events', { ...event, eventId: randomUUID(), uploadMethod: 'picker' }, 400);
    await submit('events', attempt);
    await submit('events', attempt);
    const paste = { ...attempt, eventId: randomUUID(), appId: 'chatgpt', decision: 'monitor', uploadMethod: 'paste' };
    await submit('events', paste);
    const restore = await admin(`policies/${before.version}/restore`, { method: 'POST' });
    assert.deepEqual(restore.uploadModes, before.uploadModes);
    await heartbeat(restore.version);
    assert.equal(await applied(), restore.version);
    await submit('events', { ...attempt, eventId: randomUUID(), policyVersion: restore.version }, 400);
    const query = new URLSearchParams({ installationId: client.installationId });
    const { entries } = await admin(`events/export?${query}`);
    assert.deepEqual(entries.map(({ eventId, uploadMethod }) => [eventId, uploadMethod]), [[paste.eventId, 'paste'], [attempt.eventId, 'picker']]);
    assert.equal(entries.some((row) => 'fileName' in row || 'content' in row), false);
    assert.deepEqual((await admin(`events/export?${query}`, { token: second })).entries, []);
  });

  await t.test('versions scoped file types, preserves prior upload events, and distinguishes legacy acknowledgments', async () => {
    const admin = (path, options) => call(`/v1/admin/${path}`, { token: first, ...options });
    const publish = (body, expect = 200) => admin('policies', { method: 'POST', body, expect });
    const [before] = await admin('policies');
    const previousEvents = await admin('events');
    assert.deepEqual(before.uploadTypes, { chatgpt: [], gemini: [] });
    if (postgres) {
      await stop();
      await retentionFixture(`
        DELETE FROM schema_migrations WHERE version = 17;
        ALTER TABLE policy_versions DROP COLUMN chatgpt_upload_types, DROP COLUMN gemini_upload_types;
      `);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 17'), '1');
      assert.deepEqual((await admin('policies'))[0], before);
      assert.deepEqual(await admin('events'), previousEvents);
    }
    for (const uploadTypes of [
      {}, { copilot: ['.pdf'] }, { claude: ['*.pdf'] }, { chatgpt: [null] }, { chatgpt: '.pdf' }, { chatgpt: ['   '] },
      { chatgpt: ['*.pdf'] }, { chatgpt: ['foo/bar*'] }, { chatgpt: ['.foo/bar'] },
      { chatgpt: ['.' + 'x'.repeat(64)] }, { gemini: Array.from({ length: 26 }, (_, index) => `.ext${index}`) },
    ]) await publish({ uploadTypes }, 400);
    const { grant } = await admin('enrollment-grants', { method: 'POST' });
    const client = await call('/v1/enroll', { method: 'POST', body: { grant } });
    const browser = (path, options) => call(`/v1/browser/${path}`, { token: client.token, ...options });
    const applied = async () => (await admin('installations')).find(({ installationId }) => installationId === client.installationId).appliedPolicyVersion;
    const heartbeat = (version, flags) => browser('heartbeat', { method: 'POST', expect: 204, body: {
      policyVersion: version, domainRulesApplied: true, pathRulesApplied: true, paymentCardModeApplied: true, ...flags,
    } });
    const scoped = await publish({
      uploadModes: { chatgpt: 'block', gemini: 'monitor' },
      uploadTypes: { chatgpt: ['Image/*', ' .PDF ', '.archive.TAR.GZ', '.pdf'] },
      expectedVersion: before.version,
    });
    assert.deepEqual(scoped.uploadTypes, { chatgpt: ['.archive.tar.gz', '.pdf', 'image/*'], gemini: [] });
    const revised = await publish({ uploadTypes: { gemini: ['TEXT/CSV'] }, expectedVersion: scoped.version });
    await publish({ uploadTypes: { chatgpt: [] }, expectedVersion: scoped.version }, 409);
    assert.deepEqual(revised.uploadTypes, { ...scoped.uploadTypes, gemini: ['text/csv'] });
    const delivered = await browser('policy');
    assert.deepEqual(delivered.uploadModes, { chatgpt: 'off', gemini: 'off' });
    assert.deepEqual(delivered.targetedUploads, {
      chatgpt: { mode: 'block', types: scoped.uploadTypes.chatgpt }, gemini: { mode: 'monitor', types: ['text/csv'] },
    });
    assert.equal(delivered.uploadTypes, undefined);
    await heartbeat(revised.version, { uploadControlsApplied: true });
    assert.equal(await applied(), null);
    await heartbeat(revised.version, { uploadControlsApplied: true, uploadTypesApplied: true });
    assert.equal(await applied(), revised.version);
    const modes = await publish({ uploadModes: { gemini: 'off' }, uploadTypes: { chatgpt: [] } });
    assert.deepEqual(modes.uploadTypes, { chatgpt: [], gemini: ['text/csv'] });
    assert.equal((await browser('policy')).targetedUploads, undefined);
    await heartbeat(modes.version, { uploadControlsApplied: true });
    assert.equal(await applied(), modes.version);
    const restored = await admin(`policies/${revised.version}/restore`, { method: 'POST' });
    assert.deepEqual(restored.uploadTypes, revised.uploadTypes);
    assert.deepEqual((await browser('policy')).targetedUploads, delivered.targetedUploads);
    const attempt = { ...event, eventId: randomUUID(), timestamp: new Date().toISOString(), policyVersion: revised.version,
      appId: 'chatgpt', decision: 'block', ruleId: 'ai-file-upload', detectorCategory: 'file-upload', uploadMethod: 'drop' };
    await browser('events', { method: 'POST', body: { ...attempt, fileType: 'application/pdf' }, expect: 400 });
    await browser('events', { method: 'POST', body: attempt, expect: 204 });
    await browser('events', { method: 'POST', body: attempt, expect: 204 });
    const query = `events/export?installationId=${client.installationId}`;
    const { entries } = await admin(query);
    assert.deepEqual(entries.map(({ eventId }) => eventId), [attempt.eventId]);
    assert.deepEqual((await admin(query, { token: second })).entries, []);
    await publish({
      domainRules: { allow: [], block: [] },
      pathRules: { allow: [], block: Array.from({ length: 50 }, (_, index) =>
        `${'x'.repeat(61)}${String(index).padStart(2, '0')}.${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(61)}/${'x'.repeat(63)}`) },
      uploadTypes: Object.fromEntries(['chatgpt', 'gemini'].map((app) => [app,
        Array.from({ length: 25 }, (_, index) => `.${'x'.repeat(61)}${String(index).padStart(2, '0')}`)])),
    });
    await admin(`policies/${before.version}/restore`, { method: 'POST' });
  });

  await t.test('validates and versions path policies without falsely acknowledging legacy browsers', async () => {
    const admin = (path, options) => call(`/v1/admin/${path}`, { token: first, ...options });
    const publish = (body, expect = 200) => admin('policies', { method: 'POST', body, expect });
    const history = async () => (await admin('policies'))[0];
    const original = await history();
    const empty = { allow: [], block: [] };
    assert.deepEqual(original.pathRules, empty);
    if (postgres) {
      await stop();
      await retentionFixture(`
        DELETE FROM schema_migrations WHERE version = 13;
        ALTER TABLE policy_versions DROP COLUMN allowed_paths, DROP COLUMN blocked_paths;
      `);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 13'), '1');
      assert.deepEqual(await history(), original);
    }

    const { grant } = await admin('enrollment-grants', { method: 'POST' });
    const browser = await call('/v1/enroll', { method: 'POST', body: { grant } });
    const policy = () => call('/v1/browser/policy', { token: browser.token });
    const heartbeat = (policyVersion, flags) => call('/v1/browser/heartbeat', {
      token: browser.token, method: 'POST', expect: 204,
      body: { policyVersion, domainRulesApplied: true, paymentCardModeApplied: true, uploadControlsApplied: true, ...flags },
    });
    const installed = async () => (await admin('installations')).find(({ installationId }) => installationId === browser.installationId);
    await heartbeat((await policy()).version);
    assert.equal((await installed()).appliedPolicyVersion, original.version);

    const paths = { allow: [' APPS.TEST./Work/ ', 'apps.test/Work'], block: ['apps.test/Work/private'] };
    for (const entry of ['apps.test', 'apps.test/', 'https://apps.test/x', 'apps.test:443/x', 'apps.test/a//b', 'apps.test/a/../b',
      'apps.test/a?x', 'apps.test/a#x', 'apps.test/%61', 'apps.test/é', 'apps.test/' + 'a'.repeat(64), 'apps.test/Work', null]) {
      await publish({ pathRules: { allow: paths.allow, block: [entry] } }, 400);
    }
    await publish({ pathRules: { allow: [] } }, 400);
    await admin('policies', { token: browser.token, method: 'POST', body: { pathRules: paths }, expect: 401 });
    assert.deepEqual(await history(), original);

    const active = await publish({ pathRules: paths, expectedVersion: original.version });
    const canonical = { allow: ['apps.test/Work'], block: ['apps.test/Work/private'] };
    assert.deepEqual(active.pathRules, canonical);
    assert.deepEqual(active.domainRules, original.domainRules);
    assert.deepEqual((await policy()).pathRules, canonical);
    assert.deepEqual((await admin('policies', { token: second }))[0].pathRules, empty);
    await heartbeat(active.version);
    assert.equal((await installed()).expectedPolicyVersion, active.version);
    assert.equal((await installed()).appliedPolicyVersion, original.version);
    await heartbeat(active.version, { pathRulesApplied: true });
    assert.equal((await installed()).appliedPolicyVersion, active.version);

    const hosts = Array.from({ length: 49 }, (_, index) => `host${index}.test`);
    const audit = await admin('audit');
    await publish({ domainRules: { allow: hosts, block: [] } }, 400);
    assert.deepEqual(await history(), active);
    assert.deepEqual(await admin('audit'), audit);
    const full = await publish({ domainRules: { allow: hosts.slice(1), block: [] } });
    assert.equal(full.version, active.version + 1);
    assert.deepEqual(full.pathRules, canonical);
    await publish({ pathRules: { ...canonical, block: [...canonical.block, 'apps.test/other'] } }, 400);
    await publish({ pathRules: empty, expectedVersion: active.version }, 409);
    assert.deepEqual(await history(), full);
    const clear = await publish({ pathRules: empty });
    assert.deepEqual(clear.pathRules, empty);
    assert.deepEqual(clear.domainRules, full.domainRules);
    const restored = await admin(`policies/${active.version}/restore`, { method: 'POST' });
    assert.deepEqual(restored.pathRules, canonical);
    assert.deepEqual(restored.domainRules, active.domainRules);
    assert.equal(restored.restoredFrom, active.version);
  });

  await t.test('delegates named owner-scoped Control access with expiry, revocation, and metadata-only audit', async () => {
    const admin = (path, options) => call(`/v1/admin/${path}`, { token: first, ...options });
    const audit = (options) => admin('audit?limit=1000', options);
    const auditBefore = await audit();
    const currentBefore = (await admin('policies'))[0];
    const secondBefore = await audit({ token: second });
    if (postgres) {
      await stop();
      await retentionFixture(`
        ${undoIncidentSchema}
        DELETE FROM schema_migrations WHERE version IN (14, 15, 21, 31);
        DROP TABLE control_sso_sessions;
        DROP TABLE policy_reviews;
        DROP TABLE event_triage;
        ALTER TABLE organizations DROP COLUMN require_policy_review;
        ALTER TABLE control_audit DROP COLUMN review_change, DROP COLUMN actor_access_id, DROP COLUMN subject_access_id,
          DROP COLUMN event_triage_change;
        DROP TABLE control_access;
      `);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 14'), '1');
      assert.deepEqual(await audit(), auditBefore);
      assert.deepEqual((await admin('policies'))[0], currentBefore);
    }
    const issue = (name, role, hours, expect = 200, token = first) =>
      admin('access', { token, method: 'POST', body: { name, role, hours }, expect });
    const revoke = (id, token = first, expect = 204) => admin(`access/${id}/revoke`, { token, method: 'POST', expect });
    const session = (token, expect = 200) => admin('session', { token, expect });
    assert.deepEqual(await admin('access'), []);
    await issue('Operator', 'owner', 24, 400);
    await issue('Operator', 'auditor', 0, 400);
    await issue('Operator', 'auditor', 721, 400);
    await issue('bad\nname', 'auditor', 1, 400);
    await issue(' ', 'auditor', 1, 400);
    assert.deepEqual(await audit(), auditBefore);
    const operator = await issue(' Jordan Demo ', 'administrator', 24);
    const reviewer = await issue('Kai Review', 'auditor', 1);
    const named = ({ access: { id, name, role } }) => ({ id, name, role });
    for (const issued of [operator, reviewer]) {
      assert.match(issued.token, /^[a-f0-9]{64}$/);
      assert.equal(issued.access.status, 'active');
      assert.deepEqual(await session(issued.token), {
        organization: `first-${suffix}`, role: issued.access.role, access: named(issued), reviewRequired: false,
      });
      await admin('access', { token: issued.token, expect: 403 });
      await issue('Escalation attempt', 'administrator', 24, 403, issued.token);
      await revoke(reviewer.access.id, issued.token, 403);
      await call('/v1/browser/policy', { token: issued.token, expect: 401 });
    }
    assert.equal(operator.access.name, 'Jordan Demo');
    assert.equal(Date.parse(reviewer.access.expiresAt) - Date.parse(reviewer.access.issuedAt), 3_600_000);
    assert.deepEqual(await admin('access', { token: second }), []);
    await revoke(operator.access.id, second, 404);
    if (postgres) {
      const hash = createHash('sha256').update(operator.token).digest('hex');
      assert.equal(await retentionFixture(`SELECT token_hash FROM control_access WHERE id = '${operator.access.id}'`), hash);
    }

    const fromOperator = (path, options) => admin(path, { token: operator.token, ...options });
    const change = (path, body, expect = 200) => fromOperator(path, { method: 'POST', body, expect });
    const granted = await change('enrollment-grants');
    const enrolled = await call('/v1/enroll', { method: 'POST', body: { grant: granted.grant } });
    await admin('access', { token: enrolled.token, expect: 401 });
    await call('/v1/browser/policy', { token: enrolled.token, assignmentAware: true });
    const group = await change('policy-groups', { name: 'Named access pilot' });
    const scoped = await change(`policy-groups/${group.id}/policies`, { mode: 'block' });
    await change(`installations/${enrolled.installationId}/policy-group`, { groupId: group.id }, 204);
    const promoted = await change(`policy-groups/${group.id}/promote`, { expectedVersion: scoped.version });
    const restored = await change(`policies/${currentBefore.version}/restore`);
    assert.equal(restored.version, promoted.version + 1);
    const classification = (await admin('ai-apps')).find(({ appId }) => appId === 'gemini').status === 'approved' ? 'unapproved' : 'approved';
    await change('ai-apps/gemini/classification', { status: classification }, 204);
    await change(`installations/${enrolled.installationId}/revoke`, undefined, 204);
    const retention = await admin('retention');
    await change('retention', { ...retention, auditDays: 60 }, 204);
    const actions = ['app_classified', 'browser_revoked', 'grant_issued', 'policy_group_assigned',
      'policy_group_created', 'policy_published', 'policy_published', 'policy_restored', 'retention_changed'];
    if (postgres) {
      await retentionFixture(`
        INSERT INTO control_audit (organization_id, occurred_at, action)
        SELECT id, now() - interval '61 days', 'grant_issued' FROM organizations WHERE slug = 'first-${suffix}'
      `);
      assert.ok((await change('retention/cleanup')).auditEntries >= 1);
      actions.push('retention_cleanup');
    }
    const authorized = await audit({ token: reviewer.token });
    const actorRows = authorized.entries.filter(({ actorAccess }) => actorAccess?.id === operator.access.id);
    assert.deepEqual(actorRows.map(({ action }) => action).sort(), actions.sort());
    assert.ok(actorRows.every(({ actor, actorAccess }) =>
      actor === 'named_administrator' && actorAccess.name === operator.access.name && actorAccess.role === 'administrator'));
    assert.deepEqual(await audit({ token: second }), secondBefore);

    for (const path of ['policies', 'policy-groups', `policy-groups/${group.id}/policies`, 'installations',
      'events', 'events/history', 'events/export', 'audit', 'retention', 'ai-apps']) await admin(path, { token: reviewer.token });
    for (const [path, body] of [
      ['policies', { mode: 'monitor' }], [`policies/${currentBefore.version}/restore`], ['enrollment-grants'],
      [`installations/${enrolled.installationId}/revoke`], ['policy-groups', { name: 'Reject group' }],
      [`policy-groups/${group.id}/policies`, { mode: 'monitor' }], [`policy-groups/${group.id}/policies/${scoped.version}/restore`],
      [`policy-groups/${group.id}/promote`, { expectedVersion: scoped.version }],
      [`installations/${enrolled.installationId}/policy-group`, { groupId: null }],
      ['ai-apps/gemini/classification', { status: 'unreviewed' }], ['retention', { ...retention, auditDays: 30 }], ['retention/cleanup'],
    ]) await admin(path, { token: reviewer.token, method: 'POST', body, expect: 403 });
    assert.deepEqual(await audit(), authorized);
    const credentials = await admin('access');
    assert.deepEqual(credentials.map(({ id }) => id).sort(), [operator.access.id, reviewer.access.id].sort());
    const serialized = JSON.stringify([credentials, authorized]);
    assert.ok(![first, operator.token, reviewer.token, enrolled.token, granted.grant].some((secret) => serialized.includes(secret)));
    assert.ok(!serialized.includes('tokenHash'));

    const replacement = await issue(operator.access.name, 'administrator', 24);
    assert.notEqual(replacement.access.id, operator.access.id);
    assert.notEqual(replacement.token, operator.token);
    await Promise.all([revoke(operator.access.id), revoke(operator.access.id)]);
    await session(operator.token, 401);
    await fromOperator('policies', { method: 'POST', body: { mode: 'warn' }, expect: 401 });
    const revocations = await admin('audit?action=access_revoked');
    assert.equal(revocations.entries.length, 1);
    assert.deepEqual(revocations.entries[0].subjectAccess, named(operator));
    if (postgres) {
      assert.equal(await retentionFixture(`SELECT token_hash IS NULL FROM control_access WHERE id = '${operator.access.id}'`), 't');
      await retentionFixture(`
        UPDATE control_access SET issued_at = now() - interval '2 hours', expires_at = now() - interval '1 hour'
        WHERE id = '${reviewer.access.id}'
      `);
      await session(reviewer.token, 401);
      await admin('audit', { token: reviewer.token, expect: 401 });
      const updated = await admin('access');
      assert.equal(updated.find(({ id }) => id === reviewer.access.id).status, 'expired');
      await stop();
      await start();
      await session(operator.token, 401);
      await session(reviewer.token, 401);
    }
    assert.equal((await session(first)).role, 'owner');
    assert.deepEqual((await session(replacement.token)).access, named(replacement));
    assert.ok((await audit()).entries.some(({ actorAccess }) => actorAccess?.id === operator.access.id));
  });

  await t.test('requires an independent decision for exact policy changes and serializes review with publication', async () => {
    const admin = (path, options) => call(`/v1/admin/${path}`, { token: first, ...options });
    const post = (path, token, body, expect = 200, expectReview = false) => admin(path, { method: 'POST', token, body, expect,
      expectReview });
    const issue = (name, role = 'administrator', token = first) => post('access', token, { name, role, hours: 24 });
    const requirement = (token, required, expect = 204) => post('policy-reviews/setting', token, { required }, expect);
    const decide = (id, token, approve, expect = 200) => post(`policy-reviews/${id}/decision`, token, { approve }, expect);
    const baseline = async () => (await admin('policies'))[0];
    const queue = (token = first) => admin('policy-reviews', { token });
    const status = async (id) => (await queue()).entries.find((entry) => entry.id === id);
    const settings = await baseline();
    const priorAudit = await admin('audit');
    assert.deepEqual(await queue(), { required: false, entries: [] });
    if (postgres) {
      await stop();
      await retentionFixture(`
        ${undoSsoSchema}
        DELETE FROM schema_migrations WHERE version = 15;
        DROP TABLE policy_reviews;
        ALTER TABLE organizations DROP COLUMN require_policy_review;
        ALTER TABLE control_audit DROP COLUMN review_change;
      `);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 15'), '1');
      assert.deepEqual(await baseline(), settings);
      assert.deepEqual(await admin('audit'), priorAudit);
      assert.deepEqual(await queue(), { required: false, entries: [] });
    }
    const proposer = await issue('Policy Author');
    const reviewer = await issue('Independent Reviewer');
    const sameName = await issue('policy author');
    const auditor = await issue('Policy Auditor', 'auditor');
    const other = await issue('Other Tenant', 'administrator', second);
    await requirement(proposer.token, true, 403);
    await requirement(auditor.token, true, 403);
    await requirement(first, true);
    await requirement(first, true);
    assert.equal((await admin('session')).reviewRequired, true);
    assert.deepEqual(await queue(second), { required: false, entries: [] });
    await requirement(second, true);

    const group = await post('policy-groups', proposer.token, { name: 'Review-controlled group' });
    const groupPolicies = `policy-groups/${group.id}/policies`;
    const promote = `policy-groups/${group.id}/promote`;
    const restoreBaseline = `policies/${settings.version}/restore`;
    await post('policies', first, { mode: 'warn' }, 403);
    await post(restoreBaseline, first, undefined, 403);
    await post(groupPolicies, first, { mode: 'warn' }, 403);
    await post(promote, first, { expectedVersion: settings.version }, 403);
    const candidate = { mode: 'block', githubPatMode: 'warn', extensionInventoryEnabled: true,
      pathRules: { allow: [], block: ['private-fixture.test/review'] },
      uploadModes: { chatgpt: 'block' }, uploadTypes: { chatgpt: ['.archive'] },
      expectedVersion: settings.version };
    const initial = await post('policies', proposer.token, candidate, 202, true);
    const pending = await status(initial.reviewId);
    assert.equal(pending.status, 'pending');
    assert.deepEqual(pending.snapshots.before, settings);
    assert.deepEqual(pending.snapshots.candidate.pathRules, candidate.pathRules);
    assert.deepEqual(pending.snapshots.candidate.uploadTypes, { ...settings.uploadTypes, ...candidate.uploadTypes });
    assert.equal(pending.snapshots.candidate.extensionInventoryEnabled, true);
    assert.equal(Date.parse(pending.expiresAt) - Date.parse(pending.requestedAt), 86_400_000);
    assert.equal(pending.requester.id, proposer.access.id);
    assert.deepEqual(await baseline(), settings);
    assert.deepEqual((await queue(auditor.token)).entries, (await queue()).entries);
    assert.deepEqual((await queue(second)).entries, []);
    await decide(initial.reviewId, other.token, true, 404);
    await decide(initial.reviewId, auditor.token, true, 403);
    await decide(initial.reviewId, first, true, 403);
    assert.equal((await decide(initial.reviewId, proposer.token, true, 403)).code, 'self_approval');
    assert.equal((await decide(initial.reviewId, sameName.token, true, 403)).code, 'self_approval');
    const competing = await post('policies', proposer.token, { mode: 'monitor', expectedVersion: settings.version }, 202);

    const race = () => fetch(`${baseUrl}/v1/admin/policy-reviews/${initial.reviewId}/decision`, {
      method: 'POST', headers: { Authorization: `Bearer ${reviewer.token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ approve: true }), signal: AbortSignal.timeout(5000),
    });
    const responses = await Promise.all([race(), race()]);
    assert.deepEqual(responses.map(({ status }) => status).sort(), [200, 409]);
    const firstVersion = await baseline();
    assert.equal(firstVersion.version, settings.version + 1);
    assert.deepEqual(firstVersion.pathRules, candidate.pathRules);
    assert.deepEqual(firstVersion.uploadTypes, pending.snapshots.candidate.uploadTypes);
    assert.equal(firstVersion.githubPatMode, 'warn');
    assert.equal(firstVersion.extensionInventoryEnabled, true);
    assert.equal((await status(initial.reviewId)).publishedVersion, firstVersion.version);
    assert.equal((await status(initial.reviewId)).reviewer.id, reviewer.access.id);
    assert.equal((await decide(competing.reviewId, reviewer.token, true, 409)).code, 'review_stale');
    assert.equal((await status(competing.reviewId)).status, 'stale');
    await post('policies', proposer.token, { mode: 'monitor', expectedVersion: settings.version }, 409);

    const scoped = await post(groupPolicies, proposer.token, { mode: 'warn', expectedVersion: firstVersion.version }, 202);
    const scopedFirst = await decide(scoped.reviewId, reviewer.token, true);
    const olderPromotion = await post(promote, proposer.token, { expectedVersion: scopedFirst.version }, 202);
    const groupEdit = await post(groupPolicies, proposer.token, {
      mode: 'monitor', uploadTypes: { chatgpt: ['.group'] }, expectedVersion: scopedFirst.version,
    }, 202);
    const scopedSecond = await decide(groupEdit.reviewId, reviewer.token, true);
    assert.deepEqual((await baseline()).uploadTypes.chatgpt, ['.archive']);
    assert.equal((await decide(olderPromotion.reviewId, reviewer.token, true, 409)).code, 'review_stale');
    const promotion = await post(promote, proposer.token, { expectedVersion: scopedSecond.version }, 202);
    assert.equal((await status(promotion.reviewId)).sourceVersion, scopedSecond.version);
    const promoted = await decide(promotion.reviewId, reviewer.token, true);
    assert.equal(promoted.mode, scopedSecond.mode);
    assert.deepEqual(promoted.uploadTypes.chatgpt, ['.group']);
    assert.deepEqual(await baseline(), promoted);
    const scopedRestore = await post(`${groupPolicies}/${scopedFirst.version}/restore`, proposer.token, undefined, 202);
    assert.equal((await decide(scopedRestore.reviewId, reviewer.token, true)).restoredFrom, scopedFirst.version);
    const restoration = await post(restoreBaseline, proposer.token, undefined, 202);
    const restored = await decide(restoration.reviewId, reviewer.token, true);
    assert.equal(restored.restoredFrom, settings.version);
    assert.deepEqual(restored.pathRules, settings.pathRules);
    assert.deepEqual(restored.uploadTypes, settings.uploadTypes);

    const rejected = await post('policies', proposer.token, { mode: 'warn' }, 202);
    await decide(rejected.reviewId, reviewer.token, false, 204);
    assert.equal((await status(rejected.reviewId)).status, 'rejected');
    const withdrawn = await post('policies', proposer.token, { mode: 'warn' }, 202);
    await decide(withdrawn.reviewId, proposer.token, false, 204);
    assert.equal((await status(withdrawn.reviewId)).status, 'withdrawn');
    if (postgres) {
      const expiring = await post('policies', proposer.token, { mode: 'warn' }, 202);
      await retentionFixture(`UPDATE policy_reviews SET expires_at = now() - interval '1 second' WHERE id = '${expiring.reviewId}'`);
      assert.equal((await status(expiring.reviewId)).status, 'expired');
      assert.equal((await decide(expiring.reviewId, reviewer.token, true, 409)).code, 'review_closed');
    }
    const cancelled = await post('policies', proposer.token, { mode: 'warn' }, 202);
    const revokedAuthor = await post('policies', sameName.token, { mode: 'block' }, 202);
    await post(`access/${sameName.access.id}/revoke`, first, undefined, 204);
    assert.equal((await decide(revokedAuthor.reviewId, reviewer.token, true, 409)).code, 'review_stale');
    await requirement(first, false);
    assert.equal((await status(cancelled.reviewId)).status, 'cancelled');
    assert.equal((await post('policies', proposer.token, { mode: 'warn' }, 409, true)).code, 'review_mode_changed');
    assert.deepEqual(await baseline(), restored);
    if (postgres) {
      await stop();
      await start();
      assert.equal((await status(initial.reviewId)).status, 'approved');
      assert.equal((await queue()).required, false);
    }
    const audit = await admin('audit?limit=1000');
    const requested = audit.entries.find(({ action, reviewChange }) => action === 'policy_review_requested' && reviewChange.reviewId === initial.reviewId);
    const decided = audit.entries.filter(({ action, reviewChange }) => action === 'policy_review_decided' && reviewChange.reviewId === initial.reviewId);
    assert.equal(requested.actorAccess.id, proposer.access.id);
    assert.equal(decided.length, 1);
    assert.equal(decided[0].actorAccess.id, reviewer.access.id);
    assert.equal(decided[0].reviewChange.publishedVersion, firstVersion.version);
    assert.equal(audit.entries.filter(({ action }) => action === 'policy_review_setting_changed').length, 2);
    assert.ok(!JSON.stringify(audit).includes('private-fixture.test/review'));
    assert.ok(!JSON.stringify(await queue()).includes(proposer.token));
  });

  await t.test('accepts private, bounded extension inventory only for the current enabled scope', async () => {
    const admin = (path, options) => call(`/v1/admin/${path}`, { token: first, ...options });
    const current = async () => (await admin('policies'))[0];
    const empty = await current();
    assert.equal(empty.extensionInventoryEnabled, false);
    if (postgres) {
      await stop();
      await retentionFixture(`
        DELETE FROM schema_migrations WHERE version = 16;
        DROP TABLE extension_inventory_snapshots;
        ALTER TABLE policy_versions DROP COLUMN extension_inventory_enabled;
      `);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 16'), '1');
      assert.deepEqual(await current(), empty);
    }
    const change = (path, body) => admin(path, { method: 'POST', body });
    const { grant } = await change('enrollment-grants');
    const browser = await call('/v1/enroll', { method: 'POST', body: { grant } });
    const path = `extension-inventory/${browser.installationId}`;
    const read = () => admin(path);
    const publish = (enabled) => change('policies', { extensionInventoryEnabled: enabled });
    const report = (body, expect = 204, token = browser.token) =>
      call('/v1/browser/extension-inventory', { method: 'POST', token, body, expect });
    const sample = { id: 'a'.repeat(32), name: 'Inventory fixture', version: '1.1', enabled: true,
      installType: 'development', siteAccess: 'all', permissions: ['cookies', 'tabs'] };
    const timestamp = Date.now();
    const base = { policyVersion: empty.version, assignmentVersion: 0, capturedAt: new Date(timestamp).toISOString(),
      status: 'reported', entries: [sample], omitted: 0 };
    await report(base, 409);
    assert.equal((await read()).status, 'off');
    const enabled = await publish(true);
    assert.equal(enabled.extensionInventoryEnabled, true);
    const effective = await call('/v1/browser/policy', { token: browser.token, assignmentAware: true });
    assert.equal(effective.extensionInventoryEnabled, true);
    assert.equal((await read()).status, 'awaiting');
    assert.equal((await admin('extension-inventory')).find(({ installationId }) => installationId === browser.installationId).entries, null);

    const body = { ...base, policyVersion: enabled.version };
    for (const invalid of [
      { ...body, status: 'permission_required' }, { ...body, entries: [sample, sample] },
      { ...body, capturedAt: new Date(timestamp + 180_000).toISOString() },
      { ...body, capturedAt: new Date(timestamp - 1_000_000).toISOString() },
      { ...body, entries: [{ ...sample, id: 'q'.repeat(32) }] }, { ...body, entries: [{ ...sample, name: '\n' }] },
      { ...body, entries: [{ ...sample, version: '1.99999' }] },
      { ...body, entries: [{ ...sample, hostPermissions: ['https://private-fixture.example.test/*'] }] },
      { ...body, entries: [{ ...sample, permissions: ['https://private-fixture.example.test/*'] }] },
      { ...body, entries: [{ ...sample, permissions: ['tabs', 'tabs'] }] },
      { ...body, entries: [{ ...sample, enabled: undefined }] },
      { ...body, entries: Array.from({ length: 101 }, () => sample) },
    ]) await report(invalid, 400);
    await report({ ...body, entries: [{ ...sample, name: 'x'.repeat(132_000) }] }, 413);
    await report({ ...body, assignmentVersion: 1 }, 409);
    await report(body, 401, first);
    await admin(path, { token: browser.token, expect: 401 });
    await admin(path, { token: second, expect: 404 });
    assert.equal((await admin('extension-inventory', { token: second })).some(({ installationId }) => installationId === browser.installationId), false);

    await report({ ...body, status: 'permission_required', entries: [] });
    assert.equal((await read()).status, 'permission_required');
    const withEntries = { ...body, capturedAt: new Date(timestamp + 100).toISOString() };
    await report(withEntries);
    const accepted = await read();
    assert.deepEqual(accepted.entries, [sample]);
    await Promise.all([report(withEntries), report({ ...body, status: 'unavailable', entries: [] })]);
    assert.deepEqual(await read(), accepted);
    const large = Array.from({ length: 100 }, (_, i) => ({
      ...sample,
      id: 'a'.repeat(30) + String.fromCharCode(97 + Math.floor(i / 16), 97 + i % 16),
      name: 'Fixture ' + 'x'.repeat(90),
    }));
    assert.ok(JSON.stringify(large).length > 16_384);
    await report({ ...body, capturedAt: new Date(timestamp + 200).toISOString(), entries: large, omitted: 3 });
    assert.equal((await read()).extensionCount, 100);
    assert.equal((await read()).omitted, 3);
    const noPermission = { ...body, capturedAt: new Date(timestamp + 300).toISOString(), status: 'permission_required', entries: [] };
    await report(noPermission);
    assert.deepEqual((await read()).entries, []);
    const restored = await change(`policies/${empty.version}/restore`);
    assert.equal(restored.extensionInventoryEnabled, false);
    assert.equal((await read()).status, 'off');
    await report({ ...body, capturedAt: new Date(timestamp + 400).toISOString() }, 409);

    const group = await change('policy-groups', { name: 'Extension inventory scope' });
    const scoped = await change(`policy-groups/${group.id}/policies`, { extensionInventoryEnabled: true });
    await admin(`installations/${browser.installationId}/policy-group`, { method: 'POST', body: { groupId: group.id }, expect: 204 });
    const moved = await call('/v1/browser/policy', { token: browser.token, assignmentAware: true });
    assert.equal(moved.version, scoped.version);
    assert.equal(moved.assignmentVersion, 1);
    await report({ ...body, policyVersion: scoped.version }, 409);
    const currentScope = { ...body, policyVersion: scoped.version, assignmentVersion: 1, capturedAt: new Date(timestamp + 500).toISOString() };
    await report(currentScope);
    assert.equal((await read()).groupName, group.name);
    assert.deepEqual((await read()).entries, [sample]);
    const promoted = await change(`policy-groups/${group.id}/promote`, { expectedVersion: scoped.version });
    assert.equal(promoted.extensionInventoryEnabled, true);
    assert.deepEqual((await read()).entries, [sample]);
    if (postgres) {
      const count = () => retentionFixture(`SELECT count(*) FROM extension_inventory_snapshots WHERE installation_id = '${browser.installationId}'`);
      await retentionFixture(`
        UPDATE extension_inventory_snapshots SET received_at = now() - interval '31 days' WHERE installation_id = '${browser.installationId}'
      `);
      assert.equal((await read()).status, 'awaiting');
      assert.equal(await count(), '1');
      await stop();
      await start();
      for (let retry = 0; await count() !== '0' && retry < 20; retry++) await delay(50);
      assert.equal(await count(), '0');
      await report({ ...currentScope, capturedAt: new Date(timestamp + 600).toISOString() });
      assert.equal(await count(), '1');
    }
    await admin(`installations/${browser.installationId}/revoke`, { method: 'POST', expect: 204 });
    await admin(path, { expect: 404 });
    await report(currentScope, 401);
    if (postgres) {
      assert.equal(await retentionFixture(`SELECT count(*) FROM extension_inventory_snapshots WHERE installation_id = '${browser.installationId}'`), '0');
    }
  });

  await t.test('versions a scoped app catalog and rejects uncataloged or withdrawn observations', async () => {
    const admin = (path, options) => call(`/v1/admin/${path}`, { token: first, ...options });
    const post = (path, body, expect = 200, token = first) => admin(path, { token, method: 'POST', body, expect });
    const inventory = (token) => admin('ai-apps', token ? { token } : undefined);
    const [before] = await admin('policies');
    const previousInventory = await inventory();
    assert.deepEqual(before.customApps, []);
    if (postgres) {
      await stop();
      const constraints = ['ai_app_observations', 'ai_app_classifications', 'control_audit'].map((table) => `
        ALTER TABLE ${table} DROP CONSTRAINT ${table}_app_id_check,
          ADD CONSTRAINT ${table}_app_id_check CHECK (app_id IN ('chatgpt', 'claude', 'gemini'));
      `).join('\n');
      await retentionFixture(`
        ${undoPresetSchema}
        DELETE FROM schema_migrations WHERE version = 18;
        ALTER TABLE policy_versions DROP COLUMN custom_apps;
        ${constraints}
      `);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 18'), '1');
      assert.deepEqual((await admin('policies'))[0], before);
      assert.deepEqual(await inventory(), previousInventory);
    }
    for (const customApps of [
      [{ host: 'https://workspace.example.test', name: 'Workspace' }],
      [{ host: 'workspace.example.test/private', name: 'Workspace' }],
      [{ host: '*.example.test', name: 'Wildcard' }],
      [{ host: 'project.example.test:443', name: 'Port' }],
      [{ host: 'chatgpt.com', name: 'Built in' }],
      [{ host: 'localhost', name: 'Localhost' }],
      [{ host: 'project.example.test', name: 'A\u202eB' }],
      [null],
      [{ host: 'workspace.example.test', name: 'First' }, { host: 'WORKSPACE.EXAMPLE.TEST.', name: 'Duplicate' }],
      Array.from({ length: 26 }, (_, index) => ({ host: `site-${index}.example.test`, name: 'Site' })),
    ]) await post('policies', { customApps }, 400);

    const baseline = await post('policies', { mode: before.mode, discoveryEnabled: true,
      customApps: [{ host: ' WorkSpace.Example.Test. ', name: ' Project Workspace ' }] });
    const [app] = baseline.customApps;
    assert.equal(app.name, 'Project Workspace');
    assert.equal(app.host, 'workspace.example.test');
    assert.match(app.id, /^saas:[a-f0-9]{64}$/);
    await post('policies', { customApps: [], expectedVersion: before.version }, 409);
    assert.deepEqual((await inventory()).find((entry) => entry.appId === app.id),
      { appId: app.id, name: app.name, host: app.host, status: 'unreviewed', browsersSeen: 0, lastObservedAt: null });
    assert.equal((await inventory(second)).some((entry) => entry.appId === app.id), false);
    const classify = (status, expect = 204, token = first) => post(`ai-apps/${app.id}/classification`, { status }, expect, token);
    await classify('unapproved', 404, second);
    const { grant } = await post('enrollment-grants');
    const client = await call('/v1/enroll', { method: 'POST', body: { grant } });
    const getPolicy = () => call('/v1/browser/policy', { token: client.token, assignmentAware: true });
    const observe = (body, expect = 204) => call('/v1/browser/ai-app-observations', { token: client.token, body, method: 'POST', expect });
    const ack = (policyVersion, customDiscoveryApplied) => call('/v1/browser/heartbeat', {
      token: client.token, method: 'POST', expect: 204,
      body: { policyVersion, domainRulesApplied: true, pathRulesApplied: true, paymentCardModeApplied: true, uploadControlsApplied: true,
        uploadTypesApplied: true, customDiscoveryApplied },
    });
    const applied = async () => (await admin('installations')).find((row) => row.installationId === client.installationId).appliedPolicyVersion;
    assert.deepEqual((await getPolicy()).customApps, baseline.customApps);
    await ack(baseline.version);
    assert.equal(await applied(), null);
    await ack(baseline.version, true);
    assert.equal(await applied(), baseline.version);
    const sample = { appId: app.id, observedAt: new Date().toISOString(), policyVersion: baseline.version };
    await observe({ ...sample, policyVersion: before.version }, 400);
    await observe({ ...sample, appId: 'saas:' + '0'.repeat(64) }, 400);
    await observe({ ...sample, host: app.host }, 400);
    await observe({ ...sample, url: 'https://workspace.example.test/account' }, 400);
    await Promise.all([observe(sample), observe(sample)]);
    await classify('approved');
    await classify('approved');
    const [seen] = (await inventory()).filter((entry) => entry.appId === app.id);
    assert.equal(seen.browsersSeen, 1);
    assert.equal(seen.status, 'approved');
    const matches = (await admin('audit')).entries.filter((entry) => entry.appId === app.id);
    assert.equal(matches.length, 1);
    assert.equal(matches[0].classification, 'approved');

    const removed = await post('policies', { customApps: [] });
    assert.equal((await inventory()).some((entry) => entry.appId === app.id), false);
    await classify('unreviewed', 404);
    await observe(sample, 400);
    const renamed = await post('policies', { customApps: [{ host: app.host, name: 'Renamed Workspace' }], expectedVersion: removed.version });
    assert.equal(renamed.customApps[0].id, app.id);
    assert.equal((await inventory()).find((entry) => entry.appId === app.id).status, 'approved');
    await observe(sample, 400);
    await observe({ ...sample, policyVersion: renamed.version });

    const group = await post('policy-groups', { name: 'Catalog canary' });
    const scoped = await post(`policy-groups/${group.id}/policies`, {
      customApps: [{ host: 'canary.workspace.example.test', name: 'Canary Workspace' }],
    });
    const [canary] = scoped.customApps;
    await post(`installations/${client.installationId}/policy-group`, { groupId: group.id }, 204);
    const assignment = await getPolicy();
    assert.equal(assignment.version, scoped.version);
    const groupSample = { ...sample, policyVersion: scoped.version, assignmentVersion: assignment.assignmentVersion };
    await observe(groupSample, 400);
    await observe({ ...groupSample, appId: canary.id, assignmentVersion: 0 }, 400);
    await observe({ ...groupSample, appId: canary.id });
    const scopedInventory = await inventory();
    assert.ok(scopedInventory.some((entry) => entry.appId === canary.id && entry.browsersSeen === 1));
    assert.ok(scopedInventory.some((entry) => entry.appId === app.id && entry.browsersSeen === 1));
    const promoted = await post(`policy-groups/${group.id}/promote`, { expectedVersion: scoped.version });
    assert.deepEqual(promoted.customApps, scoped.customApps);
    const restored = await post(`policies/${baseline.version}/restore`);
    assert.deepEqual(restored.customApps, baseline.customApps);
    await post(`installations/${client.installationId}/revoke`, undefined, 204);
    await observe({ ...groupSample, appId: canary.id }, 401);
  });

  await t.test('versions prompt exceptions without importing them between scopes or restoring removed exceptions', async () => {
    const admin = (path, options) => call(`/v1/admin/${path}`, { token: first, ...options });
    const post = (path, body, expect = 200, token = first, expectReview = false) =>
      admin(path, { token, method: 'POST', body, expect, expectReview });
    const [before] = await admin('policies');
    assert.deepEqual(before.promptExceptions, []);
    if (postgres) {
      const history = await admin('events');
      await stop();
      await retentionFixture(`
        ${undoIdentifierSchema}
        DELETE FROM schema_migrations WHERE version = 19;
        ALTER TABLE policy_versions DROP COLUMN prompt_exceptions;
        DELETE FROM policy_deliveries WHERE assignment_version = 0;
        ALTER TABLE policy_deliveries DROP COLUMN exception_scope, DROP CONSTRAINT policy_deliveries_assignment_version_check,
            ADD CONSTRAINT policy_deliveries_assignment_version_check CHECK (assignment_version > 0);
        ALTER TABLE security_events DROP CONSTRAINT security_events_decision_check,
            ADD CONSTRAINT security_events_decision_check CHECK (decision IN ('monitor','warn','block','warn_override'));
      `);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 19'), '1');
      assert.deepEqual((await admin('policies'))[0], before);
      assert.deepEqual(await admin('events'), history);
    }
    const sample = { appId: 'chatgpt', ruleId: 'fixture-secret', expiresAt: new Date(Date.now() + 60_000).toISOString(),
      reason: '  Synthetic exception ticket  ' };
    for (const exceptions of [
      [null], [{ ...sample, reason: ' ' }], [{ ...sample, appId: 'local-prompt-fixture' }],
      [{ ...sample, ruleId: 'ai-file-upload' }], [sample, sample],
      [{ ...sample, expiresAt: new Date(Date.now() - 60_000).toISOString() }],
      [{ ...sample, expiresAt: new Date(Date.now() + 2 * 86_400_000).toISOString() }],
    ]) await post('policies', { promptExceptions: exceptions }, 400);
    const latest = await post('policies', { mode: 'block', promptExceptions: [sample] });
    assert.deepEqual(latest.promptExceptions, [{ ...sample, expiresAt: latest.promptExceptions[0].expiresAt, reason: sample.reason.trim() }]);
    assert.equal(Date.parse(latest.promptExceptions[0].expiresAt), Date.parse(sample.expiresAt));
    await post('policies', { promptExceptions: [], expectedVersion: before.version }, 409);

    const { grant } = await post('enrollment-grants');
    const client = await call('/v1/enroll', { method: 'POST', body: { grant } });
    const browser = (path, options) => call(`/v1/browser/${path}`, { token: client.token, assignmentAware: true, ...options });
    const delivered = await browser('policy');
    assert.equal(delivered.promptExceptions, undefined);
    assert.deepEqual(delivered.promptExceptionLease.grants, [{
      appId: 'chatgpt', ruleId: 'fixture-secret', expiresAtMs: Date.parse(sample.expiresAt),
    }]);
    const status = async () => (await admin('installations')).find((row) => row.installationId === client.installationId);
    const acknowledge = (version, assignmentVersion = 0, promptExceptionsApplied = false) => browser('heartbeat', {
      method: 'POST', expect: 204, body: { policyVersion: version, assignmentVersion, promptExceptionsApplied,
        domainRulesApplied: true, pathRulesApplied: true, paymentCardModeApplied: true, uploadControlsApplied: true,
        uploadTypesApplied: true, customDiscoveryApplied: true },
    });
    await acknowledge(latest.version);
    assert.equal((await status()).appliedPolicyVersion, null);
    await acknowledge(latest.version, 0, true);
    assert.equal((await status()).appliedPolicyVersion, latest.version);
    const exceptionEvent = (policyVersion, assignmentVersion = 0) => ({
      ...event, eventId: randomUUID(), timestamp: new Date().toISOString(), appId: 'chatgpt', decision: 'exception_applied',
      policyVersion, assignmentVersion,
    });
    const send = (body, expect = 204) => browser('events', { method: 'POST', body, expect });
    const submitted = exceptionEvent(latest.version);
    for (const invalid of [
      { ...submitted, appId: 'gemini' }, { ...submitted, appId: 'local-prompt-fixture' },
      { ...submitted, timestamp: sample.expiresAt }, { ...submitted, timestamp: before.publishedAt },
      { ...submitted, reason: sample.reason }, { ...submitted, ruleId: 'ai-file-upload', detectorCategory: 'file-upload', uploadMethod: 'picker' },
    ]) await send(invalid, 400);
    await send(submitted);
    await send(submitted);
    const query = `events/export?installationId=${client.installationId}&decision=exception_applied`;
    assert.deepEqual((await admin(query)).entries.map((entry) => entry.eventId), [submitted.eventId]);
    assert.deepEqual((await admin(query, { token: second })).entries, []);
    const report = await admin('reports/ai-enforcement?appId=chatgpt');
    assert.equal(report.counts.exception_applied, 1);
    assert.equal(report.byRule.find(({ id }) => id === 'fixture-secret').counts.exception_applied, 1);
    assert.ok(!JSON.stringify(report).includes(sample.reason.trim()));

    const group = await post('policy-groups', { name: 'Exception scope' });
    await post(`installations/${client.installationId}/policy-group`, { groupId: group.id }, 204);
    const inherited = await browser('policy');
    assert.equal(inherited.version, latest.version);
    assert.equal(inherited.promptExceptionLease, undefined);
    await acknowledge(latest.version, inherited.assignmentVersion);
    assert.equal((await status()).appliedPolicyVersion, latest.version);
    await send(exceptionEvent(latest.version, inherited.assignmentVersion), 400);
    const groupPath = `policy-groups/${group.id}`;
    const firstGroup = await post(`${groupPath}/policies`, { mode: 'warn' });
    assert.deepEqual(firstGroup.promptExceptions, []);
    const scoped = await post(`${groupPath}/policies`, { promptExceptions: [sample] });
    const scopedDelivery = await browser('policy');
    assert.equal(scopedDelivery.version, scoped.version);
    assert.equal(scopedDelivery.promptExceptionLease.grants[0].appId, 'chatgpt');
    await send(exceptionEvent(scoped.version, scopedDelivery.assignmentVersion));

    const removed = await post('policies', { promptExceptions: [] });
    const newGrant = (await post('enrollment-grants')).grant;
    const lateInstall = await call('/v1/enroll', { method: 'POST', body: { grant: newGrant } });
    assert.equal((await call('/v1/browser/policy', { token: lateInstall.token })).version, removed.version);
    await call('/v1/browser/events', { token: lateInstall.token, method: 'POST', body: exceptionEvent(latest.version), expect: 400 });
    const restored = await post(`policies/${latest.version}/restore`);
    assert.ok(restored.version > removed.version);
    assert.deepEqual(restored.promptExceptions, []);
    const promoted = await post(`${groupPath}/promote`, { expectedVersion: scoped.version });
    assert.deepEqual(promoted.promptExceptions, []);
    assert.deepEqual((await admin(`${groupPath}/policies`))[0].promptExceptions, scoped.promptExceptions);

    const author = await post('access', { name: 'Exception Author', role: 'administrator', hours: 1 });
    const approver = await post('access', { name: 'Exception Reviewer', role: 'administrator', hours: 1 });
    await post('policy-reviews/setting', { required: true }, 204);
    const expiry = new Date(Date.now() + 1800).toISOString();
    const pending = await post('policies', { promptExceptions: [{ ...sample, expiresAt: expiry }] }, 202, author.token, true);
    const decide = (token, expect) => post(`policy-reviews/${pending.reviewId}/decision`, { approve: true }, expect, token);
    await decide(author.token, 403);
    await delay(Math.max(0, Date.parse(expiry) - Date.now() + 100));
    assert.equal((await decide(approver.token, 409)).code, 'review_stale');
    assert.deepEqual((await admin('policies'))[0].promptExceptions, []);
    await post('policy-reviews/setting', { required: false }, 204);
  });

  await t.test('isolates Claude policy deliveries and coverage across upgrades, versions and tenants', async () => {
    const admin = (path, options = {}) => call(`/v1/admin/${path}`, { token: first, ...options });
    const post = (path, body, expect = 200, token = first) => admin(path, { method: 'POST', body, expect, token });
    const previous = await admin('policies');
    const history = await admin('events');
    if (postgres) {
      await stop();
      await retentionFixture(`
        DELETE FROM schema_migrations WHERE version = 20;
        ALTER TABLE policy_versions DROP COLUMN claude_prompt_enabled;
        ALTER TABLE policy_deliveries DROP COLUMN claude_prompt;
        ALTER TABLE installations DROP COLUMN claude_coverage, DROP COLUMN claude_checked_at, DROP COLUMN claude_coverage_version;
        ALTER TABLE security_events DROP CONSTRAINT security_events_app_id_check,
            ADD CONSTRAINT security_events_app_id_check CHECK (app_id IN ('local-prompt-fixture', 'chatgpt', 'gemini'));
      `);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 20'), '1');
      assert.deepEqual(await admin('policies'), previous);
      assert.deepEqual(await admin('events'), history);
    }

    const active = await post('policies', { mode: 'block', claudePromptEnabled: true });
    const { grant } = await post('enrollment-grants');
    const client = await call('/v1/enroll', { method: 'POST', body: { grant } });
    const browser = (path, options = {}) => call(`/v1/browser/${path}`, { token: client.token, assignmentAware: true, ...options });
    const installed = async () => (await admin('installations')).find((row) => row.installationId === client.installationId);
    const heartbeat = (policyVersion, body = {}, expect = 204) => browser('heartbeat', { method: 'POST', expect, body: {
      policyVersion, domainRulesApplied: true, pathRulesApplied: true, paymentCardModeApplied: true,
      uploadControlsApplied: true, uploadTypesApplied: true, customDiscoveryApplied: true, ...body,
    } });
    const decision = { eventId: randomUUID(), timestamp: new Date().toISOString(), policyVersion: active.version, appId: 'claude',
      ruleId: 'fixture-secret', detectorCategory: 'synthetic-secret', decision: 'block' };
    const send = (body, expect = 204) => browser('events', { method: 'POST', body, expect });
    assert.equal((await browser('policy')).claudePromptEnabled, false);
    await heartbeat(active.version);
    assert.equal((await installed()).appliedPolicyVersion, null);
    await send(decision, 400);
    await heartbeat(active.version, { claudeCoverage: 'ready', claudePromptApplied: true }, 400);
    assert.equal((await browser('policy', { claudeAware: true })).claudePromptEnabled, true);
    await heartbeat(active.version, { claudeCoverage: 'ready' }, 400);
    await heartbeat(active.version, { claudeCoverage: 'ready', claudePromptApplied: true });
    assert.equal((await installed()).claudeCoverage, 'ready');
    assert.equal((await installed()).appliedPolicyVersion, active.version);
    await send({ ...decision, prompt: 'synthetic input' }, 400);
    await send({ ...decision, ruleId: 'ai-file-upload', detectorCategory: 'file-upload', uploadMethod: 'picker' }, 400);
    await send(decision);
    await send(decision);
    const query = 'events/export?appId=claude';
    assert.deepEqual((await admin(query)).entries.map(({ eventId }) => eventId), [decision.eventId]);
    assert.deepEqual((await admin(query, { token: second })).entries, []);

    const author = await post('access', { name: 'Claude Policy Author', role: 'administrator', hours: 1 });
    const approver = await post('access', { name: 'Claude Policy Reviewer', role: 'administrator', hours: 1 });
    await post('policy-reviews/setting', { required: true }, 204);
    const draft = await post('policies', { claudePromptEnabled: false }, 202, author.token);
    assert.equal((await admin('policies'))[0].claudePromptEnabled, true);
    const updated = await post(`policy-reviews/${draft.reviewId}/decision`, { approve: true }, 200, approver.token);
    assert.equal(updated.claudePromptEnabled, false);
    assert.equal((await installed()).claudeCoverage, null);
    await heartbeat(updated.version, { claudeCoverage: 'ready', claudePromptApplied: true }, 400);
    await heartbeat(active.version, { claudeCoverage: 'unsupported', claudePromptApplied: true });
    assert.equal((await installed()).claudeCoverage, null);
    await post('policy-reviews/setting', { required: false }, 204);
  });

  await t.test('migrates existing Control tokens and leaves optional single sign-on disabled', async () => {
    const access = () => call('/v1/admin/access', { token: first });
    const { token, access: named } = await call('/v1/admin/access', { token: first, method: 'POST',
      body: { name: 'Migration Auditor', role: 'auditor', hours: 1 } });
    const previous = await access();
    if (postgres) {
      await stop();
      await retentionFixture(undoSsoSchema);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 21'), '1');
      assert.deepEqual(await access(), previous);
    }
    const session = await call('/v1/admin/session', { token });
    assert.equal(session.role, 'auditor');
    assert.equal(session.access.id, named.id);
    await call('/v1/admin/access/sso', { token: first, expect: 204 });
    await call('/v1/internal/sso/session', { token: first, method: 'POST', body: {}, expect: 404 });
  });

  await t.test('tracks reported extension releases independently of policy acknowledgment and isolates the full fleet summary', async () => {
    const admin = (path, options = {}) => call(`/v1/admin/${path}`, { token: releaseAdmin, ...options });
    const coverage = (options) => admin('browser-releases', options);
    const issue = async () => {
      const { grant } = await admin('enrollment-grants', { method: 'POST' });
      return call('/v1/enroll', { method: 'POST', body: { grant } });
    };
    assert.deepEqual(await coverage(), []);
    const browser = await issue();
    const legacy = await issue();
    const read = (extensionVersion, token = browser.token, expect = 200) => call('/v1/browser/policy', { token, extensionVersion, expect });
    const details = async () => (await admin('installations')).find((row) => row.installationId === browser.installationId);
    const initial = await read();
    await call('/v1/browser/heartbeat', { token: browser.token, method: 'POST', body: { policyVersion: initial.version }, expect: 204 });
    const beforeUpgrade = (await admin('installations')).map(({ extensionVersion, extensionVersionReportedAt, ...entry }) => entry);
    if (postgres) {
      await stop();
      await retentionFixture(`DELETE FROM schema_migrations WHERE version = 22;
        ALTER TABLE installations DROP COLUMN extension_version, DROP COLUMN extension_version_reported_at;`);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 22'), '1');
      assert.deepEqual((await admin('installations')).map(({ extensionVersion, extensionVersionReportedAt, ...entry }) => entry), beforeUpgrade);
    }

    const unreported = { kind: 'unreported', extensionVersion: null, installations: 1, recentReports: 0 };
    assert.deepEqual(await coverage(), [{ ...unreported, installations: 2 }]);
    await read('0.20.0');
    const original = await details();
    assert.equal(original.extensionVersion, '0.20.0');
    assert.equal(original.appliedPolicyVersion, initial.version);
    assert.ok(Number.isFinite(Date.parse(original.extensionVersionReportedAt)));
    for (const invalid of ['0.0', '0.020.0', '65536', '0.20.0, 0.21.0', '1.2.3.4.5', 'ZEKVAR_TEST_SECRET', '9'.repeat(30)]) {
      assert.deepEqual(await read(invalid), initial);
    }
    await read();
    assert.equal((await details()).extensionVersionReportedAt, original.extensionVersionReportedAt);
    await read(undefined, legacy.token);
    assert.deepEqual(await coverage(), [{ kind: 'release', extensionVersion: '0.20.0', installations: 1, recentReports: 1 }, unreported]);

    if (postgres) {
      await retentionFixture(`UPDATE installations SET extension_version_reported_at = now() - interval '91 seconds'
        WHERE id = '${browser.installationId}'`);
      await read();
      assert.equal((await coverage())[0].recentReports, 0);
    }
    await Promise.all([read('0.21.0'), read('0.21.0')]);
    assert.equal((await coverage())[0].installations, 1);
    assert.equal((await details()).extensionVersion, '0.21.0');
    await read('65535.0.1.0');
    assert.equal((await details()).extensionVersion, '65535.0.1.0');
    await read('0.20.0');
    assert.equal((await details()).extensionVersion, '0.20.0');

    const auditor = await admin('access', { method: 'POST', body: { name: 'Rollout Auditor', role: 'auditor', hours: 1 } });
    assert.deepEqual(await coverage({ token: auditor.token }), await coverage());
    const { grant: foreignGrant } = await admin('enrollment-grants', { token: second, method: 'POST' });
    const foreign = await call('/v1/enroll', { method: 'POST', body: { grant: foreignGrant } });
    await read('0.99.0', foreign.token);
    assert.deepEqual((await coverage({ token: second })).filter(({ kind }) => kind === 'release'), [
      { kind: 'release', extensionVersion: '0.99.0', installations: 1, recentReports: 1 },
    ]);
    assert.ok(!(await coverage()).some((row) => row.extensionVersion === '0.99.0'));
    await coverage({ token: browser.token, expect: 401 });
    await coverage({ token: undefined, expect: 401 });
    await admin(`installations/${browser.installationId}/revoke`, { method: 'POST', expect: 204 });
    await read('0.22.0', undefined, 401);
    assert.equal((await details()).extensionVersion, '0.20.0');
    assert.deepEqual(await coverage(), [unreported]);

    if (postgres) {
      await retentionFixture(`INSERT INTO installations (id, organization_id, token_hash, extension_version, extension_version_reported_at)
        SELECT gen_random_uuid(), o.id, encode(sha256(convert_to('release-fixture-${suffix}-' || n, 'UTF8')), 'hex'),
            ('1.0.' || (n % 10)), now() - interval '2 minutes'
        FROM organizations o CROSS JOIN generate_series(1, 105) AS fixture(n) WHERE o.slug = 'release-${suffix}'`);
      assert.equal((await admin('installations')).length, 100);
      const fleet = await coverage();
      assert.equal(fleet.filter((row) => row.kind === 'release').length, 8);
      assert.deepEqual(fleet.find((row) => row.kind === 'other'), { kind: 'other', extensionVersion: null, installations: 20, recentReports: 0 });
      assert.deepEqual(fleet.at(-1), unreported);
      assert.equal(fleet.reduce((total, row) => total + row.installations, 0), 106);
      assert.equal(fleet.reduce((total, row) => total + row.recentReports, 0), 0);
    }
  });

  await t.test('scopes browser health to one rollout group and reads counts and details from one snapshot', async () => {
    const admin = (path, options = {}) => call(`/v1/admin/${path}`, { token: groupViewAdmin, ...options });
    const post = (path, body, options) => admin(path, { method: 'POST', body, ...options });
    const health = (filters = '', options) => admin(`browser-health${filters ? `?${filters}` : ''}`, options);
    const canary = await post('policy-groups', { name: 'Canary rollout' });
    const broad = await post('policy-groups', { name: 'Broad rollout' });
    const foreign = await post('policy-groups', { name: 'Canary rollout' }, { token: second });
    const scope = `rolloutGroup=${canary.id}`;
    const empty = await health(scope);
    assert.equal(empty.composerReadiness.activeInstallations, 0);
    assert.equal(empty.activeInstallations, 0);
    assert.deepEqual(empty.releases, []);
    assert.deepEqual(empty.installations, []);
    async function enroll(extensionVersion) {
      const { grant } = await post('enrollment-grants');
      const browser = await call('/v1/enroll', { method: 'POST', body: { grant } });
      await call('/v1/browser/policy', { token: browser.token, assignmentAware: true, extensionVersion });
      return browser;
    }
    const [candidate, stable, unreported] = await Promise.all([enroll('0.20.1'), enroll('0.20.0'), enroll()]);
    const assign = (id, groupId, options) => post(`installations/${id}/policy-group`, { groupId }, { expect: 204, ...options });
    await assign(candidate.installationId, canary.id);
    await assign(stable.installationId, broad.id);
    const ids = ({ installations }) => installations.map(({ installationId }) => installationId).sort();
    const expected = { kind: 'release', extensionVersion: '0.20.1', installations: 1, recentReports: 1 };
    const cohort = await health(scope);
    assert.equal(cohort.activeInstallations, 3);
    assert.deepEqual(cohort.releases, [expected]);
    assert.deepEqual(ids(cohort), [candidate.installationId]);
    assert.deepEqual(ids(await health('rolloutGroup=baseline&browserVersion=unreported')), [unreported.installationId]);
    assert.deepEqual(ids(await health('browserVersion=0.20.0')), [stable.installationId]);
    const noMatch = await health(`${scope}&browserVersion=0.20.0`);
    assert.equal(noMatch.activeInstallations, 3);
    assert.deepEqual(noMatch.releases, [expected]);
    assert.deepEqual(noMatch.installations, []);
    assert.equal(noMatch.composerReadiness.activeInstallations, 0);
    assert.deepEqual(ids(await health('rolloutGroup=&browserVersion=')), [candidate.installationId, stable.installationId, unreported.installationId].sort());

    for (const input of ['rolloutGroup=invalid', 'rolloutGroup=00000000-0000-0000-0000-000000000000',
      `${scope}&rolloutGroup=baseline`, 'browserVersion=0.020.0', 'browserVersion=ZEKVAR_TEST_SECRET', 'browserVersion=&browserVersion=']) {
      const rejected = await health(input, { expect: 400 });
      assert.doesNotMatch(JSON.stringify(rejected), /ZEKVAR_TEST_SECRET/);
    }
    await health(`rolloutGroup=${foreign.id}`, { expect: 404 });
    await health(`rolloutGroup=${randomUUID()}`, { expect: 404 });
    await health(scope, { token: second, expect: 404 });
    await health(scope, { token: candidate.token, expect: 401 });
    await health(scope, { token: undefined, expect: 401 });
    const auditor = await post('access', { name: 'Group View Auditor', role: 'auditor', hours: 1 });
    assert.deepEqual(await health(scope, { token: auditor.token }), cohort);
    await assign(candidate.installationId, broad.id, { token: auditor.token, expect: 403 });

    for (const next of [broad.id, canary.id, null, canary.id]) {
      const [racing] = await Promise.all([health(scope), assign(candidate.installationId, next)]);
      assert.equal(racing.activeInstallations, 3);
      assert.equal(racing.releases.reduce((sum, row) => sum + row.installations, 0), racing.installations.length);
      assert.equal(racing.composerReadiness.activeInstallations, racing.installations.length);
      assert.ok(racing.installations.every(({ policyGroupId }) => policyGroupId === canary.id));
    }
    await post(`installations/${candidate.installationId}/revoke`, {}, { expect: 204 });
    const after = await health(scope);
    assert.equal(after.activeInstallations, 2);
    assert.deepEqual(after.releases, []);
    assert.ok(after.installations[0].revokedAt);

    if (postgres) {
      await retentionFixture(`INSERT INTO installations (id, organization_id, token_hash, policy_group_id, extension_version, extension_version_reported_at)
        SELECT gen_random_uuid(), o.id, encode(sha256(convert_to('group-view-${suffix}-' || n, 'UTF8')), 'hex'),
            '${canary.id}'::uuid, '0.20.0', now() - interval '2 minutes'
        FROM organizations o CROSS JOIN generate_series(1, 101) AS fixture(n) WHERE o.slug = 'group-view-${suffix}'`);
      const capped = await health(scope);
      assert.equal(capped.installations.length, 100);
      assert.equal(capped.composerReadiness.activeInstallations, 101);
      assert.equal(capped.composerReadiness.apps.find(({ appId }) => appId === 'chatgpt').counts.policy_pending, 101);
      const report = await admin(`reports/composer-readiness?${scope}&browserVersion=0.20.0`);
      assert.equal(report.activeInstallations, 101);
      assert.deepEqual(report.apps, capped.composerReadiness.apps);
      const older = await health(`${scope}&browserVersion=0.20.1`);
      assert.deepEqual(ids(older), [candidate.installationId]);
      assert.deepEqual(older.releases, [{ kind: 'release', extensionVersion: '0.20.0', installations: 101, recentReports: 0 }]);
      assert.equal(older.activeInstallations, 103);
    }
  });

  await t.test('issues guarded enrollment batches and atomically places browsers into their assigned group', async () => {
    const admin = (path, options = {}) => call(`/v1/admin/${path}`, { token: batchAdmin, ...options });
    const post = (path, body, options) => admin(path, { method: 'POST', body, ...options });
    const batches = (options) => admin('enrollment-batches', options);
    const redeem = (grant, scopedEnrollment = true, expect = 200) => call('/v1/enroll', { method: 'POST', body: { grant }, scopedEnrollment, expect });
    const cancel = (id, options) => post(`enrollment-batches/${id}/cancel`, {}, { expect: 204, ...options });
    const { grant: legacy } = await post('enrollment-grants');
    if (postgres) {
      await stop();
      await retentionFixture(`DELETE FROM schema_migrations WHERE version = 23;
          ALTER TABLE enrollment_grants DROP COLUMN batch_id;
          ALTER TABLE control_audit DROP COLUMN enrollment_batch_change;
          DROP TABLE enrollment_batches;`);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 23'), '1');
    }
    const existing = await redeem(legacy, false);
    assert.ok(existing.installationId);
    assert.deepEqual(await batches(), []);

    const group = await post('policy-groups', { name: 'Scoped enrollment group' });
    const foreign = await post('policy-groups', { name: 'Scoped enrollment group' }, { token: second });
    const targetPolicy = await post(`policy-groups/${group.id}/policies`, { mode: 'block' });
    const { token: named } = await post('access', { name: 'Enrollment Admin', role: 'administrator', hours: 1 });
    const { token: auditor } = await post('access', { name: 'Enrollment Auditor', role: 'auditor', hours: 1 });
    const request = { requestId: randomUUID(), groupId: group.id, count: 3 };
    const create = (body, options) => post('enrollment-batches', body, options);
    for (const invalid of [{ ...request, count: 0 }, { ...request, count: 26 }, { ...request, requestId: null },
      { ...request, groupId: '00000000-0000-0000-0000-000000000000' }, { ...request, count: 1.5 }, { ...request, extra: 'synthetic' }]) {
      await create(invalid, { expect: 400 });
    }
    await create({ ...request, groupId: foreign.id }, { expect: 404 });
    await create(request, { token: auditor, expect: 403 });
    await batches({ token: existing.token, expect: 401 });
    const simultaneous = await Promise.all([1, 2].map(() => fetch(`${baseUrl}/v1/admin/enrollment-batches`, {
      method: 'POST', headers: { Authorization: `Bearer ${named}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(request), signal: AbortSignal.timeout(5000),
    })));
    assert.deepEqual(simultaneous.map(({ status }) => status).sort(), [200, 409]);
    const issued = await simultaneous.find(({ status }) => status === 200).json();
    assert.deepEqual(await simultaneous.find(({ status }) => status === 409).json(), { code: 'enrollment_batch_exists' });
    assert.equal(issued.id, request.requestId);
    assert.equal(new Set(issued.grants).size, request.count);
    for (const grant of issued.grants) assert.match(grant, /^[a-f\d]{64}$/);
    assert.ok(Date.parse(issued.expiresAt) - Date.now() > 590_000);
    if (postgres) {
      const stored = await retentionFixture(`SELECT string_agg(token_hash, ',' ORDER BY token_hash) FROM enrollment_grants WHERE batch_id = '${issued.id}'`);
      assert.equal(stored, issued.grants.map((grant) => createHash('sha256').update(grant).digest('hex')).sort().join(','));
    }
    await redeem(issued.grants[0], false, 401);
    assert.equal((await batches())[0].available, 3);
    const redeemed = await redeem(issued.grants[0]);
    await redeem(issued.grants[0], true, 401);
    const beforePolicy = (await admin('installations')).find(({ installationId }) => installationId === redeemed.installationId);
    assert.equal(beforePolicy.policyGroupId, group.id);
    assert.equal(beforePolicy.expectedPolicyVersion, targetPolicy.version);
    assert.equal(beforePolicy.appliedPolicyVersion, null);
    const policy = () => call('/v1/browser/policy', { token: redeemed.token, assignmentAware: true });
    await call('/v1/browser/policy', { token: redeemed.token, expect: 409 });
    assert.deepEqual([(await policy()).version, (await policy()).assignmentVersion], [targetPolicy.version, 1]);
    await cancel(issued.id, { token: auditor, expect: 403 });
    await cancel(issued.id, { token: second, expect: 404 });
    assert.deepEqual(await batches({ token: second }), []);
    const [, race] = await Promise.all([cancel(issued.id, { token: named }), fetch(`${baseUrl}/v1/enroll`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Zekvar-Scoped-Enrollment': '1' },
      body: JSON.stringify({ grant: issued.grants[1] }), signal: AbortSignal.timeout(5000),
    })]);
    assert.ok([200, 401].includes(race.status));
    const redeemedCount = race.status === 200 ? 2 : 1;
    if (race.ok) assert.ok((await race.json()).installationId);
    await cancel(issued.id, { token: named });
    await redeem(issued.grants[2], true, 401);
    assert.equal((await policy()).version, targetPolicy.version);
    const [closed] = await batches({ token: auditor });
    assert.equal(closed.status, 'cancelled');
    assert.equal(closed.available, 0);
    assert.equal(closed.redeemed, redeemedCount);
    const audit = (await admin('audit')).entries;
    const change = audit.filter((row) => row.enrollmentBatchChange?.batchId === issued.id);
    assert.deepEqual(change.filter((row) => row.action === 'enrollment_batch_issued').map((row) => row.actorAccess.name), ['Enrollment Admin']);
    assert.deepEqual(change.filter((row) => row.action === 'enrollment_batch_cancelled').map((row) => row.enrollmentBatchChange.count), [3 - redeemedCount]);
    assert.equal(change.filter((row) => row.action === 'browser_enrolled').length, redeemedCount);
    for (const token of issued.grants) assert.ok(!JSON.stringify({ closed, audit }).includes(token));

    const baseline = await create({ requestId: randomUUID(), groupId: null, count: 1 });
    await redeem(baseline.grants[0], false);
    assert.equal((await batches()).find(({ id }) => id === baseline.id).status, 'used');
    if (postgres) {
      const expiring = await create({ requestId: randomUUID(), groupId: group.id, count: 1 });
      await retentionFixture(`UPDATE enrollment_batches SET expires_at = now() - interval '1 second' WHERE id = '${expiring.id}';
        UPDATE enrollment_grants SET expires_at = now() - interval '1 second' WHERE batch_id = '${expiring.id}';`);
      await redeem(expiring.grants[0], true, 401);
      await cancel(expiring.id);
      assert.equal((await batches()).find(({ id }) => id === expiring.id).status, 'expired');
    }
  });

  await t.test('aggregates retained AI decisions by UTC day, app, and rule from a single tenant', async () => {
    const admin = (path, options = {}) => call(`/v1/admin/${path}`, { token: reportAdmin, ...options });
    const report = (query = '', options) => admin(`reports/ai-enforcement${query && `?${query}`}`, options);
    const post = (path, body, options) => admin(path, { method: 'POST', body, ...options });
    async function enroll(token = reportAdmin) {
      const { grant } = await post('enrollment-grants', {}, { token });
      return call('/v1/enroll', { method: 'POST', body: { grant } });
    }
    const empty = { monitor: 0, warn: 0, block: 0, warn_override: 0, exception_applied: 0 };
    const initial = await report();
    assert.equal(initial.days, 7);
    assert.equal(initial.organization, `report-${suffix}`);
    assert.equal(initial.appId, null);
    assert.deepEqual(initial.counts, empty);
    assert.deepEqual(initial.byApp, []);
    assert.deepEqual(initial.byRule, []);
    assert.equal(initial.daily.length, 7);
    assert.ok(initial.daily.every(({ counts }) => Object.values(counts).every((count) => count === 0)));

    const [one, two, foreign] = await Promise.all([enroll(), enroll(), enroll(batchAdmin)]);
    const selected = await post('policies', { mode: 'warn', githubPatMode: 'block', uploadModes: { chatgpt: 'monitor', gemini: 'off' } });
    const auditor = await post('access', { name: 'Report reviewer', role: 'auditor', hours: 1 });
    const named = await post('access', { name: 'Report admin', role: 'administrator', hours: 1 });
    const dayMs = 86_400_000;
    const weekStart = Date.parse(initial.startOn);
    const now = Date.now();
    const warn = { ...event, appId: 'chatgpt', eventId: randomUUID(), timestamp: new Date(now).toISOString(),
      policyVersion: selected.version, decision: 'warn' };
    const submit = (browser, patch, expect = 204) => call('/v1/browser/events', { method: 'POST', token: browser.token,
      body: { ...warn, ...patch }, expect });
    await Promise.all([submit(one, {}), submit(one, {}), submit(two, {})]);
    const oldReceipt = randomUUID();
    await Promise.all([
      submit(one, { eventId: randomUUID(), decision: 'warn_override' }),
      submit(one, { eventId: randomUUID(), appId: 'gemini', decision: 'block', ruleId: 'github-classic-pat', detectorCategory: 'credential' }),
      submit(one, { eventId: randomUUID(), decision: 'monitor', ruleId: 'ai-file-upload', detectorCategory: 'file-upload', uploadMethod: 'paste' }),
      submit(one, { eventId: randomUUID(), appId: 'local-prompt-fixture' }),
      submit(one, { eventId: randomUUID(), timestamp: new Date(now + 3_600_000).toISOString() }),
      submit(one, { eventId: randomUUID(), timestamp: new Date(weekStart - 1).toISOString() }),
      submit(one, { eventId: randomUUID(), timestamp: new Date(weekStart).toISOString() }),
      submit(one, { eventId: oldReceipt }),
      submit(one, { eventId: randomUUID(), prompt: 'synthetic-private-report-test' }, 400),
      submit(foreign, { eventId: randomUUID(), policyVersion: 1, decision: 'monitor' }),
    ]);

    if (postgres) {
      await retentionFixture(`UPDATE security_events SET received_at = now() - interval '4 days' WHERE event_id = '${oldReceipt}';`);
    }
    await delay(5);
    const anchor = Date.now();
    const week = `asOf=${anchor}`;
    const month = `days=30&${week}`;
    const current = await report(week);
    assert.equal(Date.parse(current.asOf), anchor);
    assert.equal(current.startOn, initial.startOn);
    assert.deepEqual(current.counts, { ...empty, monitor: 1, warn: 4, block: 1, warn_override: 1 });
    assert.deepEqual(current.daily[0].counts, { ...empty, warn: 1 });
    assert.deepEqual(current.daily.at(-1).counts, { ...empty, monitor: 1, warn: 3, block: 1, warn_override: 1 });
    assert.deepEqual(current.byApp, [
      { id: 'chatgpt', counts: { ...empty, monitor: 1, warn: 4, warn_override: 1 } },
      { id: 'gemini', counts: { ...empty, block: 1 } },
    ]);
    assert.deepEqual(current.byRule, [
      { id: 'ai-file-upload', counts: { ...empty, monitor: 1 } },
      { id: 'fixture-secret', counts: { ...empty, warn: 4, warn_override: 1 } },
      { id: 'github-classic-pat', counts: { ...empty, block: 1 } },
    ]);
    const scoped = await report(`${month}&appId=chatgpt`);
    assert.equal(scoped.appId, 'chatgpt');
    assert.equal(scoped.daily.length, 30);
    assert.equal(scoped.startOn, new Date(weekStart - 23 * dayMs).toISOString().slice(0, 10));
    assert.deepEqual(scoped.counts, { ...empty, monitor: 1, warn: 5, warn_override: 1 });
    assert.deepEqual((await report(`${month}&appId=claude`)).counts, empty);
    assert.deepEqual(await report(week, { token: auditor.token }), current);
    assert.deepEqual(await report(week, { token: named.token }), current);
    assert.deepEqual((await report(week, { token: batchAdmin })).counts, { ...empty, monitor: 1 });
    await report('', { token: one.token, expect: 401 });
    await report('', { token: null, expect: 401 });
    for (const query of ['days=0', 'days=07', 'days=7&days=30', 'appId=', 'appId=local-prompt-fixture',
      'appId=chatgpt&appId=gemini', 'organization=another', 'asOf=99999999999999999999999', 'asOf=0',
      `asOf=${anchor + 2 * dayMs}`, `${week}&asOf=${anchor}`]) await report(query, { expect: 400 });

    await submit(one, { eventId: randomUUID(), timestamp: new Date(now - 100).toISOString() });
    assert.deepEqual(await report(week), current);
    await delay(5);
    assert.equal((await report()).counts.warn, 5);
    await post(`installations/${two.installationId}/revoke`, {}, { expect: 204 });
    assert.deepEqual(await report(week), current);
    const raw = (await admin(`events/export?${new URLSearchParams({ since: `${current.startOn}T00:00:00Z`, until: current.asOf })}`)).entries;
    assert.equal(raw.filter(({ appId, receivedAt }) => appId !== 'local-prompt-fixture' && Date.parse(receivedAt) <= anchor).length, 7);
    for (const secret of [one.token, two.installationId, warn.eventId, reportAdmin, 'synthetic-private-report-test']) {
      assert.ok(!JSON.stringify(current).includes(secret));
    }

    await post('retention', { securityEventDays: 1, aiObservationDays: null, auditDays: null }, { expect: 204 });
    const retained = { ...empty, monitor: 1, warn: postgres ? 2 : 3, block: 1, warn_override: 1 };
    assert.deepEqual((await report(week)).counts, retained);
    await post('retention/cleanup', {});
    assert.deepEqual((await report(week)).counts, retained);
    await post(`access/${auditor.access.id}/revoke`, {}, { expect: 204 });
    await report(week, { token: auditor.token, expect: 401 });

    if (postgres) {
      const before = await report(week);
      await stop();
      await retentionFixture(`DELETE FROM schema_migrations WHERE version = 24;
        DROP INDEX ai_events_by_organization_time;`);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 24'), '1');
      assert.equal(await retentionFixture("SELECT to_regclass('public.ai_events_by_organization_time')"), 'ai_events_by_organization_time');
      assert.deepEqual(await report(week), before);
    }
  });

  await t.test('counts only timely composer observations for the current applied policy and assignment', async () => {
    const admin = (path, options = {}) => call(`/v1/admin/${path}`, { token: coverageAdmin, ...options });
    const post = (path, body, expect = 200) => admin(path, { method: 'POST', body, expect });
    const health = (filter = '', options) => admin(`browser-health?${filter}`, options);
    const report = (filter = '', options) => admin(`reports/composer-readiness?${filter}`, options);
    const appCount = (view, app, state) => view.composerReadiness.apps.find(({ appId }) => appId === app).counts[state];
    const check = (view, browser, app) => view.installations.find(({ installationId }) => installationId === browser.installationId).composerReadiness[app];
    const policy = (browser, extensionVersion) => call('/v1/browser/policy', { token: browser.token, assignmentAware: true,
      claudeAware: true, extensionVersion });
    const heartbeat = (browser, policy, reports = {}, { composerAware = true, expect = 204 } = {}) =>
      call('/v1/browser/heartbeat', { token: browser.token, method: 'POST', composerAware, expect,
        body: { policyVersion: policy.version, assignmentVersion: policy.assignmentVersion, ...reports } });
    const assign = (browser, groupId) => post(`installations/${browser.installationId}/policy-group`, { groupId }, 204);
    async function enroll(version) {
      const { grant } = await post('enrollment-grants');
      const browser = await call('/v1/enroll', { method: 'POST', body: { grant } });
      await policy(browser, version);
      return browser;
    }
    const [current, legacy, pending] = await Promise.all([enroll('0.22.0'), enroll('0.21.0'), enroll()]);
    const group = await post('policy-groups', { name: 'Composer readiness' });
    const sibling = await post('policy-groups', { name: 'Sibling readiness' });
    const scope = `rolloutGroup=${group.id}`;
    await assign(current, group.id);
    await assign(legacy, group.id);
    let v1 = await policy(current);
    await heartbeat(legacy, await policy(legacy), { chatGptCoverage: 'ready', geminiCoverage: 'unsupported' }, { composerAware: false });
    if (postgres) {
      await stop();
      await retentionFixture('DELETE FROM schema_migrations WHERE version = 25; DROP TABLE composer_observations;');
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 25'), '1');
      const history = (await admin('installations')).find(({ installationId }) => installationId === legacy.installationId);
      assert.equal(history.chatGptCoverage, 'ready');
      assert.equal(history.geminiCoverage, 'unsupported');
    }
    await heartbeat(current, v1, { chatGptCoverage: 'ready', geminiCoverage: 'unsupported' });
    const before = await health(scope);
    assert.equal(before.composerReadiness.activeInstallations, 2);
    assert.equal(appCount(before, 'chatgpt', 'detected'), 1);
    assert.equal(appCount(before, 'chatgpt', 'unobserved'), 1);
    assert.equal(appCount(before, 'gemini', 'unsupported'), 1);
    assert.equal(appCount(before, 'claude', 'off'), 2);
    assert.equal(before.composerReadinessExportAvailable, true);
    assert.equal(check(before, legacy, 'chatgpt').state, 'unobserved');
    assert.ok(Date.parse(check(before, current, 'chatgpt').checkedAt));
    assert.equal(check(await health(), pending, 'chatgpt').state, 'policy_pending');
    assert.equal((await health(`${scope}&browserVersion=0.22.0`)).composerReadiness.activeInstallations, 1);
    assert.equal(appCount(await health(`${scope}&browserVersion=0.21.0`), 'chatgpt', 'unobserved'), 1);
    assert.equal(appCount(await health('rolloutGroup=baseline&browserVersion=unreported'), 'chatgpt', 'policy_pending'), 1);
    await health(scope, { token: current.token, expect: 401 });
    await health(scope, { token: second, expect: 404 });
    const captured = await report(`${scope}&browserVersion=0.22.0`);
    assert.deepEqual(Object.keys(captured).sort(), ['activeInstallations', 'apps', 'asOf', 'freshness', 'schemaVersion', 'scope']);
    assert.equal(captured.schemaVersion, 1);
    assert.ok(Date.parse(captured.asOf) >= Date.parse(check(before, current, 'chatgpt').checkedAt));
    assert.deepEqual(captured.freshness, { heartbeatSeconds: 90, observationSeconds: 86_400 });
    assert.deepEqual(captured.scope, { rolloutGroup: group.id, rolloutGroupName: group.name,
      browserVersion: '0.22.0', targetPolicyVersion: v1.version });
    assert.deepEqual(captured.apps, (await health(`${scope}&browserVersion=0.22.0`)).composerReadiness.apps);
    assert.equal(captured.activeInstallations, 1);
    assert.doesNotMatch(JSON.stringify(captured), /installationId|checkedAt|token/);
    assert.ok(!JSON.stringify(captured).includes(current.installationId));
    assert.deepEqual((await report()).scope, { rolloutGroup: 'all', rolloutGroupName: null, browserVersion: null, targetPolicyVersion: null });
    const baselineReport = await report('rolloutGroup=baseline&browserVersion=unreported');
    assert.deepEqual(baselineReport.scope, { rolloutGroup: 'baseline', rolloutGroupName: null, browserVersion: 'unreported', targetPolicyVersion: v1.version });
    assert.equal(baselineReport.activeInstallations, 1);
    const noMatches = await report(`${scope}&browserVersion=99.0`);
    assert.equal(noMatches.activeInstallations, 0);
    assert.ok(noMatches.apps.every(({ counts }) => Object.values(counts).every((count) => count === 0)));
    for (const query of ['rolloutGroup=unknown', `${scope}&rolloutGroup=baseline`, 'browserVersion=ZEKVAR_TEST_SECRET',
      'browserVersion=&browserVersion=', 'appId=chatgpt']) {
      assert.doesNotMatch(JSON.stringify(await report(query, { expect: 400 })), /ZEKVAR_TEST_SECRET/);
    }
    await report(scope, { token: current.token, expect: 401 });
    await report(scope, { token: undefined, expect: 401 });
    await report(scope, { token: second, expect: 404 });
    assert.equal((await report('browserVersion=0.22.0', { token: second })).activeInstallations, 0);

    await assign(current, sibling.id);
    const samePolicy = await policy(current);
    assert.equal(samePolicy.version, v1.version);
    assert.notEqual(samePolicy.assignmentVersion, v1.assignmentVersion);
    await heartbeat(current, v1, { chatGptCoverage: 'ready' }, { expect: 400 });
    await heartbeat(current, samePolicy);
    assert.equal(check(await health(), current, 'chatgpt').state, 'unobserved');
    await assign(current, group.id);
    v1 = await policy(current);
    await heartbeat(current, v1, { chatGptCoverage: 'ready' });
    await post(`policy-groups/${group.id}/policies`, { mode: 'block', claudePromptEnabled: true });
    const waiting = await health(scope);
    assert.equal(appCount(waiting, 'chatgpt', 'policy_pending'), 2);
    assert.equal(appCount(waiting, 'claude', 'policy_pending'), 2);
    const v2 = await policy(current);
    const pendingReport = await report(scope);
    assert.equal(pendingReport.scope.targetPolicyVersion, v2.version);
    assert.deepEqual(pendingReport.apps, waiting.composerReadiness.apps);
    await heartbeat(current, v2, { chatGptCoverage: 'ready', claudeCoverage: 'ready' }, { expect: 400 });
    await heartbeat(current, v2, { chatGptCoverage: 'ready', claudePromptApplied: true, claudeCoverage: 'ready' });
    await heartbeat(current, v1, { chatGptCoverage: 'unsupported', geminiCoverage: 'ready' });
    const newer = await health(scope);
    assert.equal(check(newer, current, 'chatgpt').state, 'detected');
    assert.equal(check(newer, current, 'gemini').state, 'unobserved');
    assert.equal(check(newer, current, 'claude').state, 'detected');
    assert.equal(appCount(newer, 'claude', 'detected'), 1);
    assert.doesNotMatch(JSON.stringify(newer.composerReadiness), /installationId|checkedAt|token/);
    const badReport = { geminiCoverage: 'synthetic raw prompt' };
    await heartbeat(current, v2, badReport, { expect: 400 });

    if (postgres) {
      await retentionFixture(`UPDATE composer_observations SET checked_at = now() - interval '25 hours'
        WHERE installation_id = '${current.installationId}' AND app_id = 'chatgpt';`);
      const older = await health(scope);
      assert.equal(check(older, current, 'chatgpt').state, 'stale');
      assert.equal(check(older, current, 'claude').state, 'detected');
      assert.deepEqual((await report(scope)).apps, older.composerReadiness.apps);
      await retentionFixture(`UPDATE installations SET last_seen_at = now() - interval '91 seconds' WHERE id = '${current.installationId}';`);
      assert.equal(appCount(await health(scope), 'claude', 'stale'), 1);
      await heartbeat(current, v2, { claudePromptApplied: true, chatGptCoverage: 'ready' });
      assert.equal(appCount(await health(scope), 'chatgpt', 'detected'), 1);
    }

    const auditor = await post('access', { name: 'Coverage auditor', role: 'auditor', hours: 1 });
    assert.deepEqual((await health(scope, { token: auditor.token })).composerReadiness, (await health(scope)).composerReadiness);
    const auditorReport = await report(scope, { token: auditor.token });
    assert.deepEqual(auditorReport.apps, (await report(scope)).apps);
    assert.equal(auditorReport.activeInstallations, 2);
    await post(`installations/${current.installationId}/revoke`, {}, 204);
    const revoked = await health(scope);
    assert.equal(revoked.composerReadiness.activeInstallations, 1);
    assert.deepEqual((await report(scope)).apps, revoked.composerReadiness.apps);
    assert.equal(appCount(revoked, 'chatgpt', 'detected'), 0);
    assert.equal(revoked.installations.find(({ installationId }) => installationId === current.installationId).composerReadiness, undefined);
    if (postgres) assert.equal(await retentionFixture(`SELECT count(*) FROM composer_observations WHERE installation_id = '${current.installationId}'`), '0');
  });

  await t.test('versions private key protection and proves browser delivery before accepting enforcement metadata', async () => {
    const admin = (path, options = {}) => call(`/v1/admin/${path}`, { token: keyAdmin, ...options });
    const post = (path, body, options) => admin(path, { method: 'POST', body, ...options });
    const current = async () => (await admin('policies'))[0];
    const before = await current();
    assert.equal(before.privateKeyMode, 'off');
    if (postgres) {
      await stop();
      await retentionFixture(`${undoIdentifierSchema}
        DELETE FROM schema_migrations WHERE version = 26;
        ALTER TABLE policy_versions DROP COLUMN private_key_mode;
        ALTER TABLE policy_deliveries DROP COLUMN private_key;`);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 26'), '1');
      assert.deepEqual(await current(), before);
    }
    const { grant } = await post('enrollment-grants');
    const client = await call('/v1/enroll', { method: 'POST', body: { grant } });
    const browser = (path, options) => call(`/v1/browser/${path}`, { token: client.token, assignmentAware: true, ...options });
    const fetchPolicy = (privateKeyAware = true) => browser('policy', { privateKeyAware });
    const heartbeat = (policy, fields, expect = 204) => browser('heartbeat', { method: 'POST', expect,
      body: { policyVersion: policy.version, assignmentVersion: policy.assignmentVersion, ...fields } });
    const details = async () => (await admin('installations')).find(({ installationId }) => installationId === client.installationId);
    const decision = (policy, action, extra) => ({ ...event, eventId: randomUUID(), appId: 'chatgpt',
      policyVersion: policy.version, assignmentVersion: policy.assignmentVersion, timestamp: new Date().toISOString(),
      decision: action, ruleId: 'pem-private-key', detectorCategory: 'credential', ...extra });
    const submit = (body, expect = 204) => browser('events', { method: 'POST', body, expect });

    const initial = await fetchPolicy();
    assert.equal(initial.privateKeyMode, 'off');
    await heartbeat(initial, {});
    await submit(decision(initial, 'monitor'), 400);
    await post('policies', { privateKeyMode: 'allow' }, { expect: 400 });
    await post('policies', { privateKeyMode: 'block', expectedVersion: initial.version + 1 }, { expect: 409 });
    assert.equal((await current()).version, initial.version);

    const warn = await post('policies', { privateKeyMode: 'warn' });
    const legacy = await fetchPolicy(false);
    assert.equal(legacy.privateKeyMode, 'off');
    await heartbeat(legacy, {});
    assert.equal((await details()).appliedPolicyVersion, initial.version);
    await heartbeat(legacy, { privateKeyModeApplied: true }, 400);
    await submit(decision(legacy, 'warn'), 400);
    const supported = await fetchPolicy();
    assert.equal(supported.privateKeyMode, 'warn');
    assert.equal(supported.mode, initial.mode);
    await heartbeat(supported, { privateKeyModeApplied: true });
    assert.equal((await details()).appliedPolicyVersion, supported.version);
    const reported = decision(supported, 'warn');
    await Promise.all([submit(reported), submit(reported)]);
    await submit(decision(supported, 'warn_override'));
    await submit(decision(supported, 'block'), 400);
    await submit(decision(supported, 'warn', { detectorCategory: 'payment-card' }), 400);
    await submit(decision(supported, 'warn', { privateKey: 'synthetic private key content' }), 400);
    await heartbeat(supported, {});
    assert.equal((await details()).appliedPolicyVersion, null);
    assert.equal((await fetchPolicy(false)).privateKeyMode, 'off');
    await heartbeat(await fetchPolicy(), { privateKeyModeApplied: true });

    const expiresAt = new Date(Date.now() + 60_000).toISOString();
    const grants = ['chatgpt', 'gemini', 'claude'].flatMap((appId) => ['fixture-secret', 'github-classic-pat', 'payment-card-number', 'pem-private-key']
      .map((ruleId) => ({ appId, ruleId, expiresAt, reason: 'Synthetic review ticket' })));
    const excepted = await post('policies', { promptExceptions: grants });
    assert.equal(excepted.privateKeyMode, 'warn');
    assert.equal(excepted.promptExceptions.length, 12);
    assert.equal((await fetchPolicy(false)).promptExceptionLease.grants.some(({ ruleId }) => ruleId === 'pem-private-key'), false);
    const leased = await fetchPolicy();
    assert.ok(leased.promptExceptionLease.grants.some(({ ruleId }) => ruleId === 'pem-private-key'));
    await heartbeat(leased, { privateKeyModeApplied: true, promptExceptionsApplied: true });
    await submit(decision(leased, 'exception_applied'));

    const records = (await admin('events/export?appId=chatgpt')).entries;
    assert.deepEqual(records.map(({ decision, detectorCategory }) => [decision, detectorCategory]),
      [['exception_applied', 'credential'], ['warn_override', 'credential'], ['warn', 'credential']]);
    assert.doesNotMatch(JSON.stringify(records), /Synthetic review ticket|synthetic private key content|privateKey/);
    assert.deepEqual((await admin('events/export?appId=chatgpt', { token: coverageAdmin })).entries, []);

    const group = await post('policy-groups', { name: 'Private key pilot' });
    const groupPath = `policy-groups/${group.id}`;
    const previous = await post(`${groupPath}/policies`, { privateKeyMode: 'monitor' });
    const author = await post('access', { name: 'Key policy author', role: 'administrator', hours: 1 });
    const reviewer = await post('access', { name: 'Key policy approver', role: 'administrator', hours: 1 });
    await post('policy-reviews/setting', { required: true }, { expect: 204 });
    const proposed = await post(`${groupPath}/policies`, { privateKeyMode: 'block' }, { token: author.token, expectReview: true, expect: 202 });
    await post(`policy-reviews/${proposed.reviewId}/decision`, { approve: true }, { token: author.token, expect: 403 });
    const approved = await post(`policy-reviews/${proposed.reviewId}/decision`, { approve: true }, { token: reviewer.token });
    assert.equal(approved.privateKeyMode, 'block');
    await post('policy-reviews/setting', { required: false }, { expect: 204 });
    assert.equal((await post(`${groupPath}/promote`, { expectedVersion: approved.version })).privateKeyMode, 'block');
    assert.equal((await post(`${groupPath}/policies/${previous.version}/restore`)).privateKeyMode, 'monitor');
    assert.equal((await post(`policies/${warn.version}/restore`)).privateKeyMode, 'warn');
    assert.equal((await post(`policies/${initial.version}/restore`)).privateKeyMode, 'off');
  });

  await t.test('validates negotiated file inspection independently of prompt modes and file upload policies', async () => {
    const admin = (path, options = {}) => call(`/v1/admin/${path}`, { token: fileAdmin, ...options });
    const post = (path, body, options) => admin(path, { method: 'POST', body, ...options });
    const off = { chatgpt: false, gemini: false };
    const current = async () => (await admin('policies'))[0];
    assert.deepEqual((await current()).fileInspection, off);
    if (postgres) {
      await stop();
      await retentionFixture(`${undoIdentifierSchema}
        DELETE FROM schema_migrations WHERE version IN (27, 32);
        ALTER TABLE policy_versions DROP COLUMN chatgpt_file_content_block, DROP COLUMN gemini_file_content_block,
          DROP COLUMN chatgpt_file_inspection, DROP COLUMN gemini_file_inspection;
        ALTER TABLE policy_deliveries DROP COLUMN file_inspection, DROP COLUMN file_content_block;`);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 27'), '1');
    }

    const { grant } = await post('enrollment-grants');
    const client = await call('/v1/enroll', { method: 'POST', body: { grant } });
    const browser = (path, options) => call(`/v1/browser/${path}`, { token: client.token, assignmentAware: true, ...options });
    const fetchPolicy = (options) => browser('policy', { fileInspectionAware: true, privateKeyAware: true, ...options });
    const heartbeat = (policy, fields, expect = 204) => browser('heartbeat', { method: 'POST', expect,
      body: { policyVersion: policy.version, assignmentVersion: policy.assignmentVersion, ...fields } });
    const send = (policy, overrides = {}, expect = 204) => browser('events', { method: 'POST', expect,
      body: { ...event, eventId: randomUUID(), timestamp: new Date().toISOString(), policyVersion: policy.version,
        assignmentVersion: policy.assignmentVersion, appId: 'chatgpt', decision: 'monitor', uploadMethod: 'picker', ...overrides } });
    const observed = async () => (await admin('installations'))[0].appliedPolicyVersion;
    const initial = await fetchPolicy();
    await heartbeat(initial, {});
    await send(initial, {}, 400);
    await post('policies', { fileInspection: {} }, { expect: 400 });
    await post('policies', { fileInspection: { chatgpt: 'block' } }, { expect: 400 });
    await post('policies', { fileInspection: { copilot: true } }, { expect: 400 });
    const draft = await post('policies', { mode: 'block', githubPatMode: 'warn', privateKeyMode: 'block', fileInspection: { chatgpt: true } });
    const legacy = await fetchPolicy({ fileInspectionAware: false });
    assert.deepEqual(legacy.fileInspection, off);
    await heartbeat(legacy, { privateKeyModeApplied: true });
    assert.equal(await observed(), initial.version);
    await heartbeat(legacy, { privateKeyModeApplied: true, fileInspectionApplied: true }, 400);
    await send(legacy, {}, 400);
    const aware = await fetchPolicy();
    assert.equal(aware.version, draft.version);
    assert.deepEqual(aware.fileInspection, { chatgpt: true, gemini: false });
    await heartbeat(aware, { privateKeyModeApplied: true, fileInspectionApplied: true });
    assert.equal(await observed(), aware.version);

    const exportPath = 'events/export';
    const id = randomUUID();
    const pat = { ruleId: 'github-classic-pat', detectorCategory: 'credential', uploadMethod: 'drop', eventId: id };
    await Promise.all([send(aware, pat), send(aware, pat)]);
    await send(aware, { ruleId: 'pem-private-key', detectorCategory: 'credential', uploadMethod: 'paste' });
    await send(aware, { uploadMethod: undefined, decision: 'block' });
    for (const input of [ { appId: 'gemini' }, { appId: 'claude' }, { appId: 'local-prompt-fixture' }, { decision: 'block' },
      { decision: 'exception_applied' }, { uploadMethod: 'clipboard' }, { fileName: 'synthetic-sensitive-filename.txt' }, { content: 'synthetic-sensitive-file-contents' },
      { ruleId: 'payment-card-number', detectorCategory: 'payment-card' } ]) await send(aware, input, 400);

    await post('policies', { fileInspection: { gemini: true }, uploadModes: { chatgpt: 'monitor' } });
    const both = await fetchPolicy();
    assert.deepEqual(both.fileInspection, { chatgpt: true, gemini: true });
    await send(both, { appId: 'gemini' });
    await send(both, { ruleId: 'ai-file-upload', detectorCategory: 'file-upload' });
    const records = (await admin(exportPath)).entries;
    assert.equal(records.length, 5);
    assert.equal(records.filter(({ eventId }) => eventId === id).length, 1);
    assert.doesNotMatch(JSON.stringify(records), /synthetic-sensitive|fileName|mimeType|size/);
    assert.deepEqual((await admin(exportPath, { token: coverageAdmin })).entries, []);
    const sourceCounts = (await admin('reports/ai-enforcement')).bySource;
    assert.deepEqual(sourceCounts.map(({ id, counts }) => [id, counts.monitor, counts.block]),
      [['file_content', 3, 0], ['file_policy', 1, 0], ['prompt', 0, 1]]);

    const group = await post('policy-groups', { name: 'File content cohort' });
    const groupPath = `policy-groups/${group.id}`;
    const scoped = await post(`${groupPath}/policies`, { fileInspection: { chatgpt: false } });
    assert.deepEqual(scoped.fileInspection, { chatgpt: false, gemini: true });
    assert.deepEqual((await current()).fileInspection, { chatgpt: true, gemini: true });
    assert.deepEqual((await post(`${groupPath}/promote`, { expectedVersion: scoped.version })).fileInspection, scoped.fileInspection);
    assert.deepEqual((await post(`policies/${initial.version}/restore`)).fileInspection, off);
    await send(await fetchPolicy(), {}, 400);
  });

  await t.test('requires content-block capability and preserves exact per-app modes through review and rollback', async () => {
    const admin = (path, options = {}) => call(`/v1/admin/${path}`, { token: fileAdmin, ...options });
    const post = (path, body, options) => admin(path, { method: 'POST', body, ...options });
    const [initial] = await admin('policies');
    await post('policies', { fileContentModes: { chatgpt: 'warn' } }, { expect: 400 });
    await post('policies', { fileContentModes: { copilot: 'block' } }, { expect: 400 });
    await post('policies', { fileContentModes: { claude: 'warn' } }, { expect: 400 });
    await post('policies', { fileContentModes: {} }, { expect: 400 });
    const oldSetting = await post('policies', { fileInspection: { gemini: true } });
    assert.deepEqual(oldSetting.fileContentModes, { chatgpt: 'off', gemini: 'monitor' });
    if (postgres) {
      await stop();
      await retentionFixture(`${undoIdentifierSchema}
        DELETE FROM schema_migrations WHERE version = 32;
        ALTER TABLE policy_versions DROP COLUMN chatgpt_file_content_block, DROP COLUMN gemini_file_content_block;
        ALTER TABLE policy_deliveries DROP COLUMN file_content_block;`);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 32'), '1');
      assert.deepEqual((await admin('policies'))[0], oldSetting);
    }
    const { grant } = await post('enrollment-grants');
    const browser = await call('/v1/enroll', { method: 'POST', body: { grant } });
    const client = (path, options) => call(`/v1/browser/${path}`, { token: browser.token, assignmentAware: true, ...options });
    const block = await post('policies', { fileContentModes: { chatgpt: 'block' }, privateKeyMode: 'off' });
    assert.deepEqual(block.fileContentModes, { chatgpt: 'block', gemini: 'monitor' });
    const legacy = await client('policy', { fileInspectionAware: true });
    assert.equal(Object.hasOwn(legacy, 'fileContentModes'), false);
    assert.deepEqual(legacy.fileInspection, { chatgpt: false, gemini: true });
    const heartbeat = (fields, expect = 204) => client('heartbeat', { method: 'POST', expect,
      body: { policyVersion: block.version, fileInspectionApplied: true, ...fields } });
    const applied = async () => (await admin('installations')).find(({ installationId }) => installationId === browser.installationId).appliedPolicyVersion;
    await heartbeat({});
    assert.equal(await applied(), null);
    await heartbeat({ fileContentBlockApplied: true }, 400);
    const baseEvent = { ...event, timestamp: new Date().toISOString(), policyVersion: block.version,
      appId: 'chatgpt', decision: 'block', uploadMethod: 'drop' };
    const send = (fields, expect = 204) => client('events', { method: 'POST', expect, body: { ...baseEvent, eventId: randomUUID(), ...fields } });
    await send({}, 400);
    await send({ appId: 'gemini', decision: 'monitor' });
    const modern = await client('policy', { fileInspectionAware: true, fileBlockAware: true, privateKeyAware: true });
    assert.deepEqual(modern.fileContentModes, block.fileContentModes);
    await heartbeat({ fileContentBlockApplied: true });
    assert.equal(await applied(), block.version);
    const unavailable = { ruleId: 'file-inspection-unavailable', detectorCategory: 'file-upload' };
    for (const input of [{ appId: 'gemini' }, { decision: 'monitor' }, { ...unavailable, decision: 'monitor' },
      { ...unavailable, uploadMethod: undefined }, { ruleId: 'pem-private-key', detectorCategory: 'credential' },
      { ...unavailable, fileName: 'synthetic-file.txt' }, { content: 'synthetic-sensitive-value' }]) await send(input, 400);
    const id = randomUUID();
    await Promise.all([send({ eventId: id }), send({ eventId: id })]);
    await send({ ...unavailable, uploadMethod: 'paste' });
    const stored = (await admin('events/export?decision=block')).entries.filter(({ policyVersion }) => policyVersion === block.version);
    assert.deepEqual(stored.map(({ ruleId }) => ruleId).sort(), ['file-inspection-unavailable', 'fixture-secret']);
    const compatible = await post('policies', { fileInspection: { chatgpt: true } });
    assert.deepEqual(compatible.fileContentModes, block.fileContentModes);
    const group = await post('policy-groups', { name: 'File blocking review' });
    const applicants = await Promise.all(['File policy author', 'File policy reviewer'].map((name) =>
      post('access', { name, role: 'administrator', hours: 1 })));
    await post('policy-reviews/setting', { required: true }, { expect: 204 });
    const groupPath = `policy-groups/${group.id}/policies`;
    const draft = await post(groupPath, { fileContentModes: { chatgpt: 'monitor', gemini: 'block' }, expectedVersion: compatible.version },
      { token: applicants[0].token, expectReview: true, expect: 202 });
    const queued = await admin('policy-reviews');
    const pending = queued.entries.find((review) => review.id === draft.reviewId);
    assert.deepEqual(pending.snapshots.candidate.fileContentModes, { chatgpt: 'monitor', gemini: 'block' });
    const approved = await post(`policy-reviews/${draft.reviewId}/decision`, { approve: true }, { token: applicants[1].token });
    assert.deepEqual(approved.fileContentModes, { chatgpt: 'monitor', gemini: 'block' });
    assert.deepEqual((await admin(groupPath))[0].fileContentModes, approved.fileContentModes);
    assert.deepEqual((await admin('policies'))[0].fileContentModes, compatible.fileContentModes);
    const claudeDraft = await post(groupPath, { claudePromptEnabled: true, expectedVersion: approved.version,
      uploadModes: { claude: 'monitor' }, uploadTypes: { claude: ['.PDF'] }, fileContentModes: { claude: 'block' } },
    { token: applicants[0].token, expectReview: true, expect: 202 });
    const claudeReview = (await admin('policy-reviews')).entries.find(({ id }) => id === claudeDraft.reviewId);
    const draftPolicy = claudeReview.snapshots.candidate;
    assert.deepEqual([draftPolicy.uploadModes.claude, draftPolicy.uploadTypes.claude, draftPolicy.fileContentModes.claude],
      ['monitor', ['.pdf'], 'block']);
    assert.equal((await admin(groupPath))[0].version, approved.version);
    const claudeApproved = await post(`policy-reviews/${claudeDraft.reviewId}/decision`, { approve: true }, { token: applicants[1].token });
    assert.deepEqual(claudeApproved.fileContentModes, { ...approved.fileContentModes, claude: 'block' });
    await post('policy-reviews/setting', { required: false }, { expect: 204 });
    const cleared = await post(groupPath, { uploadModes: { claude: 'off' }, uploadTypes: { claude: [] },
      fileContentModes: { claude: 'off' }, expectedVersion: claudeApproved.version });
    assert.deepEqual(cleared.fileContentModes, approved.fileContentModes);
    assert.deepEqual((await admin(groupPath))[0], cleared);
    assert.deepEqual((await post(`policies/${block.version}/restore`)).fileContentModes, block.fileContentModes);
    assert.deepEqual((await post(`policies/${initial.version}/restore`)).fileContentModes, initial.fileContentModes);
  });

  await t.test('keeps recorded rollout groups through migration, reassignment, retries, and retention', async () => {
    const admin = (path, options = {}) => call(`/v1/admin/${path}`, { token: rolloutHistoryAdmin, ...options });
    const post = (path, body, expect = 200) => admin(path, { method: 'POST', body, expect });
    const enroll = async () => {
      const { grant } = await post('enrollment-grants', {});
      const browser = await call('/v1/enroll', { method: 'POST', body: { grant } });
      return [browser, await current(browser)];
    };
    const current = (browser) => call('/v1/browser/policy', { token: browser.token, assignmentAware: true });
    const assign = (browser, groupId) => post(`installations/${browser.installationId}/policy-group`, { groupId }, 204);
    const submit = async (browser, policy, fields = {}, expect = 204) => {
      const body = { ...event, eventId: randomUUID(), timestamp: new Date().toISOString(), appId: 'chatgpt',
        decision: policy.mode, policyVersion: policy.version, assignmentVersion: policy.assignmentVersion, ...fields };
      await call('/v1/browser/events', { method: 'POST', token: browser.token, body, expect });
      return body;
    };
    const exportEvents = async (rolloutGroup, options) => (await admin(
      `events/export?${new URLSearchParams(rolloutGroup ? { rolloutGroup } : {})}`, options)).entries;
    const groupRollout = ({ id, name }) => ({ kind: 'group', groupId: id, groupName: name });
    const baseline = { kind: 'baseline' };
    const unattributed = { kind: 'unattributed' };
    const [alpha, beta, scoped] = await Promise.all(['History Alpha', 'History Beta', 'History Scoped'].map(
      (name) => post('policy-groups', { name })));
    await post(`policy-groups/${scoped.id}/policies`, { mode: 'block' });
    const [[neverMoved, original], [moving, early], [legacy, legacyPolicy]] = await Promise.all([enroll(), enroll(), enroll()]);
    const untouched = await submit(neverMoved, original);
    const originalEvent = await submit(moving, early);
    await assign(moving, alpha.id);
    await assign(legacy, scoped.id);
    const [firstAlpha, scopedPolicy] = await Promise.all([current(moving), current(legacy)]);
    const originalAlpha = await submit(moving, firstAlpha);
    const originalScoped = await submit(legacy, scopedPolicy);
    await assign(moving, beta.id);
    const firstBeta = await current(moving);
    assert.equal(firstBeta.version, firstAlpha.version);
    assert.notEqual(firstBeta.assignmentVersion, firstAlpha.assignmentVersion);

    if (postgres) {
      await stop();
      await retentionFixture(`
        DELETE FROM schema_migrations WHERE version = 28;
        DROP INDEX events_by_recorded_rollout;
        ALTER TABLE security_events DROP COLUMN rollout_group_id, DROP COLUMN rollout_attributed;
        ALTER TABLE policy_deliveries DROP COLUMN rollout_group_id, DROP COLUMN rollout_attributed;
        DELETE FROM policy_deliveries WHERE installation_id = '${legacy.installationId}' AND assignment_version = 0;
      `);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 28'), '1');
      const migrated = new Map((await exportEvents()).map((entry) => [entry.eventId, entry.rollout]));
      assert.deepEqual(migrated.get(untouched.eventId), baseline);
      assert.deepEqual(migrated.get(originalScoped.eventId), groupRollout(scoped));
      assert.deepEqual(migrated.get(originalEvent.eventId), unattributed);
      assert.deepEqual(migrated.get(originalAlpha.eventId), unattributed);
    }
    const lateOriginal = await submit(moving, early);
    const lateAlpha = await submit(moving, firstAlpha);
    const missingProof = await submit(legacy, legacyPolicy);
    const knownBeta = await submit(moving, firstBeta);
    await assign(moving, null);
    const reset = await current(moving);
    await assign(moving, alpha.id);
    const active = await current(moving);
    await assign(moving, alpha.id);
    assert.equal((await current(moving)).assignmentVersion, active.assignmentVersion);
    assert.equal(active.version, reset.version);
    const movedBaseline = await submit(moving, reset);
    await submit(moving, active, { eventId: movedBaseline.eventId });
    await submit(moving, active, { assignmentVersion: active.assignmentVersion + 1 }, 400);
    await submit(moving, active, { prompt: 'synthetic-private-group-sample' }, 400);
    const expired = await submit(moving, active, { timestamp: new Date(Date.now() - 3 * 86_400_000).toISOString() });
    const ids = Array.from({ length: 104 }, () => randomUUID());
    for (let index = 0; index < ids.length; index += 10) {
      await Promise.all(ids.slice(index, index + 10).map((eventId) => submit(moving, active, { eventId })));
    }
    await assign(moving, beta.id);
    const lateActive = await submit(moving, active);
    const foreign = await admin('policy-groups', { method: 'POST', body: { name: 'History Alpha' }, token: second });
    const auditor = await post('access', { name: 'Rollout history auditor', role: 'auditor', hours: 1 });
    const recorded = new Map((await exportEvents()).map((entry) => [entry.eventId, entry.rollout]));
    assert.deepEqual(recorded.get(lateOriginal.eventId), baseline);
    assert.deepEqual(recorded.get(lateAlpha.eventId), postgres ? unattributed : groupRollout(alpha));
    assert.deepEqual(recorded.get(missingProof.eventId), postgres ? unattributed : baseline);
    assert.deepEqual(recorded.get(knownBeta.eventId), groupRollout(beta));
    assert.deepEqual(recorded.get(movedBaseline.eventId), baseline);
    assert.deepEqual(recorded.get(lateActive.eventId), groupRollout(alpha));

    const query = new URLSearchParams({ rolloutGroup: alpha.id.toUpperCase(), appId: 'chatgpt', installationId: moving.installationId });
    const page = await admin(`events/history?${query}`);
    assert.equal(page.entries.length, 100);
    const cursor = new URLSearchParams(query);
    cursor.set('beforeAt', page.next.receivedAt);
    cursor.set('beforeEventId', page.next.eventId);
    cursor.set('beforeInstallationId', page.next.installationId);
    const older = await admin(`events/history?${cursor}`);
    assert.equal(older.next, null);
    const exported = (await admin(`events/export?${query}`)).entries;
    assert.deepEqual([...page.entries, ...older.entries], exported);
    assert.ok(exported.every((entry) => entry.rollout.groupId === alpha.id));
    const expected = [...ids, expired.eventId, lateActive.eventId, ...(postgres ? [] : [originalAlpha.eventId, lateAlpha.eventId])];
    assert.deepEqual(exported.map(({ eventId }) => eventId).sort(), expected.sort());
    assert.deepEqual((await admin(`events?rolloutGroup=${alpha.id}`)), page.entries);
    assert.deepEqual(await exportEvents(alpha.id, { token: auditor.token }), exported);
    assert.deepEqual(await exportEvents(alpha.id, { token: second }), []);
    assert.deepEqual(await exportEvents(foreign.id), []);
    await admin(`events/export?rolloutGroup=${alpha.id}`, { token: moving.token, expect: 401 });

    for (const key of ['rolloutGroup=invalid', 'rolloutGroup=00000000-0000-0000-0000-000000000000',
      'rolloutGroup=baseline&RolloutGroup=unattributed', 'rolloutGroup=%20baseline', 'rolloutGroup=%27%20OR%20true']) {
      for (const path of ['events', 'events/history', 'events/export', 'reports/ai-enforcement']) {
        await admin(`${path}?${key}`, { expect: 400 });
      }
    }
    await delay(5);
    const anchor = Date.now();
    const report = (filter, options) => admin(`reports/ai-enforcement?days=7&appId=chatgpt&asOf=${anchor}&rolloutGroup=${filter}`, options);
    const selected = await report(alpha.id);
    assert.equal(selected.rolloutGroup, alpha.id);
    assert.equal(selected.counts.monitor, exported.length);
    assert.equal(selected.daily.reduce((total, day) => total + day.counts.monitor, 0), exported.length);
    assert.deepEqual(await report(alpha.id, { token: auditor.token }), selected);
    assert.equal((await report(foreign.id)).counts.monitor, 0);
    assert.equal((await report(alpha.id, { token: second })).counts.monitor, 0);
    assert.equal((await report('baseline')).counts.monitor, (await exportEvents('baseline')).length);
    assert.equal((await report('unattributed')).counts.monitor, (await exportEvents('unattributed')).length);
    const printable = JSON.stringify(selected);
    for (const secret of [moving.installationId, moving.token, ids[0], auditor.token, 'synthetic-private-group-sample']) {
      assert.ok(!printable.includes(secret));
    }

    await post(`installations/${moving.installationId}/revoke`, {}, 204);
    await submit(moving, active, {}, 401);
    assert.deepEqual(await report(alpha.id), selected);
    const retention = { securityEventDays: 1, aiObservationDays: null, auditDays: null };
    await post('retention', retention, 204);
    assert.equal((await report(alpha.id)).counts.monitor, exported.length - 1);
    assert.ok(!(await exportEvents(alpha.id)).some(({ eventId }) => eventId === expired.eventId));
    assert.equal((await post('retention/cleanup', {})).securityEvents, 1);
    if (postgres) {
      await assert.rejects(() => retentionFixture(`UPDATE security_events SET rollout_group_id = '${foreign.id}',
        rollout_attributed = true WHERE event_id = '${knownBeta.eventId}'`), /violates foreign key constraint/);
      assert.deepEqual((await exportEvents(beta.id))[0].rollout, groupRollout(beta));
    }
  });

  await t.test('versions Chrome deployment rules with tenant isolation, rollback, and audited review', async () => {
    const admin = (path, options = {}) => call(`/v1/admin/${path}`, { token: deploymentAdmin, ...options });
    const post = (path, body, options = {}) => admin(path, { method: 'POST', body, ...options });
    const [initial] = await admin('policies');
    const empty = { unlisted: 'preserve', rules: [] };
    assert.deepEqual(initial.extensionDeployment, empty);
    if (postgres) {
      await stop();
      await retentionFixture(`DELETE FROM schema_migrations WHERE version = 29;
        ALTER TABLE policy_versions DROP COLUMN extension_deployment;`);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 29'), '1');
      assert.deepEqual((await admin('policies'))[0], initial);
    }
    const a = 'a'.repeat(32);
    const b = 'b'.repeat(32);
    const c = 'c'.repeat(32);
    const url = 'https://updates.fixture.test:8443/channel/update.xml';
    const rules = [{ id: a, mode: 'allow' }, { id: b, mode: 'block' }, { id: c, mode: 'force', updateUrl: url }];
    const deployment = { unlisted: 'preserve', rules };
    for (const invalid of [
      {}, { unlisted: 'other', rules }, { unlisted: 'block', rules: null },
      { unlisted: 'block', rules: [null] }, { unlisted: 'block', rules: [rules[0], rules[0]] },
      { unlisted: 'block', rules: [{ id: '*', mode: 'block' }] },
      { unlisted: 'block', rules: [{ id: a, mode: 'removed' }] },
      { unlisted: 'block', rules: [{ id: a, mode: 'allow', updateUrl: url }] },
      ...['http://updates.fixture.test/x', 'https://user@updates.fixture.test/x', 'https:///updates.fixture.test/x',
        'https://updates.fixture.test/x?', 'https://updates.fixture.test/x#', 'https://updates.fixture.test/with space',
        'https://updates.fixture.test\\x', null].map((updateUrl) =>
        ({ unlisted: 'preserve', rules: [{ id: a, mode: 'force', updateUrl }] })),
    ]) await post('policies', { extensionDeployment: invalid, expectedVersion: initial.version }, { expect: 400 });
    await post('policies', { extensionDeployment: deployment }, { expect: 400 });
    const published = await post('policies', { extensionDeployment: { ...deployment, rules: [
      { ...rules[2], updateUrl: ` ${url} ` }, rules[0], rules[1],
    ] }, expectedVersion: initial.version });
    assert.deepEqual(published.extensionDeployment, deployment);
    await post('policies', { extensionDeployment: empty, expectedVersion: initial.version }, { expect: 409 });
    assert.deepEqual((await admin('policies', { token: second }))[0].extensionDeployment, empty);

    const group = await post('policy-groups', { name: 'Deployment canary' });
    const groupPolicies = `policy-groups/${group.id}/policies`;
    await post(groupPolicies, { extensionDeployment: deployment, expectedVersion: published.version }, { token: rolloutHistoryAdmin, expect: 409 });
    const inherited = await post(groupPolicies, { mode: 'warn', expectedVersion: published.version });
    assert.deepEqual(inherited.extensionDeployment, deployment);
    const separate = { unlisted: 'block', rules: [rules[0], rules[2]] };
    const reviewer = await post('access', { name: 'Deployment reviewer', role: 'administrator', hours: 1 });
    const proposer = await post('access', { name: 'Deployment proposer', role: 'administrator', hours: 1 });
    const auditor = await post('access', { name: 'Deployment auditor', role: 'auditor', hours: 1 });
    const foreignReviewer = await post('access', { name: 'Foreign deployment reviewer', role: 'administrator', hours: 1 }, { token: rolloutHistoryAdmin });
    assert.deepEqual((await admin(groupPolicies, { token: auditor.token }))[0].extensionDeployment, deployment);
    await post(groupPolicies, { extensionDeployment: separate, expectedVersion: inherited.version }, { token: auditor.token, expect: 403 });
    await post('policy-reviews/setting', { required: true }, { expect: 204 });
    const { reviewId } = await post(groupPolicies, { extensionDeployment: separate, expectedVersion: inherited.version },
      { token: proposer.token, expectReview: true, expect: 202 });
    const reviewed = (await admin('policy-reviews')).entries.find(({ id }) => id === reviewId);
    assert.deepEqual(reviewed.snapshots.before.extensionDeployment, deployment);
    assert.deepEqual(reviewed.snapshots.candidate.extensionDeployment, separate);
    assert.deepEqual((await admin(groupPolicies))[0].extensionDeployment, deployment);
    await post(`policy-reviews/${reviewId}/decision`, { approve: true }, { token: proposer.token, expect: 403 });
    await post('policy-reviews/setting', { required: true }, { token: rolloutHistoryAdmin, expect: 204 });
    await post(`policy-reviews/${reviewId}/decision`, { approve: true }, { token: foreignReviewer.token, expect: 404 });
    const approved = await post(`policy-reviews/${reviewId}/decision`, { approve: true }, { token: reviewer.token });
    assert.deepEqual(approved.extensionDeployment, separate);
    assert.deepEqual((await admin('policies'))[0].extensionDeployment, deployment);
    await post('policy-reviews/setting', { required: false }, { expect: 204 });
    const promoted = await post(`policy-groups/${group.id}/promote`, { expectedVersion: approved.version });
    assert.deepEqual(promoted.extensionDeployment, separate);
    const unrelated = await post('policies', { mode: 'block' });
    assert.deepEqual(unrelated.extensionDeployment, separate);
    const restored = await post(`policies/${initial.version}/restore`, undefined);
    assert.deepEqual(restored.extensionDeployment, empty);
    assert.deepEqual((await admin(groupPolicies))[0].extensionDeployment, separate);

    const { grant } = await post('enrollment-grants', {});
    const browser = await call('/v1/enroll', { method: 'POST', body: { grant } });
    await call('/v1/browser/policy', { token: browser.token, assignmentAware: true });
    await post(`installations/${browser.installationId}/policy-group`, { groupId: group.id }, { expect: 204 });
    const applied = await call('/v1/browser/policy', { token: browser.token, assignmentAware: true });
    assert.equal(applied.version, approved.version);
    assert.equal(Object.hasOwn(applied, 'extensionDeployment'), false);
    assert.doesNotMatch(JSON.stringify(applied), /updates\.fixture\.test/);
    const audit = (await admin('audit?action=policy_published')).entries.find(({ policyVersion }) => policyVersion === approved.version);
    assert.equal(audit.actorAccess.id, reviewer.access.id);
  });

  await t.test('versions cataloged AI app access and acknowledges only a delivered browser policy', async () => {
    const admin = (path, options = {}) => call(`/v1/admin/${path}`, { token: aiAppAccessAdmin, ...options });
    const post = (path, body, options = {}) => admin(path, { method: 'POST', body, ...options });
    const [initial] = await admin('policies');
    assert.deepEqual(initial.blockedAiAppHosts, []);
    if (postgres) {
      await stop();
      await retentionFixture(`DELETE FROM schema_migrations WHERE version = 30;
        ALTER TABLE policy_versions DROP COLUMN blocked_ai_app_hosts;
        ALTER TABLE policy_deliveries DROP COLUMN ai_app_access;`);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 30'), '1');
      assert.deepEqual((await admin('policies'))[0], initial);
    }
    const host = 'chat.application.test';
    const catalog = [{ host, name: 'Application fixture' }];
    for (const blockedAiAppHosts of [[null], ['.chatgpt.com'], ['https://chatgpt.com/'], ['chatgpt.com:443'], ['*.ai'],
      ['chatgpt.com', 'ChatGPT.COM.'], [host], ['unlisted.application.test']]) {
      await post('policies', { blockedAiAppHosts }, { expect: 400 });
    }
    const tooMany = Array.from({ length: 50 }, (_, index) => `app-${index}.fixture.test`);
    await post('policies', { blockedAiAppHosts: ['chatgpt.com'], domainRules: { allow: tooMany, block: [] } }, { expect: 400 });
    const baseline = await post('policies', { customApps: catalog, blockedAiAppHosts: ['COPILOT.COM.', ' ChatGPT.com ', host],
      pathRules: { allow: [`${host}/allowed`], block: [] }, discoveryEnabled: false });
    assert.deepEqual(baseline.blockedAiAppHosts, [host, 'chatgpt.com', 'copilot.com']);
    await post('policies', { customApps: [] }, { expect: 400 });
    await post('policies', { expectedVersion: initial.version, blockedAiAppHosts: [] }, { expect: 409 });
    assert.deepEqual((await admin('policies', { token: deploymentAdmin }))[0].blockedAiAppHosts, []);

    async function enroll() {
      const { grant } = await post('enrollment-grants', {});
      return call('/v1/enroll', { method: 'POST', body: { grant } });
    }
    const [fresh, secondBrowser] = await Promise.all([enroll(), enroll()]);
    const policy = (browser, aiAppAccessAware) => call('/v1/browser/policy', {
      token: browser.token, assignmentAware: true, aiAppAccessAware,
    });
    const heartbeat = (browser, current, aiAppAccessApplied, expect = 204) => call('/v1/browser/heartbeat', {
      method: 'POST', token: browser.token, expect,
      body: { policyVersion: current.version, assignmentVersion: current.assignmentVersion, pathRulesApplied: true, aiAppAccessApplied },
    });
    const seen = async (browser) => (await admin('installations')).find(({ installationId }) =>
      installationId === browser.installationId).appliedPolicyVersion;
    const legacy = await policy(fresh, false);
    assert.equal(legacy.version, baseline.version);
    assert.equal(Object.hasOwn(legacy, 'blockedAiAppHosts'), false);
    await heartbeat(fresh, legacy);
    assert.equal(await seen(fresh), null);
    await heartbeat(fresh, legacy, true, 400);
    const delivered = await policy(fresh, true);
    assert.deepEqual(delivered.blockedAiAppHosts, baseline.blockedAiAppHosts);
    await heartbeat(fresh, delivered, true);
    assert.equal(await seen(fresh), delivered.version);
    await heartbeat(secondBrowser, delivered, true, 400);
    await heartbeat(fresh, legacy);
    assert.equal(await seen(fresh), null);
    await heartbeat(fresh, delivered, true);

    const group = await post('policy-groups', { name: 'AI access canary' });
    const groupPath = `policy-groups/${group.id}`;
    const groupPolicy = await post(`${groupPath}/policies`, { blockedAiAppHosts: ['www.perplexity.ai'] });
    assert.deepEqual(groupPolicy.blockedAiAppHosts, ['www.perplexity.ai']);
    assert.deepEqual(groupPolicy.customApps, baseline.customApps);
    await post(`installations/${fresh.installationId}/policy-group`, { groupId: group.id }, { expect: 204 });
    const grouped = await policy(fresh, true);
    assert.equal(grouped.version, groupPolicy.version);
    assert.deepEqual(grouped.blockedAiAppHosts, groupPolicy.blockedAiAppHosts);
    await heartbeat(fresh, delivered, true, 400);
    await heartbeat(fresh, grouped, true);
    assert.equal(await seen(fresh), grouped.version);
    assert.deepEqual((await policy(secondBrowser, true)).blockedAiAppHosts, baseline.blockedAiAppHosts);
    const promoted = await post(`${groupPath}/promote`, { expectedVersion: groupPolicy.version });
    assert.deepEqual(promoted.blockedAiAppHosts, groupPolicy.blockedAiAppHosts);
    const restored = await post(`policies/${initial.version}/restore`, undefined);
    assert.deepEqual(restored.blockedAiAppHosts, []);
    assert.deepEqual((await policy(secondBrowser, true)).blockedAiAppHosts, []);
    await post(`installations/${fresh.installationId}/revoke`, {}, { expect: 204 });
    await heartbeat(fresh, grouped, true, 401);
  });

  await t.test('triages retained events with isolated assignees, atomic revisions, and audit history', async (triage) => {
    const admin = (path, options = {}) => call(`/v1/admin/${path}`, { token: eventTriageAdmin, ...options });
    const post = (path, body, options) => admin(path, { method: 'POST', body, ...options });
    const issue = (name, role = 'administrator', token = eventTriageAdmin) => post('access', { name, role, hours: 1 }, { token });
    const enroll = async () => {
      const { grant } = await post('enrollment-grants');
      return call('/v1/enroll', { method: 'POST', body: { grant } });
    };
    const eventId = randomUUID();
    const payload = { ...contract.event, eventId, timestamp: new Date().toISOString() };
    const [one, two] = await Promise.all([enroll(), enroll()]);
    const record = (browser, body = payload) =>
      call('/v1/browser/events', { method: 'POST', token: browser.token, body, expect: 204 });
    await Promise.all([record(one), record(two)]);
    const path = (browser, id = eventId) => `events/${browser.installationId}/${id}`;
    const review = path(one);
    const entries = (query, options) => admin(`events/history?${query}`, options).then((result) => result.entries);
    const activity = () => admin('audit?action=event_triage_changed').then((result) => result.entries);
    const initial = await admin(review);
    assert.equal(initial.event.eventId, eventId);
    assert.equal(initial.event.triage, undefined);
    assert.deepEqual(initial.activity, []);

    await triage.test('migrates an existing event from schema 30 and exposes it as unassigned and needing review', async () => {
      if (postgres) {
        await stop();
        await retentionFixture(`
          ${undoIncidentSchema}
          DELETE FROM schema_migrations WHERE version = 31;
          DROP TABLE event_triage;
          ALTER TABLE control_audit DROP COLUMN event_triage_change;
        `);
        await start();
        assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 31'), '1');
      }
      assert.deepEqual(await admin(review), initial);
      const list = await entries('triageStatus=needs_review&triageAssignee=unassigned');
      assert.deepEqual(list.map(({ installationId }) => installationId).sort(), [one.installationId, two.installationId].sort());
      assert.deepEqual(await entries('triageStatus=resolved'), []);
      assert.deepEqual(await entries('triageStatus=investigating'), []);
      const headers = { Authorization: `Bearer ${eventTriageAdmin}` };
      for (const route of ['history', 'export']) {
        const response = await fetch(`${baseUrl}/v1/admin/events/${route}?triageStatus=needs_review`, { headers });
        assert.equal(response.headers.get('X-Zekvar-Event-Triage'), '1');
        assert.equal((await response.json()).entries.length, 2);
        for (const invalid of ['triageStatus=complete', 'triageStatus=resolved&triageStatus=needs_review',
          'triageAssignee=other', 'triageAssignee=unassigned&triageAssignee=unassigned',
          'triageAssignee=00000000-0000-0000-0000-000000000000']) {
          await admin(`events/${route}?${invalid}`, { expect: 400 });
        }
      }
    });

    const [operator, alternate, auditor, foreign] = await Promise.all([
      issue('Triage operator'), issue('Triage backup'), issue('Triage auditor', 'auditor'), issue('Outside organization', 'administrator', second),
    ]);
    const investigating = { expectedRevision: 0, status: 'investigating', disposition: null, assigneeId: operator.access.id };
    const change = (body, options) => post(`${review}/triage`, body, options);
    await triage.test('enforces permissions, rejects extra data, and serializes overlapping and repeated saves', async () => {
      const roster = await admin('events/triage-assignees', { token: auditor.token });
      assert.deepEqual(roster.map(({ id }) => id), [alternate.access.id, operator.access.id]);
      await admin(review, { token: one.token, expect: 401 });
      await admin('events/triage-assignees', { token: one.token, expect: 401 });
      await admin(review, { token: second, expect: 404 });
      await admin(path(two, randomUUID()), { expect: 404 });
      await change(investigating, { token: second, expect: 404 });
      await change(investigating, { token: auditor.token, expect: 403 });
      assert.deepEqual(await admin(review, { token: auditor.token }), initial);
      for (const parameters of [{ expectedRevision: null }, { expectedRevision: -1 }, { status: null },
        { status: 'resolved' }, { disposition: 'false_positive' }, { note: 'SYNTHETIC_PROMPT_VALUE' }]) {
        await change({ ...investigating, ...parameters }, { expect: 400 });
      }
      for (const assigneeId of [foreign.access.id, auditor.access.id, randomUUID()]) {
        assert.deepEqual(await change({ ...investigating, assigneeId }, { expect: 400 }), { code: 'event_assignee_unavailable' });
      }
      assert.deepEqual(await activity(), []);
      const requests = [
        { body: investigating, token: operator.token },
        { body: { ...investigating, status: 'resolved', disposition: 'false_positive', assigneeId: alternate.access.id }, token: alternate.token },
      ];
      const responses = await Promise.all(requests.map(({ token, body }) => fetch(`${baseUrl}/v1/admin/${review}/triage`, {
        method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify(body),
        signal: AbortSignal.timeout(5000),
      })));
      const outcomes = await Promise.all(responses.map((response) => response.json()));
      assert.deepEqual(responses.map(({ status }) => status).sort(), [200, 409], JSON.stringify(outcomes));
      const winner = responses.findIndex(({ ok }) => ok);
      const saved = outcomes[winner];
      assert.deepEqual(outcomes[1 - winner], { code: 'event_triage_stale' });
      assert.equal(saved.revision, 1);
      assert.equal(saved.assignee.id, requests[winner].body.assigneeId);
      assert.deepEqual(await change(requests[winner].body), saved);
      assert.deepEqual(await change({ ...requests[winner].body, expectedRevision: 1 }), saved);
      assert.deepEqual((await admin(review)).event.triage, saved);
      const [entry] = await activity();
      assert.equal((await activity()).length, 1);
      assert.equal(entry.actorAccess.id, saved.assignee.id);
      assert.deepEqual(entry.eventTriageChange, {
        installationId: one.installationId, eventId, revision: 1,
        before: { status: 'needs_review', disposition: null, assigneeId: null },
        after: { status: saved.status, disposition: saved.disposition, assigneeId: saved.assignee.id },
      });
      assert.deepEqual((await admin(review)).activity[0].change, entry.eventTriageChange);
      assert.equal((await admin(path(two))).event.triage, undefined);
      await record(one);
      assert.equal((await entries(`triageAssignee=${saved.assignee.id}`)).length, 1);
      assert.deepEqual(await entries(`triageAssignee=${foreign.access.id}`), []);
      const filtered = `triageAssignee=${saved.assignee.id}&triageStatus=${saved.status}&appId=${payload.appId}`;
      assert.deepEqual((await admin(`events/export?${filtered}`)).entries, await entries(filtered));
    });

    await triage.test('retains inactive assignments and cleans expired events independently of their audit evidence', async () => {
      const current = (await admin(review)).event.triage;
      const inactive = current.assignee.id;
      const backup = [operator, alternate].find(({ access }) => access.id !== inactive);
      await post(`access/${inactive}/revoke`, undefined, { expect: 204 });
      assert.equal((await admin(review)).event.triage.assignee.active, false);
      assert.ok(!(await admin('events/triage-assignees')).some(({ id }) => id === inactive));
      const staleOwner = { expectedRevision: 0, status: 'investigating', disposition: null, assigneeId: inactive };
      await post(`${path(two)}/triage`, staleOwner, { expect: 400 });
      const reopened = await change({ ...staleOwner, expectedRevision: 1, status: 'needs_review' }, { token: backup.token });
      assert.equal(reopened.revision, 2);
      assert.equal(reopened.assignee.active, false);
      const resolved = await change({ ...staleOwner, expectedRevision: 2, status: 'resolved', disposition: 'expected_activity', assigneeId: null });
      assert.equal(resolved.assignee, null);
      assert.equal(resolved.revision, 3);
      assert.equal((await entries('triageStatus=resolved&triageAssignee=unassigned')).length, 1);
      assert.equal((await entries('triageStatus=needs_review&triageAssignee=unassigned')).length, 1);
      assert.deepEqual((await admin(review)).activity.map(({ change }) => change.revision), [3, 2, 1]);
      assert.deepEqual(await admin('audit?action=event_triage_changed', { token: second }), { entries: [], next: null });
      assert.doesNotMatch(JSON.stringify(await activity()), /SYNTHETIC_PROMPT_VALUE|tokenHash|rawText/);
      if (!postgres) return;

      await retentionFixture(`
        UPDATE control_audit SET occurred_at = now() - interval '3 days'
        WHERE action = 'event_triage_changed' AND event_triage_change->>'eventId' = '${eventId}' AND event_triage_change->>'revision' = '1';
      `);
      await post('retention', { securityEventDays: 1, aiObservationDays: null, auditDays: 1 }, { expect: 204 });
      assert.deepEqual((await admin(review)).activity.map(({ change }) => change.revision), [3, 2]);
      assert.equal((await admin(review)).event.triage.revision, 3);
      await retentionFixture(`UPDATE security_events SET occurred_at = now() - interval '3 days'
        WHERE installation_id = '${one.installationId}' AND event_id = '${eventId}';`);
      assert.deepEqual(await entries('triageStatus=resolved'), []);
      assert.deepEqual((await admin('events/export?triageStatus=resolved')).entries, []);
      await admin(review, { expect: 404 });
      await change({ ...investigating, expectedRevision: 3 }, { expect: 404 });
      assert.equal(await retentionFixture(`SELECT count(*) FROM event_triage WHERE event_id = '${eventId}'`), '1');
      const removed = await post('retention/cleanup');
      assert.deepEqual([removed.securityEvents, removed.auditEntries], [1, 1]);
      assert.equal(await retentionFixture(`SELECT count(*) FROM event_triage WHERE event_id = '${eventId}'`), '0');
      assert.deepEqual((await activity()).map(({ eventTriageChange }) => eventTriageChange.revision), [3, 2]);
      assert.equal((await admin(path(two))).event.eventId, eventId);
    });
  });

  await t.test('versions organization identifiers and requires capability for prompt, exception, and attachment evidence', async () => {
    const admin = (path, options = {}) => call(`/v1/admin/${path}`, { token: identifiersAdmin, ...options });
    const post = (path, body, options) => admin(path, { method: 'POST', body, ...options });
    const [initial] = await admin('policies');
    const empty = { mode: 'off', formats: [] };
    assert.deepEqual(initial.identifierProtection, empty);
    if (postgres) {
      await stop();
      await retentionFixture(undoIdentifierSchema);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 33'), '1');
      assert.deepEqual((await admin('policies'))[0], initial);
    }
    const proposed = { mode: 'block', formats: [{ prefix: '  cust- ', digits: 8 }, { prefix: 'CASE_', digits: 6 }] };
    const canonical = { mode: 'block', formats: [{ prefix: 'CASE_', digits: 6 }, { prefix: 'CUST-', digits: 8 }] };
    for (const identifierProtection of [
      { mode: 'on', formats: [] }, { mode: 'block', formats: [] }, { mode: 'off', formats: [null] }, { mode: 'block' },
      { ...proposed, formats: [{ prefix: 'CASE.*-', digits: 8 }] }, { ...proposed, formats: [{ prefix: '客户-', digits: 8 }] },
      { ...proposed, formats: [{ prefix: 'CASE-', digits: 3 }] }, { ...proposed, formats: [{ prefix: 'CASE-', digits: 13 }] },
      { ...proposed, formats: [{ prefix: 'CASE-', digits: 4 }, { prefix: 'case-', digits: 6 }] },
      { ...proposed, formats: [{ prefix: 'CASE-', digits: 4, value: 'CASE-1234' }] },
      { ...proposed, formats: Array.from({ length: 17 }, (_, i) => ({ prefix: `SYN${i}-`, digits: 6 })) },
    ]) await post('policies', { identifierProtection }, { expect: 400 });
    assert.deepEqual((await admin('policies'))[0], initial);
    const expiry = new Date(Date.now() + 10 * 60_000).toISOString();
    const grantSetting = { appId: 'chatgpt', ruleId: 'organization-identifier', expiresAt: expiry, reason: 'Synthetic workflow review' };
    const active = await post('policies', { expectedVersion: initial.version, identifierProtection: proposed,
      fileContentModes: { chatgpt: 'monitor', gemini: 'block' }, promptExceptions: [grantSetting] });
    assert.deepEqual(active.identifierProtection, canonical);
    assert.deepEqual((await admin('policies', { token: second }))[0].identifierProtection, empty);
    await post('policies', { expectedVersion: initial.version, identifierProtection: empty }, { expect: 409 });
    async function enroll() {
      const { grant } = await post('enrollment-grants');
      return call('/v1/enroll', { method: 'POST', body: { grant } });
    }
    const [one, two] = await Promise.all([enroll(), enroll()]);
    const browser = (client, path, options = {}) => call(`/v1/browser/${path}`, { token: client.token, assignmentAware: true, ...options });
    const fetchPolicy = (client, identifiersAware) => browser(client, 'policy', { identifiersAware, fileInspectionAware: true, fileBlockAware: true });
    const old = await fetchPolicy(one, false);
    assert.equal(old.identifierProtection, undefined);
    assert.equal(old.promptExceptionLease, undefined);
    const ack = (client, enabled, expect = 204) => browser(client, 'heartbeat', { method: 'POST', expect,
      body: { policyVersion: active.version, identifiersApplied: enabled, promptExceptionsApplied: enabled,
        fileInspectionApplied: true, fileContentBlockApplied: true } });
    const applied = async (client) => (await admin('installations')).find(({ installationId }) => installationId === client.installationId).appliedPolicyVersion;
    await ack(one, false);
    assert.equal(await applied(one), null);
    await ack(one, true, 400);
    const attempt = { ...event, timestamp: new Date().toISOString(), appId: 'chatgpt', policyVersion: active.version,
      ruleId: 'organization-identifier', detectorCategory: 'internal-identifier', decision: 'block' };
    const send = (fields = {}, expect = 204, client = one) => browser(client, 'events', {
      method: 'POST', expect, body: { ...attempt, eventId: randomUUID(), ...fields },
    });
    await send({}, 400);
    const capable = await fetchPolicy(one, true);
    assert.deepEqual(capable.identifierProtection, canonical);
    assert.equal(capable.promptExceptionLease.grants[0].ruleId, grantSetting.ruleId);
    await ack(one, true);
    await ack(two, true, 400);
    assert.equal(await applied(one), active.version);
    await send({}, 400, two);
    for (const invalid of [
      { decision: 'warn' }, { decision: 'warn_override' }, { detectorCategory: 'synthetic-secret' }, { decision: 'block', uploadMethod: 'picker' },
      { decision: 'exception_applied', appId: 'gemini' }, { rawText: 'CUST-73498765' }, { prefix: 'CUST-' },
    ]) await send(invalid, 400);
    const stable = randomUUID();
    await Promise.all([send({ eventId: stable }), send({ eventId: stable })]);
    await send({ decision: 'exception_applied' });
    await send({ decision: 'monitor', uploadMethod: 'drop' });
    await send({ appId: 'gemini', uploadMethod: 'picker' });
    const exported = (await admin('events/export')).entries;
    assert.equal(exported.length, 4);
    assert.deepEqual(exported.map(({ decision }) => decision).sort(), ['block', 'block', 'exception_applied', 'monitor']);
    assert.doesNotMatch(JSON.stringify(exported), /CUST-|CASE_|rawText|73498765/);
    assert.deepEqual((await admin('events/export', { token: second })).entries.filter(({ ruleId }) => ruleId === grantSetting.ruleId), []);
    const rule = (await admin('reports/ai-enforcement')).byRule.find(({ id }) => id === grantSetting.ruleId);
    assert.equal(rule.counts.block, 2);
    assert.equal(rule.counts.monitor, 1);

    const [{ token: author }, { token: reviewer }] = await Promise.all(['Identifier author', 'Identifier reviewer'].map((name) =>
      post('access', { name, role: 'administrator', hours: 1 })));
    const group = await post('policy-groups', { name: 'Identifier canary' });
    const groupPath = `policy-groups/${group.id}`;
    await post('policy-reviews/setting', { required: true }, { expect: 204 });
    const candidate = { mode: 'warn', formats: [{ prefix: 'LAB-', digits: 4 }] };
    const pending = await post(`${groupPath}/policies`, { expectedVersion: active.version, identifierProtection: candidate },
      { token: author, expectReview: true, expect: 202 });
    const review = (await admin('policy-reviews')).entries.find(({ id }) => id === pending.reviewId);
    assert.deepEqual(review.snapshots.before.identifierProtection, canonical);
    assert.deepEqual(review.snapshots.candidate.identifierProtection, candidate);
    await post(`policy-reviews/${pending.reviewId}/decision`, { approve: true }, { token: author, expect: 403 });
    const approved = await post(`policy-reviews/${pending.reviewId}/decision`, { approve: true }, { token: reviewer });
    assert.deepEqual(approved.identifierProtection, candidate);
    assert.deepEqual((await admin('policies'))[0].identifierProtection, canonical);
    await post(`installations/${one.installationId}/policy-group`, { groupId: group.id }, { expect: 204 });
    const scoped = await fetchPolicy(one, true);
    assert.deepEqual(scoped.identifierProtection, candidate);
    await send({ policyVersion: scoped.version, assignmentVersion: scoped.assignmentVersion, decision: 'warn_override' });
    await post('policy-reviews/setting', { required: false }, { expect: 204 });
    const promoted = await post(`${groupPath}/promote`, { expectedVersion: approved.version });
    assert.deepEqual(promoted.identifierProtection, candidate);
    const restored = await post(`policies/${initial.version}/restore`);
    assert.deepEqual(restored.identifierProtection, empty);
    assert.deepEqual((await admin('policies'))[0].identifierProtection, empty);
  });

  await t.test('enables expanded AI discovery only after an approved scoped policy and matching browser delivery', async () => {
    const admin = (path, options) => call(`/v1/admin/${path}`, { token: presetsAdmin, ...options });
    const post = (path, body, options) => admin(path, { method: 'POST', body, ...options });
    const inventory = (token) => admin('ai-apps', token ? { token } : undefined);
    const { grant } = await post('enrollment-grants');
    const browser = await call('/v1/enroll', { method: 'POST', body: { grant } });
    const policy = (presetAware = true) => call('/v1/browser/policy', { token: browser.token, assignmentAware: true, presetAware });
    const observe = (appId, version, { expect = 204, extra } = {}) => call('/v1/browser/ai-app-observations', {
      token: browser.token, method: 'POST', expect,
      body: { appId, observedAt: new Date().toISOString(), policyVersion: version.version, assignmentVersion: version.assignmentVersion, ...extra },
    });
    const initial = await post('policies', { mode: 'monitor', discoveryEnabled: true,
      customApps: [{ host: 'copilot.com', name: 'Company Copilot' }] });
    assert.equal(initial.presetDiscoveryEnabled, false);
    await observe(initial.customApps[0].id, initial);
    await observe('chatgpt', initial);
    await post('ai-apps/chatgpt/classification', { status: 'approved' }, { expect: 204 });
    const existing = await inventory();
    if (postgres) {
      await stop();
      await retentionFixture(undoPresetSchema);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 35'), '1');
      assert.deepEqual(await inventory(), existing);
    }
    await observe('copilot', await policy(), { expect: 400 });
    const group = await post('policy-groups', { name: 'AI discovery pilot' });
    await post(`installations/${browser.installationId}/policy-group`, { groupId: group.id }, { expect: 204 });
    const groupPath = `policy-groups/${group.id}`;
    const { token: author } = await post('access', { name: 'Preset author', role: 'administrator', hours: 1 });
    const { token: reviewer } = await post('access', { name: 'Preset reviewer', role: 'administrator', hours: 1 });
    const { token: auditor } = await post('access', { name: 'Preset auditor', role: 'auditor', hours: 1 });
    await post('policy-reviews/setting', { required: true }, { expect: 204 });
    const requested = await post(`${groupPath}/policies`, { expectedVersion: initial.version, presetDiscoveryEnabled: true },
      { token: author, expect: 202, expectReview: true });
    assert.equal((await policy()).presetDiscoveryEnabled, false);
    await post(`policy-reviews/${requested.reviewId}/decision`, { approve: true }, { token: author, expect: 403 });
    const approved = await post(`policy-reviews/${requested.reviewId}/decision`, { approve: true }, { token: reviewer });
    assert.equal(approved.presetDiscoveryEnabled, true);
    assert.equal((await admin('policies'))[0].presetDiscoveryEnabled, false);
    const legacy = await policy(false);
    assert.equal(legacy.presetDiscoveryEnabled, undefined);
    await observe('copilot', legacy, { expect: 400 });
    const delivered = await policy();
    assert.equal(delivered.presetDiscoveryEnabled, true);
    assert.equal(delivered.version, approved.version);
    for (const appId of ['copilot', 'perplexity', 'grok', 'meta-ai', 'deepseek']) {
      await observe(appId, delivered, { expect: 400, extra: { url: 'https://example.test/synthetic-private-path' } });
      await Promise.all([observe(appId, delivered), observe(appId, delivered)]);
    }
    await post('ai-apps/copilot/classification', { status: 'approved' }, { token: auditor, expect: 403 });
    await post('ai-apps/copilot/classification', { status: 'approved' }, { token: reviewer, expect: 204 });
    const entries = await inventory(auditor);
    const copilot = entries.find(({ appId }) => appId === 'copilot');
    assert.equal(copilot.browsersSeen, 1);
    assert.equal(copilot.name, 'Microsoft Copilot');
    assert.equal(copilot.status, 'approved');
    assert.equal(entries.find(({ appId }) => appId === initial.customApps[0].id).browsersSeen, 1);
    assert.doesNotMatch(JSON.stringify(entries), /synthetic-private-path|installationId/);
    assert.equal((await inventory(second)).find(({ appId }) => appId === 'copilot').browsersSeen, 0);
    assert.equal((await admin('audit?action=app_classified')).entries.some((entry) =>
      entry.appId === 'copilot' && entry.classification === 'approved'), true);
    await post('policy-reviews/setting', { required: false }, { expect: 204 });
    await post(`${groupPath}/policies`, { customApps: [{ host: 'grok.com', name: 'Managed Grok' }] });
    const overridden = await policy();
    await observe('grok', delivered, { expect: 400 });
    await observe('grok', overridden, { expect: 400 });
    await observe(overridden.customApps[0].id, overridden);
    const disabled = await post(`${groupPath}/policies`, { presetDiscoveryEnabled: false });
    assert.equal(disabled.discoveryEnabled, true);
    await observe('deepseek', overridden, { expect: 400 });
    await observe('chatgpt', await policy());
    await post(`installations/${browser.installationId}/policy-group`, { groupId: null }, { expect: 204 });
    await observe('copilot', delivered, { expect: 400 });
    assert.equal((await policy()).presetDiscoveryEnabled, false);
    assert.equal((await post(`${groupPath}/policies/${approved.version}/restore`)).presetDiscoveryEnabled, true);
    await post(`installations/${browser.installationId}/revoke`, {}, { expect: 204 });
    await observe('copilot', delivered, { expect: 401 });
  });

  await t.test('validates SSN enforcement, historical evidence, review, and privacy by policy version', async () => {
    const admin = (path, options) => call(`/v1/admin/${path}`, { token: ssnAdmin, ...options });
    const post = (path, body, options) => admin(path, { method: 'POST', body, ...options });
    const { grant } = await post('enrollment-grants');
    const browser = await call('/v1/enroll', { method: 'POST', body: { grant } });
    const policy = (ssnAware = true) => call('/v1/browser/policy', { token: browser.token, assignmentAware: true, ssnAware,
      fileInspectionAware: true, fileBlockAware: true });
    const confirm = (config, flags, expect = 204) => call('/v1/browser/heartbeat', { token: browser.token, method: 'POST', expect,
      body: { policyVersion: config.version, assignmentVersion: config.assignmentVersion, ...flags } });
    const ruleId = 'us-social-security-number';
    const detectorCategory = 'government-identifier';
    const signal = (config, extra) => ({ eventId: randomUUID(), appId: 'chatgpt', timestamp: new Date().toISOString(),
      policyVersion: config.version, assignmentVersion: config.assignmentVersion, decision: 'monitor', ruleId, detectorCategory, ...extra });
    const submit = (body, expect = 204) => call('/v1/browser/events', { token: browser.token, method: 'POST', body, expect });
    const [initial] = await admin('policies');
    assert.equal(initial.ssnMode, 'off');
    await submit(signal(initial), 400);
    await submit(signal(initial, { ruleId: contract.event.ruleId, detectorCategory: contract.event.detectorCategory }));
    if (postgres) {
      const before = await admin('events');
      await stop();
      await retentionFixture(undoSsnSchema);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 36'), '1');
      assert.deepEqual(await admin('events'), before);
      assert.equal((await admin('policies'))[0].ssnMode, 'off');
    }
    await post('policies', { ssnMode: 'on' }, { expect: 400 });
    const monitored = await post('policies', { ssnMode: 'monitor' });
    assert.equal((await policy(false)).ssnMode, undefined);
    await confirm(monitored, { ssnModeApplied: true }, 400);
    await confirm(monitored, {});
    assert.equal((await admin('installations'))[0].appliedPolicyVersion, null);
    await submit(signal(monitored), 400);
    assert.equal((await policy()).ssnMode, 'monitor');
    await confirm(monitored, { ssnModeApplied: true });
    assert.equal((await admin('installations'))[0].appliedPolicyVersion, monitored.version);
    const detected = signal(monitored);
    await Promise.all([submit(detected), submit(detected)]);
    await submit(signal(monitored, { decision: 'warn_override' }), 400);
    await submit(signal(monitored, { detectorCategory: 'credential' }), 400);
    await submit(signal(monitored, { prompt: 'synthetic SSN fixture' }), 400);
    const warning = await post('policies', { ssnMode: 'warn', fileContentModes: { chatgpt: 'block', gemini: 'monitor' } });
    assert.equal((await policy()).ssnMode, 'warn');
    await confirm(warning, { ssnModeApplied: true, fileInspectionApplied: true, fileContentBlockApplied: true });
    await submit(signal(warning, { decision: 'warn' }));
    await submit(signal(warning, { decision: 'warn_override' }));
    await submit(signal(warning, { decision: 'block', uploadMethod: 'picker' }));
    await submit(signal(warning, { appId: 'gemini', uploadMethod: 'drop' }));
    await submit(signal(warning, { decision: 'monitor', uploadMethod: 'picker' }), 400);
    await submit(signal(warning, { appId: 'gemini', uploadMethod: 'drop', decision: 'block' }), 400);

    const group = await post('policy-groups', { name: 'Privacy canary' });
    const path = `policy-groups/${group.id}`;
    const { token: author } = await post('access', { name: 'Privacy author', role: 'administrator', hours: 1 });
    const { token: reviewer } = await post('access', { name: 'Privacy reviewer', role: 'administrator', hours: 1 });
    await post('policy-reviews/setting', { required: true }, { expect: 204 });
    const validUntil = new Date(Date.now() + 60_000).toISOString();
    const exception = { appId: 'chatgpt', ruleId, expiresAt: validUntil, reason: 'Controlled test' };
    const proposed = await post(`${path}/policies`, { ssnMode: 'block', expectedVersion: warning.version, promptExceptions: [exception] },
      { token: author, expect: 202, expectReview: true });
    assert.equal((await policy()).ssnMode, 'warn');
    await post(`policy-reviews/${proposed.reviewId}/decision`, { approve: true }, { token: author, expect: 403 });
    const approved = await post(`policy-reviews/${proposed.reviewId}/decision`, { approve: true }, { token: reviewer });
    assert.equal(approved.ssnMode, 'block');
    await post(`installations/${browser.installationId}/policy-group`, { groupId: group.id }, { expect: 204 });
    assert.equal((await policy(false)).promptExceptionLease, undefined);
    const scoped = await policy();
    assert.equal(scoped.ssnMode, 'block');
    assert.equal(scoped.promptExceptionLease.grants[0].ruleId, ruleId);
    await confirm(scoped, { ssnModeApplied: true, fileInspectionApplied: true, fileContentBlockApplied: true, promptExceptionsApplied: true });
    await submit(signal(scoped, { decision: 'exception_applied' }));
    await submit(signal(scoped, { appId: 'gemini', decision: 'exception_applied' }), 400);
    await submit(signal(scoped, { decision: 'exception_applied', timestamp: new Date(Date.parse(validUntil) + 1000).toISOString() }), 400);
    await submit(signal(scoped, { decision: 'block', uploadMethod: 'picker' }));
    const entries = await admin('events');
    assert.equal(entries.filter(({ eventId }) => eventId === detected.eventId).length, 1);
    assert.equal(entries.find(({ eventId }) => eventId === detected.eventId).detectorCategory, detectorCategory);
    assert.doesNotMatch(JSON.stringify(entries), /synthetic SSN fixture|Controlled test/);
    assert.ok(!(await admin('events', { token: second })).some((event) => event.ruleId === ruleId));
    const report = await admin('reports/ai-enforcement?days=7');
    assert.equal(report.byRule.find(({ id }) => id === ruleId).counts.block, 2);

    await post('policy-reviews/setting', { required: false }, { expect: 204 });
    const promoted = await post(`${path}/promote`, { expectedVersion: approved.version });
    assert.equal(promoted.ssnMode, 'block');
    const restored = await post(`policies/${initial.version}/restore`);
    assert.equal(restored.ssnMode, 'off');
    assert.equal((await policy()).ssnMode, 'block');
  });

  await t.test('groups retained events into audited cases with tenant isolation and bounded, retryable membership', async () => {
    const admin = (path, options = {}) => call(`/v1/admin/${path}`, { token: casesAdmin, ...options });
    const post = (path, body, options) => admin(path, { method: 'POST', body, ...options });
    const enroll = async () => {
      const { grant } = await post('enrollment-grants');
      return call('/v1/enroll', { method: 'POST', body: { grant } });
    };
    const [alpha, beta] = await Promise.all([enroll(), enroll()]);
    const identity = (browser, eventId = randomUUID()) => ({ installationId: browser.installationId, eventId });
    const firstEvent = identity(alpha);
    const secondEvent = identity(beta, firstEvent.eventId);
    const thirdEvent = identity(alpha);
    const spare = identity(beta);
    for (const [browser, record] of [[alpha, firstEvent], [beta, secondEvent], [alpha, thirdEvent], [beta, spare]]) {
      await call('/v1/browser/events', { token: browser.token, method: 'POST', expect: 204,
        body: { ...event, eventId: record.eventId, timestamp: new Date().toISOString() } });
    }
    const eventPath = (record) => `events/${record.installationId}/${record.eventId}`;
    assert.equal((await admin(eventPath(firstEvent))).incidentCase, null);
    if (postgres) {
      await stop();
      await retentionFixture(undoIncidentSchema);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 34'), '1');
    }
    const roster = await Promise.all([['Case operator', 'administrator'], ['Case auditor', 'auditor']].map(([name, role]) =>
      post('access', { name, role, hours: 1 })));
    const [operator, auditor] = roster;
    const category = 'suspected_data_exposure';
    const id = randomUUID();
    const create = { requestId: id, category, ...firstEvent };
    const path = `cases/${id}`;
    await post('cases', { ...create, category: 'custom' }, { expect: 400 });
    await post('cases', { ...create, title: 'SYNTHETIC_PROMPT' }, { expect: 400 });
    await post('cases', create, { token: auditor.token, expect: 403 });
    await post('cases', create, { token: second, expect: 404 });
    await admin('cases', { token: alpha.token, expect: 401 });
    const retry = () => post('cases', create, { token: operator.token });
    assert.deepEqual(await Promise.all([retry(), retry()]), [{ caseId: id }, { caseId: id }]);
    assert.deepEqual(await post('cases', { ...create, category: 'other' }, { expect: 409 }), { code: 'case_request_conflict' });
    assert.deepEqual(await post('cases', { ...create, requestId: randomUUID() }, { expect: 409 }), { code: 'event_in_case' });
    await admin(path, { token: second, expect: 404 });
    await admin(`${path}/export`, { token: second, expect: 404 });
    assert.deepEqual(await admin('cases', { token: second }), { entries: [], next: null });
    const opened = await admin(path, { token: auditor.token });
    assert.equal(opened.case.eventCount, 1);
    assert.equal(opened.case.triage.revision, 1);
    assert.deepEqual(opened.events.map(({ installationId, eventId }) => ({ installationId, eventId })), [firstEvent]);
    assert.deepEqual(opened.activity.map(({ change, actorAccess }) => [change.operation, actorAccess.name]), [['created', 'Case operator']]);

    const membership = (record, expectedRevision, linked, options) => post(`${path}/membership`, { ...record, expectedRevision, linked }, options);
    await membership(secondEvent, 1, true, { token: auditor.token, expect: 403 });
    await membership(identity(beta), 1, true, { expect: 404 });
    const responses = await Promise.all([secondEvent, thirdEvent].map((record) => fetch(`${baseUrl}/v1/admin/${path}/membership`, {
      method: 'POST', headers: { Authorization: `Bearer ${operator.token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...record, expectedRevision: 1, linked: true }), signal: AbortSignal.timeout(5000),
    })));
    const outcomes = await Promise.all(responses.map((response) => response.json()));
    assert.deepEqual(responses.map(({ status }) => status).sort(), [200, 409], JSON.stringify(outcomes));
    const winner = responses.findIndex(({ ok }) => ok);
    const joined = [secondEvent, thirdEvent][winner];
    const pendingLink = [secondEvent, thirdEvent][1 - winner];
    assert.deepEqual(outcomes[1 - winner], { code: 'case_stale' });
    await membership(joined, 1, true);
    await membership(pendingLink, 2, true);
    assert.deepEqual((await admin(path)).activity.map(({ change }) => change.revision), [3, 2, 1]);
    assert.equal((await admin(eventPath(secondEvent))).incidentCase.id, id);
    const investigate = { expectedRevision: 3, status: 'investigating', disposition: null, assigneeId: operator.access.id };
    await post(`${path}/triage`, { ...investigate, assigneeId: auditor.access.id }, { expect: 400 });
    await post(`${path}/triage`, investigate, { token: operator.token });
    await post(`${path}/triage`, investigate);
    assert.equal((await admin(eventPath(firstEvent))).event.triage, undefined);
    const exported = await admin(`${path}/export`, { token: auditor.token });
    assert.equal(exported.organization, `incident-cases-${suffix}`);
    assert.equal(exported.investigation.case.eventCount, 3);
    assert.equal(exported.investigation.case.triage.assignee.name, 'Case operator');
    assert.doesNotMatch(JSON.stringify(exported), /SYNTHETIC_PROMPT|rawText|filename|tokenHash|creationFingerprint/);
    assert.equal((await admin('audit?action=incident_case_changed')).entries.length, 4);
    assert.equal((await admin('cases?status=investigating')).entries[0].eventCount, 3);
    for (const invalid of ['status=closed', 'status=resolved&status=needs_review', 'beforeId=00000000-0000-0000-0000-000000000000',
      'beforeAt=2026-11-22T00:00:00Z', 'unsupported=true']) await admin(`cases?${invalid}`, { expect: 400 });
    await post(`access/${operator.access.id}/revoke`, undefined, { expect: 204 });
    const close = { ...investigate, expectedRevision: 4, status: 'resolved', disposition: 'confirmed_violation' };
    await post(`${path}/triage`, close);
    assert.equal((await admin(path)).case.triage.assignee.active, false);
    assert.deepEqual(await admin('cases?openOnly=true'), { entries: [], next: null });
    assert.deepEqual(await membership(secondEvent, 5, false, { expect: 409 }), { code: 'case_resolved' });
    await post(`${path}/triage`, { ...investigate, expectedRevision: 5, assigneeId: null });
    await membership(secondEvent, 6, false);
    await membership(secondEvent, 6, false);
    assert.equal((await admin(eventPath(secondEvent))).incidentCase, null);
    assert.equal((await admin(path)).case.eventCount, 2);

    if (!postgres) return;
    const separate = randomUUID();
    await post('cases', { requestId: separate, category: 'other', ...spare });
    await post(`cases/${separate}/triage`, { expectedRevision: 1, status: 'resolved', disposition: 'false_positive', assigneeId: null });
    await retentionFixture(`
      UPDATE incident_cases SET updated_at = now() - interval '3 days' WHERE id = '${separate}';
      UPDATE security_events SET occurred_at = now() - interval '3 days'
      WHERE installation_id = '${firstEvent.installationId}' AND event_id = '${firstEvent.eventId}';
    `);
    await post('retention', { securityEventDays: 1, aiObservationDays: null, auditDays: 1 }, { expect: 204 });
    await admin(`cases/${separate}`, { expect: 404 });
    await admin(`cases/${separate}/export`, { expect: 404 });
    assert.equal((await admin(eventPath(spare))).incidentCase, null);
    assert.equal((await admin(path)).case.eventCount, 1);
    await membership(spare, 7, true);
    await membership(firstEvent, 8, true, { expect: 404 });
    const cleaned = await post('retention/cleanup');
    assert.equal(cleaned.incidentCases, 1);
    assert.ok(cleaned.securityEvents >= 1);
    assert.equal((await admin(eventPath(spare))).incidentCase.id, id);
    assert.equal(await retentionFixture(`SELECT count(*) FROM incident_case_events WHERE installation_id = '${firstEvent.installationId}'
      AND event_id = '${firstEvent.eventId}';`), '0');
    assert.equal((await admin('audit?action=incident_case_changed')).entries.some(({ incidentCaseChange }) =>
      incidentCaseChange.caseId === separate), true);
    await retentionFixture(`
      WITH organization AS (SELECT id FROM organizations WHERE slug = 'incident-cases-${suffix}')
      INSERT INTO incident_cases (organization_id, id, category, creation_fingerprint)
      SELECT id, gen_random_uuid(), 'other', 'synthetic' FROM organization CROSS JOIN generate_series(1, 101);
      WITH more AS (
        INSERT INTO security_events (organization_id, installation_id, event_id, occurred_at, received_at, policy_version, decision, app_id, rule_id)
        SELECT organization_id, id, gen_random_uuid(), now(), now(), 1, 'monitor', 'local-prompt-fixture', 'fixture-secret'
        FROM installations CROSS JOIN generate_series(1, 98) WHERE id = '${alpha.installationId}'
        RETURNING organization_id, installation_id, event_id
      )
      INSERT INTO incident_case_events (organization_id, case_id, installation_id, event_id)
      SELECT organization_id, '${id}', installation_id, event_id FROM more;
    `);
    assert.equal((await admin(path)).case.eventCount, 100);
    assert.deepEqual(await membership(secondEvent, 8, true, { expect: 409 }), { code: 'case_event_limit' });
    const list = await admin('cases');
    const more = await admin(`cases?${new URLSearchParams({ beforeAt: list.next.createdAt, beforeId: list.next.id })}`);
    assert.equal(list.entries.length, 100);
    assert.equal(more.entries.length, 2);
    assert.equal(new Set([...list.entries, ...more.entries].map((entry) => entry.id)).size, 102);
  });

  await t.test('correlates new AI block decisions into auditable tenant alerts with retained evidence', async () => {
    const admin = (path, options) => call(`/v1/admin/${path}`, { token: alertsAdmin, ...options });
    const post = (path, body, options) => admin(path, { method: 'POST', body, ...options });
    const enroll = async () => call('/v1/enroll', { method: 'POST', body: { grant: (await post('enrollment-grants')).grant } });
    const [browser, canary] = await Promise.all([enroll(), enroll()]);
    const policy = await post('policies', { mode: 'block' });
    const legacy = { ...contract.event, eventId: randomUUID(), appId: 'chatgpt',
      policyVersion: policy.version, timestamp: new Date().toISOString(), decision: 'block' };
    const send = (data, token = browser.token, expect = 204) =>
      call('/v1/browser/events', { token, method: 'POST', body: data, expect });
    const event = (fields = {}) => ({ ...legacy, eventId: randomUUID(), timestamp: new Date().toISOString(), ...fields });
    const save = (enabled, threshold, expectedRevision, options) => post('alerts/settings', { enabled, threshold, expectedRevision }, options);
    const settings = { enabled: false, threshold: 5, revision: 0 };
    assert.deepEqual(await admin('alerts/settings'), settings);
    await send(legacy);
    assert.deepEqual((await admin('alerts')).entries, []);
    if (postgres) {
      const before = await admin('events');
      await stop();
      await retentionFixture(undoAlertSchema);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 37'), '1');
      assert.deepEqual(await admin('events'), before);
      assert.deepEqual(await admin('alerts/settings'), settings);
    }
    const { token: operator } = await post('access', { name: 'Alert operator', role: 'administrator', hours: 1 });
    const { token: auditor } = await post('access', { name: 'Alert auditor', role: 'auditor', hours: 1 });
    await save(true, 1, 0, { expect: 400 });
    await save(true, 2, 0, { token: auditor, expect: 403 });
    await post('alerts/settings', { enabled: true, threshold: 2 }, { expect: 400 });
    await admin('alerts', { token: browser.token, expect: 401 });
    await admin('alerts', { token: undefined, expect: 401 });
    await admin('alerts?status=open&status=acknowledged', { expect: 400 });
    await admin('alerts?appId=local-prompt-fixture', { expect: 400 });
    await admin('alerts?beforeId=' + randomUUID(), { expect: 400 });
    const [configured, retry] = await Promise.all([save(true, 2, 0, { token: operator }), save(true, 2, 0, { token: operator })]);
    assert.deepEqual(configured, { enabled: true, threshold: 2, revision: 1 });
    assert.deepEqual(retry, configured);
    assert.deepEqual(await save(true, 3, 0, { expect: 409 }), { code: 'alert_settings_changed' });
    assert.deepEqual(await admin('alerts/settings', { token: second }), settings);

    const leftInBucket = 900_000 - Date.now() % 900_000;
    if (leftInBucket < 10_000) await delay(leftInBucket + 50);
    const original = event();
    await Promise.all([send(original), send(original), send(legacy)]);
    await send(event({ appId: 'local-prompt-fixture' }));
    await send(event({ appId: 'gemini' }));
    await send(event({ prompt: 'synthetic secret text' }), browser.token, 400);
    assert.deepEqual((await admin('alerts')).entries, []);
    const group = await post('policy-groups', { name: 'Alert canary' });
    await call('/v1/browser/policy', { token: canary.token, assignmentAware: true });
    await post(`installations/${canary.installationId}/policy-group`, { groupId: group.id }, { expect: 204 });
    const groupPolicy = await call('/v1/browser/policy', { token: canary.token, assignmentAware: true });
    const inGroup = event({ policyVersion: groupPolicy.version, assignmentVersion: groupPolicy.assignmentVersion });
    await send(inGroup, canary.token);
    assert.deepEqual((await admin('alerts')).entries, []);
    const next = event();
    const also = event({ timestamp: new Date(Date.now() - 2 * 3600_000).toISOString() });
    await Promise.all([send(next), send(also), send(next)]);
    const [raised] = (await admin('alerts?appId=chatgpt&status=open')).entries;
    assert.equal(raised.blockCount, 3);
    assert.equal(raised.threshold, 2);
    assert.deepEqual(raised.rollout, { kind: 'baseline' });
    assert.equal(Date.parse(raised.windowStart) % 900_000, 0);
    assert.equal(Date.parse(raised.windowEnd) - Date.parse(raised.windowStart), 900_000);
    const path = `alerts/${raised.id}`;
    const detail = await admin(path, { token: auditor });
    assert.deepEqual(detail.alert, raised);
    assert.deepEqual(detail.evidence.entries.map(({ eventId }) => eventId).sort(), [original.eventId, next.eventId, also.eventId].sort());
    assert.doesNotMatch(JSON.stringify(detail), /synthetic secret text|token/);
    await admin(path, { token: second, expect: 404 });
    await admin(path, { token: browser.token, expect: 401 });
    await admin(`${path}?beforeEventId=${next.eventId}`, { expect: 400 });
    await post(`${path}/acknowledge`, {}, { token: auditor, expect: 403 });
    await post(`${path}/acknowledge`, {}, { token: second, expect: 404 });
    await Promise.all([
      post(`${path}/acknowledge`, {}, { token: operator, expect: 204 }),
      post(`${path}/acknowledge`, {}, { token: operator, expect: 204 }),
    ]);
    assert.deepEqual((await admin('alerts?status=open')).entries, []);
    assert.equal((await admin('alerts?status=acknowledged')).entries[0].id, raised.id);
    const acknowledged = (await admin('audit?action=security_alert_acknowledged')).entries;
    assert.equal(acknowledged.length, 1);
    assert.equal(acknowledged[0].securityAlertChange.alertId, raised.id);
    assert.equal(acknowledged[0].actorAccess.name, 'Alert operator');
    const changed = (await admin('audit?action=security_alert_settings_changed')).entries;
    assert.equal(changed.length, 1);
    assert.deepEqual(changed[0].securityAlertChange.after, configured);

    await send(event({ assignmentVersion: groupPolicy.assignmentVersion }), canary.token);
    const [scoped] = (await admin('alerts?status=open')).entries;
    assert.equal(scoped.blockCount, 2);
    assert.deepEqual(scoped.rollout, { kind: 'group', groupId: group.id, groupName: group.name });
    const off = await save(false, 2, 1);
    assert.equal(off.revision, 2);
    await send(event());
    assert.equal((await admin(path)).alert.blockCount, 3);
    await save(true, 2, 2);
    await send(event());
    assert.equal((await admin('alerts')).entries.length, 2);
    await Promise.all([send(event()), send(event())]);
    const all = await admin('alerts');
    assert.equal(all.entries.length, 3);
    const latest = all.entries.find((entry) => entry.id !== raised.id && entry.id !== scoped.id);
    assert.equal(latest.blockCount, 3);

    if (postgres) {
      for (let batch = 0; batch < 10; batch++) await Promise.all(Array.from({ length: 10 }, () => send(event())));
      const latestPath = `alerts/${latest.id}`;
      const full = await admin(latestPath);
      assert.equal(full.alert.blockCount, 103);
      assert.equal(full.evidence.entries.length, 100);
      const cursor = full.evidence.next;
      const older = await admin(`${latestPath}?${new URLSearchParams({ beforeAt: cursor.receivedAt,
        beforeEventId: cursor.eventId, beforeInstallationId: cursor.installationId })}`);
      assert.equal(older.evidence.entries.length, 3);
      assert.equal(new Set([...full.evidence.entries, ...older.evidence.entries].map(({ eventId }) => eventId)).size, 103);
      await retentionFixture(`UPDATE security_alert_windows SET window_start = window_start - interval '15 minutes'
        WHERE id = '${latest.id}';`);
      await send(event());
      assert.equal((await admin(latestPath)).alert.blockCount, 103);
      assert.equal((await admin('alerts')).entries.length, 3);
      await retentionFixture(`INSERT INTO security_alert_windows (organization_id, setting_revision, app_id, rollout_attributed,
          window_start, first_received_at, threshold, block_count, triggered_at)
        SELECT id, 100 + n, 'gemini', true, now(), now(), 2, 2, now() - interval '1 second'
        FROM organizations CROSS JOIN generate_series(1, 101) AS fixture(n) WHERE slug = 'alerts-${suffix}';`);
      const page = await admin('alerts?appId=gemini');
      assert.equal(page.entries.length, 100);
      const last = await admin(`alerts?${new URLSearchParams({ appId: 'gemini', beforeAt: page.next.triggeredAt, beforeId: page.next.id })}`);
      assert.equal(last.entries.length, 1);
      assert.equal(new Set([...page.entries, ...last.entries].map(({ id }) => id)).size, 101);

      await retentionFixture(`UPDATE security_alert_windows SET first_received_at = now() - interval '31 days'
          WHERE id = '${last.entries[0].id}';
        UPDATE security_alert_windows SET window_start = now() - interval '2 hours'
          WHERE organization_id = (SELECT id FROM organizations WHERE slug = 'alerts-${suffix}')
              AND triggered_at IS NULL AND app_id = 'gemini';`);
      await admin(`alerts/${last.entries[0].id}`, { expect: 404 });
      await stop();
      await start(1);
      let scheduled;
      for (let attempt = 0; attempt < 25 && !scheduled; attempt++) {
        scheduled = (await admin('audit?action=retention_cleanup')).entries.find((entry) => entry.cleanup.source === 'scheduled');
        if (!scheduled) await delay(100);
      }
      assert.equal(scheduled?.cleanup.alertWindows, 2);
      assert.equal(await retentionFixture(`SELECT count(*) FROM security_alert_windows WHERE id = '${last.entries[0].id}'`), '0');
      await stop();
      await start();

      await retentionFixture(`UPDATE security_events SET occurred_at = now() - interval '2 days' WHERE event_id = '${original.eventId}';`);
      await post('retention', { securityEventDays: 1, aiObservationDays: null, auditDays: null }, { expect: 204 });
      const redactedEvidence = await admin(path);
      assert.equal(redactedEvidence.alert.blockCount, 3);
      assert.equal(redactedEvidence.evidence.entries.length, 2);
      await retentionFixture(`UPDATE security_alert_windows SET first_received_at = now() - interval '2 days' WHERE id = '${raised.id}';`);
      await admin(path, { expect: 404 });
      await post(`${path}/acknowledge`, {}, { expect: 404 });
      const cleanup = await post('retention/cleanup');
      assert.equal(cleanup.alertWindows, 1);
      assert.equal(cleanup.securityEvents, 1);
      assert.equal(await retentionFixture(`SELECT count(*) FROM security_alert_events WHERE alert_id = '${raised.id}'`), '0');
      assert.equal((await admin('audit?action=security_alert_acknowledged')).entries.length, 1);
    }
  });

  await t.test('delivers a durable signed webhook with tenant isolation, retry, and recovery', async (webhookTest) => {
    const inbox = [];
    const replies = [];
    const receiver = createServer(async (request, response) => {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      inbox.push({ path: request.url, method: request.method, headers: request.headers, body });
      const reply = replies.shift() ?? { status: 204 };
      if (!reply.hold) response.writeHead(reply.status, reply.headers).end();
    });
    receiver.listen(0, '127.0.0.1');
    await once(receiver, 'listening');
    webhookTest.after(() => new Promise((resolve) => { receiver.close(resolve); receiver.closeAllConnections(); }));
    const endpoint = `http://127.0.0.1:${receiver.address().port}/notify`;
    const secret = randomBytes(32).toString('hex');
    const organization = `webhooks-${suffix}`;
    const route = {
      Control__AlertWebhooks__0__OrganizationSlug: organization,
      Control__AlertWebhooks__0__Endpoint: endpoint,
      Control__AlertWebhooks__0__SigningSecret: secret,
    };
    const admin = (path, options) => call(`/v1/admin/${path}`, { token: webhooksAdmin, ...options });
    const post = (path, body, options) => admin(path, { method: 'POST', body, ...options });
    const { grant } = await post('enrollment-grants');
    const browser = await call('/v1/enroll', { method: 'POST', body: { grant } });
    const policy = await post('policies', { mode: 'block' });
    async function eventually(check, message) {
      for (let attempt = 0; attempt < 75; attempt++) {
        const result = await check();
        if (result) return result;
        await delay(100);
      }
      assert.fail(message);
    }
    async function raise(appId = 'chatgpt') {
      const previous = new Set((await admin('alerts')).entries.map(({ id }) => id));
      let settings = await admin('alerts/settings');
      if (settings.enabled) settings = await post('alerts/settings', { enabled: false, threshold: 2, expectedRevision: settings.revision });
      await post('alerts/settings', { enabled: true, threshold: 2, expectedRevision: settings.revision });
      const remaining = 900_000 - Date.now() % 900_000;
      if (remaining < 3000) await delay(remaining + 50);
      const one = { ...contract.event, appId, eventId: randomUUID(), timestamp: new Date().toISOString(),
        policyVersion: policy.version, decision: 'block' };
      const send = (body) => call('/v1/browser/events', { token: browser.token, method: 'POST', body, expect: 204 });
      await Promise.all([send(one), send({ ...one, eventId: randomUUID() }), send(one)]);
      const alert = (await admin('alerts')).entries.find(({ id }) => !previous.has(id));
      assert.ok(alert);
      assert.equal(alert.blockCount, 2);
      return alert;
    }
    const detail = (alert, options) => admin(`alerts/${alert.id}`, options);
    const state = (alert, wanted) => eventually(async () => {
      const lease = (await detail(alert)).webhook;
      return lease?.status === wanted ? lease : false;
    }, `The webhook did not enter state ${wanted}.`);
    const old = await raise();
    assert.equal((await detail(old)).webhook, undefined);
    await assert.rejects(sql('dotnet', [app], { timeout: 5000, env: {
      ...process.env, ASPNETCORE_ENVIRONMENT: 'Production', DOTNET_ENVIRONMENT: 'Production', Control__HostedPilot: 'true',
      ConnectionStrings__Control: db, Control__Organizations__0__Slug: organization, Control__Organizations__0__AdminToken: webhooksAdmin, ...route,
    } }), (error) => {
      assert.match(error.stderr, /Configure one HTTPS alert webhook/);
      assert.doesNotMatch(error.stderr, new RegExp(secret));
      return true;
    });
    await stop();
    if (postgres) await retentionFixture('DELETE FROM schema_migrations WHERE version = 38; DROP TABLE alert_webhook_deliveries;');
    await start(3600, route);
    if (postgres) assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 38'), '1');
    assert.equal((await detail(old)).webhook, undefined);
    assert.deepEqual(inbox, []);

    if (postgres) replies.push({ status: 429, headers: { 'Retry-After': '90' } }, { status: 204 });
    const delivered = await raise('gemini');
    if (postgres) {
      const retry = await state(delivered, 'retrying');
      assert.equal(retry.lastHttpStatus, 429);
      assert.equal(retry.attempts, 1);
      assert.ok(Date.parse(retry.nextAttemptAt) - Date.parse(retry.lastAttemptAt) >= 90_000);
      await retentionFixture(`UPDATE alert_webhook_deliveries SET available_at = now() WHERE alert_id = '${delivered.id}';`);
    }
    const sent = await state(delivered, 'sent');
    assert.equal(sent.attempts, postgres ? 2 : 1);
    assert.equal(sent.lastHttpStatus, 204);
    assert.ok(Date.parse(sent.sentAt));
    const [message, again] = inbox;
    function checkSignature(entry) {
      const time = entry.headers['x-zekvar-timestamp'];
      assert.match(time, /^\d{10}$/);
      assert.ok(Math.abs(Math.floor(Date.now() / 1000) - Number(time)) < 60);
      const signature = createHmac('sha256', Buffer.from(secret, 'hex')).update(time + '.').update(entry.body).digest('hex');
      assert.equal(entry.headers['x-zekvar-signature'], `v1=${signature}`);
      assert.equal(entry.headers.authorization, undefined);
      assert.equal(entry.headers['content-type'], 'application/json');
      assert.equal(entry.method, 'POST');
      const payload = JSON.parse(entry.body);
      assert.equal(payload.deliveryId, entry.headers['x-zekvar-delivery-id']);
      assert.equal(payload.organization, organization);
      assert.deepEqual(Object.keys(payload).sort(), [
        'alertId', 'appId', 'deliveryId', 'organization', 'rollout', 'rolloutGroupId', 'schemaVersion',
        'threshold', 'triggeredAt', 'type', 'windowEnd', 'windowStart',
      ]);
      return payload;
    }
    const payload = checkSignature(message);
    assert.equal(message.path, '/notify');
    assert.equal(payload.type, 'security.alert.opened');
    assert.equal(payload.schemaVersion, 1);
    assert.equal(payload.appId, 'gemini');
    assert.equal(payload.alertId, delivered.id);
    assert.equal(payload.threshold, 2);
    if (again) {
      assert.deepEqual(checkSignature(again), payload);
      assert.deepEqual(again.body, message.body);
    }
    const auditor = await post('access', { name: 'Webhook auditor', role: 'auditor', hours: 1 });
    assert.deepEqual((await detail(delivered, { token: auditor.token })).webhook, sent);
    await detail(delivered, { token: second, expect: 404 });
    const recorded = JSON.stringify(await detail(delivered));
    assert.ok(!recorded.includes(endpoint) && !recorded.includes(secret) && !recorded.includes(payload.deliveryId));

    const foreign = (path, options) => admin(path, { token: alertsAdmin, ...options });
    const foreignPost = (path, body) => foreign(path, { method: 'POST', body });
    const prior = await foreign('alerts/settings');
    const previousForeignAlerts = new Set((await foreign('alerts?appId=chatgpt')).entries.map(({ id }) => id));
    const disabled = await foreignPost('alerts/settings', { enabled: false, threshold: 2, expectedRevision: prior.revision });
    await foreignPost('alerts/settings', { enabled: true, threshold: 2, expectedRevision: disabled.revision });
    const [foreignPolicy] = await foreign('policies');
    const foreignGrant = (await foreignPost('enrollment-grants')).grant;
    const unrouted = await call('/v1/enroll', { method: 'POST', body: { grant: foreignGrant } });
    const remaining = 900_000 - Date.now() % 900_000;
    if (remaining < 3000) await delay(remaining + 50);
    await Promise.all(Array.from({ length: 2 }, () => {
      const eventId = randomUUID();
      return call('/v1/browser/events', { method: 'POST', token: unrouted.token, expect: 204, body: {
        ...contract.event, eventId, appId: 'chatgpt', policyVersion: foreignPolicy.version, decision: 'block', timestamp: new Date().toISOString(),
      } });
    }));
    const otherAlert = (await foreign('alerts?appId=chatgpt')).entries.find(({ id }) => !previousForeignAlerts.has(id));
    assert.ok(otherAlert);
    assert.equal((await foreign(`alerts/${otherAlert.id}`)).webhook, undefined);
    await delay(2200);
    assert.equal(inbox.length, postgres ? 2 : 1);

    replies.push({ status: 302, headers: { Location: '/should-not-receive' } });
    const redirect = await raise();
    const failed = await state(redirect, 'failed');
    assert.equal(failed.attempts, 1);
    assert.equal(failed.lastHttpStatus, 302);
    assert.ok(inbox.every(({ path }) => path === '/notify'));
    if (!postgres) return;

    replies.push({ hold: true });
    const interrupted = await raise();
    const attempted = await eventually(() => inbox.find(({ body }) => JSON.parse(body).alertId === interrupted.id),
      'The pending webhook did not reach its receiver.');
    await stop();
    await start(3600, { ...route, Control__AlertWebhooks__0__Endpoint: endpoint + '-replacement' });
    const unavailable = await state(interrupted, 'paused');
    assert.equal(unavailable.attempts, 1);
    assert.equal(unavailable.nextAttemptAt, null);
    assert.ok(inbox.every(({ path }) => path === '/notify'));
    await stop();
    await retentionFixture(`UPDATE alert_webhook_deliveries SET lease_until = now() - interval '1 second'
      WHERE alert_id = '${interrupted.id}';`);
    await start(3600, route);
    assert.equal((await state(interrupted, 'sent')).attempts, 2);
    const recovered = inbox.filter(({ body }) => JSON.parse(body).alertId === interrupted.id);
    assert.equal(recovered.length, 2);
    assert.deepEqual(recovered[1].body, attempted.body);
    checkSignature(recovered[1]);

    replies.push({ status: 503 }, { status: 503 });
    const exhausted = await raise('gemini');
    await state(exhausted, 'retrying');
    await retentionFixture(`UPDATE alert_webhook_deliveries SET attempts = 5, available_at = now()
      WHERE alert_id = '${exhausted.id}';`);
    const terminal = await state(exhausted, 'failed');
    assert.equal(terminal.attempts, 6);
    assert.equal(terminal.lastHttpStatus, 503);
    assert.equal(terminal.nextAttemptAt, null);

    replies.push({ status: 503 });
    const restored = await raise();
    await state(restored, 'retrying');
    await stop();
    await retentionFixture(await readFile(new URL('../../../deploy/pilot/recover-access.sql', import.meta.url), 'utf8'));
    await start(3600, route);
    const cancelled = await state(restored, 'failed');
    assert.equal(cancelled.failureCode, 'recovery_cancelled');
    assert.equal(cancelled.attempts, 1);
    assert.equal((await detail(interrupted)).webhook.status, 'sent');
  });

  await t.test('streams retained event metadata in commit order with isolated, expiring keys and recoverable checkpoints', async () => {
    const admin = (path, options) => call(`/v1/admin/${path}`, { token: eventFeedAdmin, ...options });
    const post = (path, body, options) => admin(path, { method: 'POST', body, ...options });
    const browse = (token, query = '', expect = 200) => call('/v1/integrations/events' + query, { token, expect });
    const keys = 'access/event-feed';
    const issue = (name, options, fields = {}) => post(keys, { name, days: 15, requestId: randomUUID(), ...fields }, options);
    const revoke = (keyId, options) => post(`${keys}/${keyId}/revoke`, undefined, { expect: 204, ...options });
    const { grant } = await post('enrollment-grants');
    const browser = await call('/v1/enroll', { method: 'POST', body: { grant } });
    const { version } = await post('policies', { mode: 'block', uploadModes: { gemini: 'block' } });
    const event = (fields = {}) => ({ ...contract.event, eventId: randomUUID(), timestamp: new Date().toISOString(),
      policyVersion: version, decision: 'block', appId: 'chatgpt', ...fields });
    const send = (body) => call('/v1/browser/events', { token: browser.token, method: 'POST', body, expect: 204 });
    const first = event();
    const second = event({ timestamp: new Date(Date.now() - 10_000).toISOString(), appId: 'gemini',
      ruleId: 'ai-file-upload', detectorCategory: 'file-upload', uploadMethod: 'drop' });
    await send(first);
    await send(second);
    if (postgres) {
      await stop();
      await retentionFixture(undoEventFeedSchema);
      await start();
      assert.equal(await retentionFixture("SELECT count(*) FROM schema_migrations WHERE version = 39"), '1');
    }

    const operator = await post('access', { name: 'Feed operator', role: 'administrator', hours: 1 });
    const auditor = await post('access', { name: 'Feed auditor', role: 'auditor', hours: 1 });
    for (const token of [operator.token, auditor.token]) {
      await admin(keys, { token, expect: 403 });
      await issue('Denied key', { token, expect: 403 });
    }
    for (const token of [undefined, eventFeedAdmin, browser.token, auditor.token, 'zkf_' + '0'.repeat(64)]) {
      await browse(token, '', 401);
    }
    await issue('Bad lifetime', { expect: 400 }, { days: 91 });
    await issue('Bad request ID', { expect: 400 }, { requestId: '00000000-0000-0000-0000-000000000000' });
    await issue('Extra data', { expect: 400 }, { prompt: 'SYNTHETIC_PRIVATE_PROMPT' });
    const requestId = randomUUID();
    const retryIssue = () => fetch(`${baseUrl}/v1/admin/${keys}`, { method: 'POST', headers: {
      Authorization: `Bearer ${eventFeedAdmin}`, 'Content-Type': 'application/json',
    }, body: JSON.stringify({ name: 'Primary collector', requestId, days: 15 }), signal: AbortSignal.timeout(5000) });
    const replies = await Promise.all([retryIssue(), retryIssue()]);
    assert.deepEqual(replies.map(({ status }) => status).sort(), [200, 409]);
    const { token, key } = await replies.find(({ ok }) => ok).json();
    assert.deepEqual(await replies.find(({ ok }) => !ok).json(), { code: 'event_feed_key_exists' });
    assert.match(token, /^zkf_[a-f0-9]{64}$/);
    assert.equal(key.id, requestId);
    assert.equal(Date.parse(key.expiresAt) - Date.parse(key.issuedAt), 15 * 86_400_000);
    assert.deepEqual(await admin(keys), [key]);
    if (postgres) assert.equal(await retentionFixture(`SELECT token_hash FROM event_feed_keys WHERE id = '${key.id}'`),
      createHash('sha256').update(token).digest('hex'));
    await admin('session', { token, expect: 401 });
    await call('/v1/browser/policy', { token, expect: 401 });
    await call('/v1/integrations/events', { token, method: 'POST', expect: 405 });
    for (const query of ['?after=', '?after=malformed', '?limit=-1', '?limit=501', '?limit=1&limit=2', '?limit=1&output=json']) {
      await browse(token, query, 400);
    }

    const readAfter = (cursor, pageSize = 1, key = token, expect = 200) =>
      browse(key, '?' + new URLSearchParams({ after: cursor, limit: pageSize }), expect);
    const page = await browse(token, '?limit=1');
    assert.equal(page.schemaVersion, 1);
    assert.equal(page.hasMore, true);
    assert.equal(page.entries[0].eventId, first.eventId);
    assert.deepEqual(Object.keys(page.entries[0]).sort(), ['appId', 'decision', 'detectorCategory', 'eventId', 'installationId',
      'policyVersion', 'receivedAt', 'rollout', 'ruleId', 'timestamp']);
    assert.deepEqual(page.entries[0].rollout, { kind: 'baseline' });
    const tail = await readAfter(page.nextCursor);
    assert.equal(tail.hasMore, false);
    assert.equal(tail.entries[0].eventId, second.eventId);
    assert.equal(tail.entries[0].uploadMethod, 'drop');
    assert.equal(tail.entries[0].detectorCategory, 'file-upload');
    assert.deepEqual(await readAfter(page.nextCursor), tail);
    assert.deepEqual(await readAfter(tail.nextCursor), { schemaVersion: 1, entries: [], nextCursor: tail.nextCursor, hasMore: false });
    assert.deepEqual(await readAfter(tail.nextCursor.split(':')[0] + ':9223372036854775807', 1, token, 409),
      { code: 'event_feed_cursor_invalid' });
    const foreign = await issue('Foreign collector', { token: retentionAdmin });
    assert.deepEqual(await readAfter(page.nextCursor, 1, foreign.token, 409), { code: 'event_feed_cursor_invalid' });
    await revoke(key.id, { token: retentionAdmin, expect: 404 });

    const arriving = Array.from({ length: 12 }, () => event());
    const concurrent = Promise.all(arriving.flatMap((entry) => [send(entry), send(entry)]));
    let seen = await readAfter(tail.nextCursor, 2);
    const delivered = seen.entries.map(({ eventId }) => eventId);
    await concurrent;
    do {
      seen = await readAfter(seen.nextCursor, 2);
      delivered.push(...seen.entries.map(({ eventId }) => eventId));
    } while (seen.hasMore);
    assert.deepEqual(delivered.sort(), arriving.map(({ eventId }) => eventId).sort());
    if (postgres) {
      const pending = event();
      const following = event();
      const delayed = retentionFixture(`BEGIN;
        INSERT INTO security_events (organization_id, installation_id, event_id, occurred_at, policy_version,
          decision, app_id, rule_id, rollout_attributed)
        SELECT organization_id, id, '${pending.eventId}', now(), ${version}, 'block', 'chatgpt', 'fixture-secret', true
        FROM installations WHERE id = '${browser.installationId}';
        SELECT pg_advisory_xact_lock(39, 10201);
        SELECT pg_sleep(1.5);
        COMMIT;`);
      for (let attempt = 0; attempt < 30; attempt++) {
        const inserting = await retentionFixture("SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND classid = 39 AND objid = 10201 AND granted)");
        if (inserting === 't') break;
        assert.ok(attempt < 29, 'The delayed writer did not acquire the stream lock.');
        await delay(20);
      }
      const followingWrite = send(following);
      const peek = await readAfter(seen.nextCursor);
      assert.deepEqual(peek.entries, []);
      assert.equal(peek.nextCursor, seen.nextCursor);
      await Promise.all([delayed, followingWrite]);
      seen = await readAfter(peek.nextCursor, 2);
      assert.deepEqual(seen.entries.map(({ eventId }) => eventId), [pending.eventId, following.eventId]);
    }
    const rotation = await issue('Replacement collector');
    assert.deepEqual(await readAfter(seen.nextCursor, 1, rotation.token), await readAfter(seen.nextCursor));
    await Promise.all([revoke(key.id), revoke(key.id)]);
    await browse(token, '', 401);
    assert.equal((await admin(keys)).find(({ id }) => id === key.id).status, 'revoked');
    assert.deepEqual((await admin('audit?action=event_feed_key_issued')).entries.map(({ eventFeedKeyChange }) => eventFeedKeyChange.keyId).sort(),
      [key.id, rotation.key.id].sort());
    const audit = (await admin('audit?action=event_feed_key_revoked')).entries;
    assert.equal(audit.length, 1);
    assert.deepEqual(audit[0].eventFeedKeyChange, { keyId: key.id, name: 'Primary collector' });
    assert.equal(JSON.stringify(audit).includes(token), false);

    if (!postgres) return;
    await retentionFixture(`UPDATE event_feed_keys SET issued_at = now() - interval '2 days', expires_at = now() - interval '1 day'
      WHERE id = '${foreign.key.id}'; UPDATE security_events SET occurred_at = now() - interval '2 days' WHERE event_id = '${first.eventId}';`);
    await browse(foreign.token, '', 401);
    assert.equal((await admin(keys, { token: retentionAdmin })).find(({ id }) => id === foreign.key.id).status, 'expired');
    await post('retention', { securityEventDays: 1, aiObservationDays: null, auditDays: 30 }, { expect: 204 });
    assert.equal((await retentionFixture(`SELECT count(*) FROM security_events WHERE event_id = '${first.eventId}'`)), '1');
    const retained = await browse(rotation.token);
    assert.ok(retained.entries.every(({ eventId }) => eventId !== first.eventId));
    assert.equal(retained.entries.length, 15);
    await post('retention/cleanup');
    assert.equal((await retentionFixture(`SELECT count(*) FROM security_events WHERE event_id = '${first.eventId}'`)), '0');
    assert.deepEqual(await browse(rotation.token), retained);

    await stop();
    await retentionFixture(await readFile(new URL('../../../deploy/pilot/recover-access.sql', import.meta.url), 'utf8'));
    await start();
    await browse(rotation.token, '', 401);
    const recovered = await issue('Restored collector');
    await readAfter(retained.nextCursor, 1, recovered.token, 409);
    assert.deepEqual((await browse(recovered.token)).entries, retained.entries);
    assert.ok((await admin('audit?action=event_feed_key_revoked')).entries.some(({ eventFeedKeyChange }) => eventFeedKeyChange.keyId === rotation.key.id));
    const reserve = await Promise.all(Array.from({ length: 19 }, (_, index) => issue(`Capacity check ${index + 1}`)));
    assert.equal((await admin(keys)).filter(({ status }) => status === 'active').length, 20);
    assert.deepEqual(await issue('Over capacity', { expect: 409 }), { code: 'event_feed_key_limit' });
    await revoke(reserve[0].key.id);
    assert.equal((await issue('Recovered key slot')).key.status, 'active');
  });

  await t.test('versions Chrome hardening plans with scoped reviews, safe defaults, and policy rollback', async () => {
    const admin = (path, options) => call(`/v1/admin/${path}`, { token: hardeningAdmin, ...options });
    const post = (path, body, options) => admin(path, { method: 'POST', body, ...options });
    const initial = { safeBrowsing: 'preserve', downloads: 'preserve', lockSafeBrowsingWarnings: false, disableGuest: false,
      disableIncognito: false, disablePasswordSaving: false, disableSync: false };
    const baseline = await post('policies', { mode: 'block' });
    if (postgres) {
      await stop();
      await retentionFixture('DELETE FROM schema_migrations WHERE version = 40; ALTER TABLE policy_versions DROP COLUMN browser_hardening;');
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 40'), '1');
    }
    assert.deepEqual((await admin('policies'))[0], baseline);
    assert.deepEqual(baseline.browserHardening, initial);
    const requested = { ...initial, safeBrowsing: 'standard', downloads: 'all', lockSafeBrowsingWarnings: true,
      disableGuest: true, disableIncognito: true, disablePasswordSaving: true, disableSync: true };
    const group = await post('policy-groups', { name: 'Chrome hardening canary' });
    const groupPath = `policy-groups/${group.id}`;
    const path = `${groupPath}/policies`;
    const save = (browserHardening, options, expectedVersion = baseline.version) => post(path, { browserHardening, expectedVersion }, options);
    await post(path, { browserHardening: requested }, { expect: 400 });
    await save({ ...requested, safeBrowsing: 'disabled' }, { expect: 400 });
    await save({ ...requested, safeBrowsing: null }, { expect: 400 });
    await save({ ...requested, downloads: '3' }, { expect: 400 });
    await save({ ...requested, extraPolicy: 'private synthetic marker' }, { expect: 400 });
    await save(requested, { token: eventFeedAdmin, expect: 409 });
    await save(requested, { expect: 409 }, baseline.version - 1);
    const first = await save(requested);
    assert.deepEqual(first.browserHardening, requested);
    assert.deepEqual(await admin(path, { token: eventFeedAdmin }), []);
    await save(requested, { expect: 409 });
    assert.equal((await admin(path)).length, 1);
    assert.deepEqual((await admin('policies'))[0].browserHardening, initial);
    const author = await post('access', { name: 'Hardening author', role: 'administrator', hours: 1 });
    const reviewer = await post('access', { name: 'Hardening reviewer', role: 'administrator', hours: 1 });
    const auditor = await post('access', { name: 'Hardening auditor', role: 'auditor', hours: 1 });
    assert.deepEqual((await admin(path, { token: auditor.token }))[0].browserHardening, requested);
    await save(requested, { token: auditor.token, expect: 403 }, first.version);
    await post('policy-reviews/setting', { required: true }, { expect: 204 });
    await save(requested, { expect: 403 }, first.version);
    const stricter = { ...requested, safeBrowsing: 'enhanced' };
    const { reviewId } = await save(stricter, { token: author.token, expect: 202, expectReview: true }, first.version);
    const review = (await admin('policy-reviews')).entries.find(({ id }) => id === reviewId);
    assert.deepEqual(review.snapshots.before.browserHardening, requested);
    assert.deepEqual(review.snapshots.candidate.browserHardening, stricter);
    assert.deepEqual((await admin(path))[0].browserHardening, requested);
    await post(`policy-reviews/${reviewId}/decision`, { approve: true }, { token: author.token, expect: 403 });
    const approved = await post(`policy-reviews/${reviewId}/decision`, { approve: true }, { token: reviewer.token });
    assert.deepEqual(approved.browserHardening, stricter);
    const audited = (await admin('audit?action=policy_published')).entries.find(({ policyVersion }) => policyVersion === approved.version);
    assert.equal(audited.actorAccess.id, reviewer.access.id);
    assert.equal(audited.groupChange.groupId, group.id);
    await post('policy-reviews/setting', { required: false }, { expect: 204 });
    const otherSetting = await post(path, { mode: 'warn', expectedVersion: approved.version });
    assert.deepEqual(otherSetting.browserHardening, stricter);
    const promoted = await post(`${groupPath}/promote`, { expectedVersion: otherSetting.version });
    assert.deepEqual(promoted.browserHardening, stricter);
    const { grant } = await post('enrollment-grants');
    const browser = await call('/v1/enroll', { method: 'POST', body: { grant } });
    const delivered = await call('/v1/browser/policy', { token: browser.token });
    assert.equal(delivered.version, promoted.version);
    assert.equal(delivered.mode, 'warn');
    assert.equal(Object.hasOwn(delivered, 'browserHardening'), false);
    const restored = await post(`policies/${baseline.version}/restore`);
    assert.deepEqual(restored.browserHardening, initial);
    assert.deepEqual((await admin(path))[0].browserHardening, stricter);
  });

  await t.test('validates clipboard decisions against delivered policy, isolates metadata, and preserves legacy events', async () => {
    const admin = (path, options) => call(`/v1/admin/${path}`, { token: clipboardAdmin, ...options });
    const post = (path, body, options) => admin(path, { method: 'POST', body, ...options });
    const browser = await call('/v1/enroll', { method: 'POST', body: { grant: (await post('enrollment-grants')).grant } });
    const browserCall = (path, options) => call(`/v1/browser/${path}`, { token: browser.token, ...options });
    const deliver = () => browserCall('policy', { assignmentAware: true, clipboardAware: true, claudeAware: true });
    const write = (path, body, expect = 204) => browserCall(path, { method: 'POST', body, expect });
    const publish = (fields, options) => post('policies', fields, options);
    const [initial] = await admin('policies');
    const event = (policy, fields = {}) => ({ ...contract.event, eventId: randomUUID(), appId: 'chatgpt',
      timestamp: new Date().toISOString(), policyVersion: policy.version, decision: 'monitor', clipboardPaste: true, ...fields });
    const legacy = event(initial);
    delete legacy.clipboardPaste;
    await write('events', legacy);
    const before = await admin('events');
    if (postgres) {
      await stop();
      await retentionFixture(undoClipboardSchema);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 41'), '1');
      assert.deepEqual(await admin('events'), before);
    }
    assert.equal((await admin('policies'))[0].clipboardMode, 'off');
    await write('events', event(initial), 400);
    await publish({ clipboardMode: 'warn' }, { expect: 400 });
    const monitoring = await publish({ mode: 'block', clipboardMode: 'monitor' });
    assert.equal((await browserCall('policy', { clipboardAware: true })).clipboardMode, undefined);
    await write('heartbeat', { policyVersion: monitoring.version });
    assert.notEqual((await admin('installations'))[0].appliedPolicyVersion, monitoring.version);
    await write('heartbeat', { policyVersion: monitoring.version, clipboardModeApplied: true }, 400);
    await write('events', event(monitoring), 400);
    assert.equal((await deliver()).clipboardMode, 'monitor');
    await write('heartbeat', { policyVersion: monitoring.version, clipboardModeApplied: true });
    assert.equal((await admin('installations'))[0].appliedPolicyVersion, monitoring.version);

    const detection = event(monitoring);
    await Promise.all([write('events', detection), write('events', detection)]);
    for (const fields of [
      { decision: 'block' }, { decision: 'warn' }, { decision: 'exception_applied' }, { appId: 'claude' },
      { appId: 'local-prompt-fixture' }, { uploadMethod: 'paste' }, { content: 'private synthetic clipboard' },
      { ruleId: 'github-classic-pat', detectorCategory: 'credential' },
      { ruleId: 'clipboard-inspection-unavailable', detectorCategory: 'clipboard' },
    ]) await write('events', event(monitoring, fields), 400);
    const stored = (await admin('events')).filter(({ clipboardPaste }) => clipboardPaste);
    assert.deepEqual(stored.map(({ eventId }) => eventId), [detection.eventId]);
    assert.equal(stored[0].uploadMethod, undefined);
    const path = `events/${browser.installationId}/${detection.eventId}`;
    assert.equal((await admin(path)).event.clipboardPaste, true);
    await admin(path, { token: eventFeedAdmin, expect: 404 });

    const { token } = await post('access/event-feed', { name: 'Clipboard collector', days: 1, requestId: randomUUID() });
    const feed = await call('/v1/integrations/events', { token });
    assert.equal(feed.entries.find(({ eventId }) => eventId === detection.eventId).clipboardPaste, true);
    const exported = await admin('events/export');
    assert.equal(exported.entries.find(({ eventId }) => eventId === detection.eventId).clipboardPaste, true);
    assert.doesNotMatch(JSON.stringify({ exported, feed }), /private synthetic clipboard|clipboardText|clipboardData/);

    const author = await post('access', { name: 'Clipboard author', role: 'administrator', hours: 1 });
    const reviewer = await post('access', { name: 'Clipboard reviewer', role: 'administrator', hours: 1 });
    await post('policy-reviews/setting', { required: true }, { expect: 204 });
    const { reviewId } = await publish({ clipboardMode: 'block', githubPatMode: 'monitor', claudePromptEnabled: true,
      expectedVersion: monitoring.version }, { token: author.token, expectReview: true, expect: 202 });
    assert.equal((await deliver()).clipboardMode, 'monitor');
    const applied = await post(`policy-reviews/${reviewId}/decision`, { approve: true }, { token: reviewer.token });
    assert.equal((await deliver()).clipboardMode, 'block');
    await write('events', event(applied, { appId: 'claude', ruleId: 'github-classic-pat', detectorCategory: 'credential', decision: 'block' }));
    const incomplete = event(applied, { ruleId: 'clipboard-inspection-unavailable', detectorCategory: 'clipboard', decision: 'block' });
    await write('events', incomplete);
    await write('events', { ...incomplete, eventId: randomUUID(), clipboardPaste: false }, 400);
    await post('policy-reviews/setting', { required: false }, { expect: 204 });
    const restored = await post(`policies/${initial.version}/restore`);
    assert.equal((await deliver()).clipboardMode, 'off');
    await write('events', event(restored), 400);
    assert.equal((await admin('events')).find(({ eventId }) => eventId === incomplete.eventId).detectorCategory, 'clipboard');
  });

  await t.test('moves and revokes browser batches atomically with scoped receipts and stale-selection protection', async () => {
    const admin = (path, options) => call(`/v1/admin/${path}`, { token: fleetAdmin, ...options });
    const post = (path, body, options) => admin(path, { method: 'POST', body, ...options });
    const path = 'installations/fleet';
    const enroll = async (aware = true) => {
      const { grant } = await post('enrollment-grants');
      const browser = await call('/v1/enroll', { method: 'POST', body: { grant } });
      if (aware) await call('/v1/browser/policy', { token: browser.token, assignmentAware: true });
      return browser;
    };
    const selection = (row) => ({ installationId: row.installationId, assignmentVersion: row.assignmentVersion });
    const [firstBrowser, secondBrowser, legacy, thirdBrowser] = await Promise.all([enroll(), enroll(), enroll(false), enroll()]);
    const original = await admin(path);
    assert.equal(original.entries.length, 4);
    if (postgres) {
      await stop();
      await retentionFixture(undoFleetSchema);
      await start();
      assert.deepEqual(await admin(path), original);
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 42'), '1');
    }
    const find = (browser, page = original) => page.entries.find(({ installationId }) => installationId === browser.installationId);
    const [one, two, old, three] = [firstBrowser, secondBrowser, legacy, thirdBrowser].map((browser) => selection(find(browser)));
    const group = await post('policy-groups', { name: 'Fleet rollout canary' });
    const groupPath = `policy-groups/${group.id}/policies`;
    const initial = await post(groupPath, { mode: 'block' });
    const target = await post(groupPath, { mode: 'warn' });
    const assign = (selections, fields = {}) => ({ requestId: randomUUID(), operation: 'assign', groupId: group.id,
      expectedPolicyVersion: target.version, selections, ...fields });
    const run = (body, options = {}) => post(path, body, options);
    const scoped = async () => (await admin(`${path}?rolloutGroup=${group.id}`)).entries;
    for (const query of ['beforeAt=2024-01-01', 'beforeAt=invalid&beforeId=' + randomUUID(), 'rolloutGroup=baseline&rolloutGroup=baseline', 'page=2']) {
      await admin(`${path}?${query}`, { expect: 400 });
    }
    await admin(`${path}?rolloutGroup=${group.id}`, { token: clipboardAdmin, expect: 404 });
    await run(assign([one, one]), { expect: 400 });
    await run(assign([one, { ...two, assignmentVersion: -1 }]), { expect: 400 });
    await run(assign([one], { operation: 'revoke' }), { expect: 400 });
    await run(assign(Array.from({ length: 26 }, () => ({ installationId: randomUUID(), assignmentVersion: 0 }))), { expect: 400 });
    assert.deepEqual(await run(assign([one, old]), { expect: 409 }), { code: 'fleet_upgrade_required' });
    assert.deepEqual(await run(assign([one, two], { expectedPolicyVersion: initial.version }), { expect: 409 }), { code: 'fleet_policy_changed' });
    await run(assign([one, { installationId: randomUUID(), assignmentVersion: 0 }]), { expect: 404 });
    await run(assign([one], { groupId: randomUUID() }), { expect: 404 });
    assert.deepEqual(await scoped(), []);

    const actor = await post('access', { name: 'Fleet operator', role: 'administrator', hours: 1 });
    const auditor = await post('access', { name: 'Fleet auditor', role: 'auditor', hours: 1 });
    assert.equal((await admin(path, { token: auditor.token })).entries.length, 4);
    await run(assign([one, two]), { token: auditor.token, expect: 403 });
    const batch = assign([one, two]);
    if (postgres) {
      await retentionFixture(`ALTER TABLE control_audit ADD CONSTRAINT fleet_test_reject_receipt
        CHECK (action <> 'browser_fleet_changed' OR fleet_change->>'batchId' <> '${batch.requestId}');`);
      try {
        const failure = await fetch(`${baseUrl}/v1/admin/${path}`, {
          method: 'POST', body: JSON.stringify(batch), headers: { Authorization: `Bearer ${actor.token}`, 'Content-Type': 'application/json' },
          signal: AbortSignal.timeout(5000),
        });
        assert.equal(failure.status, 500);
        await failure.body?.cancel();
        assert.deepEqual(await scoped(), []);
        assert.deepEqual((await admin('audit?action=policy_group_assigned')).entries, []);
        assert.deepEqual((await admin('audit?action=browser_fleet_changed')).entries, []);
      } finally {
        await retentionFixture('ALTER TABLE control_audit DROP CONSTRAINT fleet_test_reject_receipt');
      }
    }
    const [commit, replay] = await Promise.all([run(batch, { token: actor.token }),
      run({ ...batch, selections: [two, one] }, { token: actor.token })]);
    assert.deepEqual(commit, replay);
    assert.deepEqual({ ...commit, changedInstallations: commit.changedInstallations.sort() }, {
      batchId: batch.requestId, operation: 'assign', groupId: group.id, groupName: group.name,
      policyVersion: target.version, selectedCount: 2, changedInstallations: [one.installationId, two.installationId].sort(),
    });
    assert.equal((await scoped()).length, 2);
    assert.deepEqual(await run(batch, { expect: 409 }), { code: 'fleet_request_conflict' });
    assert.deepEqual(await run({ ...batch, selections: [one] }, { token: actor.token, expect: 409 }), { code: 'fleet_request_conflict' });
    assert.deepEqual(await run(assign([one, three]), { expect: 409 }), { code: 'fleet_selection_changed' });
    assert.deepEqual(await run(batch, { token: clipboardAdmin, expect: 404 }), { code: 'fleet_target_unavailable' });
    const installed = await call('/v1/browser/policy', { token: firstBrowser.token, assignmentAware: true });
    assert.equal(installed.version, target.version);
    assert.equal(installed.assignmentVersion, 1);
    const same = await run(assign((await scoped()).map(selection)));
    assert.deepEqual(same.changedInstallations, []);
    const changes = (await admin('audit?action=browser_fleet_changed', { token: auditor.token })).entries;
    const assignment = changes.find(({ fleetChange }) => fleetChange.batchId === batch.requestId);
    assert.deepEqual(assignment.fleetChange, replay);
    assert.equal(assignment.actorAccess.id, actor.access.id);
    assert.equal(changes.length, 2);
    assert.doesNotMatch(JSON.stringify(changes), /fleet_request_hash|requestHash|tokenHash/);

    await post(`installations/${three.installationId}/policy-group`, { groupId: group.id }, { expect: 204 });
    const removal = { requestId: randomUUID(), operation: 'revoke', groupId: null, expectedPolicyVersion: null, selections: [
      { ...one, assignmentVersion: 1 }, { ...two, assignmentVersion: 1 },
    ] };
    assert.deepEqual(await run({ ...removal, selections: [removal.selections[0], three] }, { expect: 409 }), { code: 'fleet_selection_changed' });
    assert.equal((await scoped()).length, 3);
    const revoked = await run(removal);
    assert.equal(revoked.changedInstallations.length, 2);
    assert.deepEqual(await run(removal), revoked);
    for (const browser of [firstBrowser, secondBrowser]) {
      await call('/v1/browser/policy', { token: browser.token, assignmentAware: true, expect: 401 });
      await post(`installations/${browser.installationId}/revoke`, undefined, { expect: 204 });
    }
    assert.deepEqual((await scoped()).map(({ installationId }) => installationId), [three.installationId]);
    assert.equal((await admin('audit?action=browser_revoked')).entries.length, 2);
    assert.deepEqual(await run(batch, { token: actor.token }), replay);
    if (postgres) {
      await retentionFixture(`UPDATE control_audit SET occurred_at = now() - interval '2 days' WHERE id = '${assignment.id}';`);
      await post('retention', { securityEventDays: null, aiObservationDays: null, auditDays: 1 }, { expect: 204 });
      assert.deepEqual(await run(batch, { token: actor.token, expect: 409 }), { code: 'fleet_request_conflict' });
      assert.ok(!(await admin('audit?action=browser_fleet_changed')).entries.some(({ id }) => id === assignment.id));
    }

    const newBrowsers = [];
    for (let offset = 0; offset < 50; offset += 10) {
      newBrowsers.push(...await Promise.all(Array.from({ length: 10 }, () => enroll(false))));
    }
    const firstPage = await admin(`${path}?rolloutGroup=baseline`);
    assert.equal(firstPage.entries.length, 50);
    const query = new URLSearchParams({ rolloutGroup: 'baseline', beforeAt: firstPage.next.enrolledAt, beforeId: firstPage.next.installationId });
    const lastPage = await admin(`${path}?${query}`);
    assert.equal(lastPage.next, null);
    assert.deepEqual([...firstPage.entries, ...lastPage.entries].map(({ installationId }) => installationId).sort(),
      [...newBrowsers, legacy].map(({ installationId }) => installationId).sort());
  });

  await t.test('reuses immutable template revisions with scoped comparisons, pinned review, and archive safety', async () => {
    const admin = (path, options) => call(`/v1/admin/${path}`, { token: templateAdmin, ...options });
    const post = (path, body, options = {}) => admin(path, { method: 'POST', body, ...options });
    const slug = 'policy-templates';
    const initial = (await admin('policies'))[0];
    await post('policies', { mode: 'warn' });
    await post('policies', { mode: 'monitor' });
    const expiresAt = new Date(Date.now() + 3600_000).toISOString();
    const exception = (appId, reason) => ({ appId, ruleId: 'fixture-secret', reason, expiresAt });
    const source = await post('policies', { mode: 'block', clipboardMode: 'block', domainRules: { allow: [], block: ['templates.test'] },
      promptExceptions: [exception('chatgpt', 'Source-only synthetic exception')] });
    if (postgres) {
      await stop();
      await retentionFixture(undoTemplateSchema);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 43'), '1');
    }
    assert.deepEqual(await admin(slug), []);
    assert.deepEqual((await admin('policies'))[0], source);

    const create = (name, version, options) => post(slug, { name, sourceVersion: version }, options);
    await create('x', source.version, { expect: 400 });
    await create('Missing source', 100_000, { expect: 404 });
    await create('Foreign source', source.version, { token: fleetAdmin, expect: 404 });
    const template = await create(' Starter controls ', source.version);
    assert.deepEqual(await admin(slug), [template]);
    assert.equal(template.name, 'Starter controls');
    assert.equal(template.revision, 1);
    assert.deepEqual(await create('starter CONTROLS', source.version, { expect: 409 }), { code: 'template_name_exists' });
    const path = `${slug}/${template.id}`;
    const revise = (expectedRevision, sourceVersion, options) => post(`${path}/revisions`, { expectedRevision, sourceVersion }, options);
    const archive = (expectedRevision, options) => post(`${path}/archive`, { expectedRevision }, { expect: 204, ...options });
    const compare = (revision, groupId, options) => admin(`${path}/preview?${new URLSearchParams({ revision, ...(groupId && { groupId }) })}`, options);
    const apply = (revision, groupId, expectedVersion, options) => post(`${path}/apply`, { revision, groupId, expectedVersion }, options);

    const operator = await post('access', { name: 'Template author', role: 'administrator', hours: 1 });
    const reviewer = await post('access', { name: 'Template reviewer', role: 'administrator', hours: 1 });
    const auditor = await post('access', { name: 'Template auditor', role: 'auditor', hours: 1 });
    assert.equal((await admin(path, { token: auditor.token })).revisions.length, 1);
    await admin(path, { token: fleetAdmin, expect: 404 });
    await compare(1, null, { token: fleetAdmin, expect: 404 });
    await apply(1, null, 1, { token: fleetAdmin, expect: 404 });
    await revise(1, initial.version, { token: auditor.token, expect: 403 });
    await archive(1, { token: auditor.token, expect: 403 });
    await admin(`${path}/preview?revision=1&revision=2`, { expect: 400 });

    const [saved, duplicate] = await Promise.all([revise(1, initial.version), revise(1, initial.version)]);
    assert.deepEqual(saved, duplicate);
    assert.equal(saved.revision, 2);
    assert.deepEqual(await revise(1, source.version, { expect: 409 }), { code: 'template_revision_changed' });
    assert.deepEqual(await revise(2, initial.version), saved);
    assert.deepEqual((await admin(path)).revisions.map(({ revision, sourceVersion }) => [revision, sourceVersion]),
      [[2, initial.version], [1, source.version]]);

    const child = await post('policy-groups', { name: 'Template destination' });
    const canary = await post('policy-groups', { name: 'Independent template cohort' });
    const destination = `policy-groups/${child.id}/policies`;
    const before = await post(destination, { mode: 'warn', promptExceptions: [exception('gemini', 'Destination-only fixture exception')] });
    const comparison = await compare(1, child.id, { token: auditor.token });
    assert.equal(comparison.before.version, before.version);
    assert.equal(comparison.candidate.version, source.version);
    assert.equal(comparison.candidate.clipboardMode, 'block');
    assert.deepEqual(comparison.candidate.promptExceptions, before.promptExceptions);
    assert.doesNotMatch(JSON.stringify(comparison), /Source-only synthetic exception/);
    assert.equal((await compare(1, canary.id)).candidate.promptExceptions.length, 0);
    await apply(1, child.id, before.version, { token: auditor.token, expect: 403 });
    const changed = await post(destination, { mode: 'monitor' });
    assert.deepEqual(await apply(1, child.id, before.version, { expect: 409 }), { code: 'template_target_changed' });
    const applied = await apply(1, child.id, changed.version);
    assert.deepEqual(applied.promptExceptions, before.promptExceptions);
    assert.equal(applied.mode, 'block');
    assert.equal(applied.clipboardMode, 'block');
    assert.deepEqual(applied.domainRules, source.domainRules);
    await apply(1, child.id, changed.version, { expect: 409 });
    assert.equal((await admin(`policy-groups/${canary.id}/policies`)).length, 0);

    await post('policy-reviews/setting', { required: true }, { expect: 204 });
    const options = { token: operator.token, expect: 202, expectReview: true };
    const [request, retry] = await Promise.all([apply(2, canary.id, source.version, options), apply(2, canary.id, source.version, options)]);
    assert.deepEqual(request, retry);
    await apply(1, canary.id, source.version, { expect: 403 });
    assert.equal((await admin('policy-reviews')).entries.length, 1);
    const reviewed = (await admin('policy-reviews')).entries[0];
    assert.deepEqual(reviewed.snapshots.template, { templateId: template.id, name: template.name, revision: 2, sourceVersion: initial.version });
    assert.equal(reviewed.snapshots.candidate.mode, initial.mode);
    await post(`policy-reviews/${request.reviewId}/decision`, { approve: true }, { token: operator.token, expect: 403 });

    assert.equal((await revise(2, source.version)).revision, 3);
    const approved = await post(`policy-reviews/${request.reviewId}/decision`, { approve: true }, { token: reviewer.token });
    assert.equal(approved.mode, initial.mode);
    assert.deepEqual(approved.domainRules, initial.domainRules);
    assert.equal((await admin(destination))[0].version, applied.version);
    const pending = await apply(3, child.id, applied.version, options);
    await archive(2, { expect: 409 });
    await Promise.all([archive(3), archive(3)]);
    assert.deepEqual(await admin(slug), []);
    await admin(path, { expect: 404 });
    await compare(3, child.id, { expect: 404 });
    await apply(3, child.id, applied.version, { token: operator.token, expectReview: true, expect: 404 });
    await post(`policy-reviews/${pending.reviewId}/decision`, { approve: true }, { token: reviewer.token, expect: 409 });
    assert.equal((await admin('policy-reviews')).entries.find(({ id }) => id === pending.reviewId).status, 'stale');
    assert.equal((await admin(destination))[0].version, applied.version);

    const audit = (await admin('audit?action=policy_template_changed', { token: auditor.token })).entries;
    assert.deepEqual(audit.map(({ templateChange }) => templateChange.operation).sort(), ['applied', 'applied', 'archived', 'created', 'revised', 'revised']);
    const evidence = audit.find(({ templateChange }) => templateChange.publishedVersion === approved.version);
    assert.equal(evidence.templateChange.groupId, canary.id);
    assert.equal(evidence.templateChange.template.revision, 2);
    assert.equal(evidence.actorAccess.id, reviewer.access.id);
    assert.doesNotMatch(JSON.stringify(audit), /synthetic exception|Fixture exception|promptExceptions|templates\.test/);
    const replacement = await create(template.name, initial.version);
    assert.notEqual(replacement.id, template.id);
    assert.equal(replacement.revision, 1);

    await post('policy-reviews/setting', { required: false }, { expect: 204 });
    const toBaseline = await post(`${slug}/${replacement.id}/apply`,
      { revision: 1, expectedVersion: source.version });
    assert.equal(toBaseline.mode, initial.mode);
    assert.deepEqual(toBaseline.promptExceptions, source.promptExceptions);
    assert.equal((await admin('policies'))[0].version, toBaseline.version);
    assert.equal((await admin(destination))[0].version, applied.version);
    const [baselineAudit] = (await admin('audit?action=policy_template_changed')).entries;
    assert.equal(baselineAudit.templateChange.groupId, null);
    assert.equal(baselineAudit.templateChange.publishedVersion, toBaseline.version);
  });

  await t.test('versions GitHub token protection with negotiated delivery, private evidence and rollback', async () => {
    const admin = (path, options) => call(`/v1/admin/${path}`, { token: githubTokenAdmin, ...options });
    const post = (path, body, options) => admin(path, { method: 'POST', body, ...options });
    const [initial] = await admin('policies');
    const browser = await call('/v1/enroll', { method: 'POST', body: { grant: (await post('enrollment-grants')).grant } });
    const browserCall = (path, options) => call(`/v1/browser/${path}`, { token: browser.token, ...options });
    const write = (path, body, expect = 204) => browserCall(path, { method: 'POST', body, expect });
    const deliver = () => browserCall('policy', { assignmentAware: true, githubTokenAware: true, clipboardAware: true,
      fileInspectionAware: true, fileBlockAware: true });
    await write('events', { ...contract.event, eventId: randomUUID(), timestamp: new Date().toISOString(), policyVersion: initial.version });
    const originalEvents = await admin('events');
    if (postgres) {
      await stop();
      await retentionFixture(undoGithubTokenSchema);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 44'), '1');
      assert.deepEqual(await admin('events'), originalEvents);
    }
    assert.equal((await deliver()).githubTokenMode, 'off');
    await post('policies', { githubTokenMode: 'always' }, { expect: 400 });
    const ruleId = 'github-app-or-fine-grained-token';
    const warn = await post('policies', { githubTokenMode: 'warn', githubPatMode: 'off', clipboardMode: 'block',
      fileContentModes: { chatgpt: 'block' } });
    const event = (policy, fields = {}) => ({
      ...contract.event, eventId: randomUUID(), timestamp: new Date().toISOString(), policyVersion: policy.version,
      appId: 'chatgpt', ruleId, detectorCategory: 'credential', decision: 'warn', ...fields,
    });
    const heartbeat = (modeApplied) => ({ policyVersion: warn.version, githubTokenModeApplied: modeApplied,
      clipboardModeApplied: true, fileInspectionApplied: true, fileContentBlockApplied: true });
    assert.equal((await browserCall('policy', { githubTokenAware: true })).githubTokenMode, undefined);
    await write('heartbeat', { policyVersion: warn.version });
    assert.notEqual((await admin('installations'))[0].appliedPolicyVersion, warn.version);
    await write('heartbeat', heartbeat(true), 400);
    await write('events', event(warn), 400);
    assert.equal((await deliver()).githubTokenMode, 'warn');
    await write('heartbeat', heartbeat(false));
    assert.notEqual((await admin('installations'))[0].appliedPolicyVersion, warn.version);
    await write('heartbeat', heartbeat(true));
    assert.equal((await admin('installations'))[0].appliedPolicyVersion, warn.version);
    const detected = event(warn);
    await Promise.all([write('events', detected), write('events', detected)]);
    await write('events', event(warn, { decision: 'warn_override' }));
    await write('events', event(warn, { decision: 'block', clipboardPaste: true }));
    await write('events', event(warn, { decision: 'block', uploadMethod: 'picker' }));
    for (const fields of [{ decision: 'block' }, { detectorCategory: 'synthetic-secret' },
      { decision: 'exception_applied' }, { decision: 'monitor', clipboardPaste: true }, { content: 'synthetic private value' }]) {
      await write('events', event(warn, fields), 400);
    }
    const path = `events/${browser.installationId}/${detected.eventId}`;
    await admin(path, { token: templateAdmin, expect: 404 });
    const { token } = await post('access/event-feed', { name: 'Token decision collector', days: 1, requestId: randomUUID() });
    const feed = await call('/v1/integrations/events', { token });
    const exported = await admin('events/export');
    assert.equal(feed.entries.filter((entry) => entry.eventId === detected.eventId).length, 1);
    assert.equal(feed.entries.filter((entry) => entry.ruleId === ruleId).length, 4);
    assert.equal(exported.entries.filter((entry) => entry.ruleId === ruleId).length, 4);
    assert.doesNotMatch(JSON.stringify({ exported, feed }), /synthetic private value/);

    const author = await post('access', { name: 'Token policy author', role: 'administrator', hours: 1 });
    const reviewer = await post('access', { name: 'Token policy reviewer', role: 'administrator', hours: 1 });
    await post('policy-reviews/setting', { required: true }, { expect: 204 });
    const { reviewId } = await post('policies', { githubTokenMode: 'block', expectedVersion: warn.version,
      promptExceptions: [{ appId: 'chatgpt', ruleId, expiresAt: new Date(Date.now() + 3600_000).toISOString(), reason: 'Synthetic exception' }] },
      { token: author.token, expectReview: true, expect: 202 });
    const [{ snapshots }] = (await admin('policy-reviews')).entries;
    assert.equal(snapshots.candidate.githubTokenMode, 'block');
    await post(`policy-reviews/${reviewId}/decision`, { approve: true }, { token: author.token, expect: 403 });
    const block = await post(`policy-reviews/${reviewId}/decision`, { approve: true }, { token: reviewer.token });
    assert.equal((await deliver()).promptExceptionLease.grants[0].ruleId, ruleId);
    const oldBrowser = await browserCall('policy', { assignmentAware: true });
    assert.equal(oldBrowser.promptExceptionLease, undefined);
    assert.equal(oldBrowser.githubTokenMode, undefined);
    await write('events', event(block, { decision: 'exception_applied' }));
    await write('events', event(block, { decision: 'exception_applied', appId: 'gemini' }), 400);
    await post('policy-reviews/setting', { required: false }, { expect: 204 });
    const restored = await post(`policies/${initial.version}/restore`);
    assert.equal(restored.githubTokenMode, 'off');
    assert.equal((await deliver()).githubTokenMode, 'off');
    await write('events', event(restored), 400);
  });

  await t.test('captures the effective rollout audience and rejects a promotion of a stale destination', async () => {
    const admin = (path, options) => call(`/v1/admin/${path}`, { token: impactAdmin, ...options });
    const post = (path, body, options) => admin(path, { method: 'POST', body, ...options });
    const report = (query = '', options) => admin(`reports/policy-impact?${query}`, options);
    const [initial] = await admin('policies');
    const counts = (active, reporting, acknowledged, reportingAndAcknowledged) => ({ active, reporting, acknowledged, reportingAndAcknowledged });
    const scope = (group, policyVersion = initial.version, followsBaseline = false) =>
      ({ groupId: group?.id ?? null, groupName: group?.name ?? null, policyVersion, followsBaseline });
    assert.deepEqual((await report()).totals, counts(0, 0, 0, 0));
    const [follows, own, empty] = await Promise.all(['Inheriting cohort', 'Independent cohort', 'Empty cohort']
      .map((name) => post('policy-groups', { name })));
    const ownPath = `policy-groups/${own.id}`;
    const published = await post(`${ownPath}/policies`, { mode: 'warn' });
    const promote = (target, expectedVersion = published.version, options) => post(`${ownPath}/promote`,
      { expectedVersion, expectedBaselineVersion: target }, options);
    assert.equal((await admin('policy-groups')).find(({ id }) => id === own.id).baselineVersion, initial.version);
    async function enroll(group, observed) {
      const { grant } = await post('enrollment-grants');
      const browser = await call('/v1/enroll', { method: 'POST', body: { grant } });
      const browserCall = (path, options) => call(`/v1/browser/${path}`, { token: browser.token, ...options });
      const policy = () => browserCall('policy', { assignmentAware: true });
      let effective = await policy();
      if (group) {
        await post(`installations/${browser.installationId}/policy-group`, { groupId: group.id }, { expect: 204 });
        effective = await policy();
      }
      if (observed) await browserCall('heartbeat', { method: 'POST', expect: 204, composerAware: true,
        body: { policyVersion: effective.version, assignmentVersion: effective.assignmentVersion ?? 0, ...observed } });
      return browser;
    }
    const [base, inherited, stale, pending, independent, revoked] = await Promise.all([
      enroll(null, { chatGptCoverage: 'ready' }),
      enroll(follows, { chatGptCoverage: 'unsupported', geminiCoverage: 'ready' }),
      enroll(null, { chatGptCoverage: 'ready' }),
      enroll(follows),
      enroll(own, { chatGptCoverage: 'ready' }),
      enroll(follows, { chatGptCoverage: 'ready' }),
    ]);
    await post(`installations/${revoked.installationId}/revoke`, {}, { expect: 204 });
    if (postgres) {
      await retentionFixture(`
        UPDATE installations SET last_seen_at = now() - interval '3 minutes' WHERE id = '${stale.installationId}';
        INSERT INTO installations (id, organization_id, token_hash, policy_group_id, assignment_aware)
        SELECT gen_random_uuid(), organization_id, gen_random_uuid()::text, policy_group_id, true
        FROM installations CROSS JOIN generate_series(1, 101) WHERE id = '${pending.installationId}';
      `);
      assert.equal((await admin('installations')).length, 100);
    }
    const large = postgres ? 101 : 0;
    const cohort = (group, aggregate) => ({ groupId: group?.id ?? null, groupName: group?.name ?? null, counts: aggregate });
    const auditor = await post('access', { name: 'Impact auditor', role: 'auditor', hours: 1 });
    const pinned = `scope=baseline&expectedVersion=${initial.version}`;
    const baseline = await report(pinned, { token: auditor.token });
    assert.equal(baseline.schemaVersion, 1);
    assert.ok(Number.isFinite(Date.parse(baseline.asOf)));
    assert.deepEqual(baseline.scope, scope(null));
    assert.deepEqual(baseline.freshness, { heartbeatSeconds: 90, observationSeconds: 86_400 });
    assert.deepEqual(baseline.cohorts, [
      cohort(null, counts(2, postgres ? 1 : 2, 2, postgres ? 1 : 2)),
      cohort(empty, counts(0, 0, 0, 0)),
      cohort(follows, counts(2 + large, 2 + large, 1, 1)),
    ]);
    assert.deepEqual(baseline.totals, counts(4 + large, (postgres ? 3 : 4) + large, 3, postgres ? 2 : 3));
    assert.equal(baseline.outsideScope, 1);
    const onApp = (view, app) => view.composers.find(({ appId }) => appId === app).counts;
    assert.deepEqual(onApp(baseline, 'chatgpt'), { detected: postgres ? 1 : 2, unsupported: 1, stale: postgres ? 1 : 0,
      unobserved: 0, policy_pending: 1 + large, off: 0, disabled_by_admin: 0 });
    assert.equal(onApp(baseline, 'gemini').detected, 1);
    assert.equal(onApp(baseline, 'claude').off, 4 + large);
    const inheritedView = await report(`scope=${follows.id}`);
    assert.deepEqual(inheritedView.scope, scope(follows, initial.version, true));
    assert.deepEqual(inheritedView.cohorts, [baseline.cohorts[2]]);
    assert.equal(inheritedView.outsideScope, 3);
    assert.deepEqual((await report(`scope=${own.id}`)).scope, scope(own, published.version));
    assert.deepEqual((await report(`scope=${empty.id}`)).totals, counts(0, 0, 0, 0));
    const aggregate = JSON.stringify(baseline);
    for (const browser of [base, inherited, stale, pending, independent, revoked]) {
      assert.ok(!aggregate.includes(browser.installationId) && !aggregate.includes(browser.token));
    }
    await report(`scope=${own.id}`, { token: second, expect: 404 });
    await report(pinned, { token: base.token, expect: 401 });
    for (const query of ['scope=all', 'scope=', 'scope=00000000-0000-0000-0000-000000000000', 'scope=baseline&scope=baseline',
      'expectedVersion=0', 'expectedVersion=-1', 'expectedVersion=1&expectedVersion=2', 'expectedVersion=2147483648', 'organization=other']) {
      await report(query, { expect: 400 });
    }
    const revised = await post('policies', { mode: 'block' });
    assert.deepEqual(await report(pinned, { expect: 409 }), { code: 'policy_impact_stale' });
    await promote(initial.version, published.version, { expect: 409 });
    await promote(revised.version, published.version, { token: auditor.token, expect: 403 });
    assert.equal((await admin('policies'))[0].version, revised.version);
    const fresh = await report();
    assert.deepEqual(fresh.scope, scope(null, revised.version));
    assert.equal(fresh.totals.acknowledged, 0);
    assert.equal(onApp(fresh, 'chatgpt').policy_pending, 4 + large);
    const promoted = await promote(revised.version);
    assert.equal(promoted.mode, 'warn');
    await promote(revised.version, published.version, { expect: 409 });
    assert.equal((await admin(`${ownPath}/policies`))[0].version, published.version);
    assert.deepEqual((await report()).scope, scope(null, promoted.version));
    assert.equal((await admin('audit?action=policy_published')).entries.filter(({ policyVersion }) => policyVersion === promoted.version).length, 1);
  });

  await t.test('guards a previewed publish and approval with current composer evidence in the affected scope', async () => {
    const admin = (path, options) => call(`/v1/admin/${path}`, { token: composerGateAdmin, ...options });
    const post = (path, body, options) => admin(path, { method: 'POST', body, ...options });
    const initial = (await admin('policies'))[0].version;
    const gate = (expectedVersion, apps = ['chatgpt']) => ({ mode: 'block', expectedVersion, requireComposerReady: apps });
    const incomplete = { code: 'composer_coverage_incomplete' };
    const baseline = 'policies';
    const audit = async () => (await admin('audit?action=policy_published')).entries;
    assert.deepEqual(await post(baseline, gate(initial), { expect: 409 }), incomplete);
    for (const request of [gate(undefined), gate(initial, []), gate(initial, ['chatgpt', 'chatgpt']), gate(initial, ['other'])]) {
      assert.deepEqual(await post(baseline, request, { expect: 400 }), { code: 'invalid_composer_gate' });
    }
    assert.deepEqual(await audit(), []);
    const group = await post('policy-groups', { name: 'Inheriting pilot cohort' });
    const independent = await post('policy-groups', { name: 'Independent policy cohort' });
    const groupPath = `policy-groups/${group.id}/policies`;
    const ownVersion = await post(`policy-groups/${independent.id}/policies`, { mode: 'monitor' });
    async function enroll(groupId) {
      const { grant } = await post('enrollment-grants');
      const browser = await call('/v1/enroll', { method: 'POST', body: { grant } });
      browser.policy = () => call('/v1/browser/policy', { token: browser.token, assignmentAware: true });
      if (groupId) {
        await browser.policy();
        await post(`installations/${browser.installationId}/policy-group`, { groupId }, { expect: 204 });
      }
      return browser;
    }
    async function observe(browser, coverage) {
      const { version, assignmentVersion } = await browser.policy();
      await call('/v1/browser/heartbeat', { token: browser.token, method: 'POST', composerAware: true, expect: 204,
        body: { policyVersion: version, assignmentVersion: assignmentVersion ?? 0, ...coverage } });
    }
    const [base, pilot, outside, revoked] = await Promise.all([enroll(), enroll(group.id), enroll(independent.id), enroll(group.id)]);
    await post(`installations/${revoked.installationId}/revoke`, {}, { expect: 204 });
    await observe(base, { chatGptCoverage: 'ready' });
    await observe(pilot, { chatGptCoverage: 'unsupported' });
    assert.deepEqual(await post(baseline, gate(initial), { expect: 409 }), incomplete);
    await observe(pilot, { chatGptCoverage: 'ready' });
    assert.deepEqual(await post(baseline, gate(initial, ['chatgpt', 'gemini']), { expect: 409 }), incomplete);
    assert.deepEqual(await post(baseline, gate(initial, ['claude']), { expect: 409 }), incomplete);
    assert.equal((await outside.policy()).version, ownVersion.version);
    if (postgres) {
      await retentionFixture(`UPDATE composer_observations SET checked_at = now() - interval '25 hours' WHERE installation_id = '${pilot.installationId}';`);
      assert.deepEqual(await post(baseline, gate(initial), { expect: 409 }), incomplete);
      await observe(pilot, { chatGptCoverage: 'ready' });
      await retentionFixture(`UPDATE installations SET last_seen_at = now() - interval '91 seconds' WHERE id = '${pilot.installationId}';`);
      assert.deepEqual(await post(baseline, gate(initial), { expect: 409 }), incomplete);
      await observe(pilot, { chatGptCoverage: 'ready' });
      await stop();
      await retentionFixture('ALTER TABLE control_audit DROP COLUMN composer_gate; DELETE FROM schema_migrations WHERE version = 49;');
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 49'), '1');
    }
    const auditor = await post('access', { name: 'Composer auditor', role: 'auditor', hours: 1 });
    await post(baseline, gate(initial), { token: auditor.token, expect: 403 });
    const foreignAdmin = await call('/v1/admin/access', { method: 'POST', token: second,
      body: { name: 'Foreign gate reviewer', role: 'administrator', hours: 1 } });
    await call(`/v1/admin/${groupPath}`, { method: 'POST', body: gate(initial), token: foreignAdmin.token, expect: 409 });
    await Promise.all([base, pilot].map((browser) => observe(browser, { chatGptCoverage: 'ready', geminiCoverage: 'ready' })));
    const attempts = await Promise.all([1, 2].map(() => fetch(`${baseUrl}/v1/admin/policies`, {
      method: 'POST', headers: { Authorization: `Bearer ${composerGateAdmin}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(gate(initial, ['chatgpt', 'gemini'])), signal: AbortSignal.timeout(5000),
    })));
    assert.deepEqual(attempts.map(({ status }) => status).sort(), [200, 409]);
    const published = await attempts.find(({ ok }) => ok).json();
    const firstAudit = (await audit()).filter(({ policyVersion }) => policyVersion === published.version);
    assert.equal(firstAudit.length, 1);
    assert.deepEqual(firstAudit[0].composerGate, { referenceVersion: initial, apps: ['chatgpt', 'gemini'], browsers: 2 });
    assert.equal((await audit()).find(({ policyVersion }) => policyVersion === ownVersion.version).composerGate, undefined);

    const [author, reviewer] = await Promise.all(['Author', 'Reviewer'].map((name) =>
      post('access', { name: `Gate ${name}`, role: 'administrator', hours: 1 })));
    await post('policy-reviews/setting', { required: true }, { expect: 204 });
    const request = () => post(groupPath, gate(published.version, ['gemini']), { token: author.token, expect: 202 });
    await observe(pilot, { geminiCoverage: 'ready' });
    const { reviewId } = await request();
    const entry = async () => (await admin('policy-reviews')).entries.find(({ id }) => id === reviewId);
    assert.deepEqual((await entry()).snapshots.requireComposerReady, ['gemini']);
    const approve = (token, expect = 200) => post(`policy-reviews/${reviewId}/decision`, { approve: true }, { token, expect });
    await approve(author.token, 403);
    await observe(pilot, { geminiCoverage: 'unsupported' });
    assert.deepEqual(await approve(reviewer.token, 409), incomplete);
    assert.equal((await entry()).status, 'pending');
    await observe(pilot, { geminiCoverage: 'ready' });
    const approved = await approve(reviewer.token);
    assert.equal((await entry()).status, 'approved');
    const reviewAudit = (await audit()).find(({ policyVersion }) => policyVersion === approved.version);
    assert.deepEqual(reviewAudit.composerGate, { referenceVersion: published.version, apps: ['gemini'], browsers: 1 });
    assert.equal(reviewAudit.actorAccess.id, reviewer.access.id);
    const evidence = JSON.stringify([firstAudit[0], reviewAudit]);
    for (const browser of [base, pilot, outside, revoked]) {
      assert.ok(!evidence.includes(browser.installationId) && !evidence.includes(browser.token));
    }
    await approve(reviewer.token, 409);
  });

  await t.test('receives deduplicated scoped prompt review requests and verifies the separately published exception', async () => {
    const admin = (path, options) => call(`/v1/admin/${path}`, { token: promptRequestAdmin, ...options });
    const post = (path, body, options) => admin(path, { method: 'POST', body, ...options });
    const queue = (status = 'pending', options) => admin(`prompt-exception-requests?status=${status}`, options);
    const decide = (id, status, options) => post(`prompt-exception-requests/${id}/decision`, { status }, options);
    const group = await post('policy-groups', { name: 'Request cohort' });
    const baseline = await post('policies', { mode: 'block', clipboardMode: 'block', uploadModes: { chatgpt: 'block' } });
    const browser = await call('/v1/enroll', { method: 'POST', body: { grant: (await post('enrollment-grants')).grant } });
    const other = await call('/v1/enroll', { method: 'POST', body: { grant: (await post('enrollment-grants')).grant } });
    const deliver = () => call('/v1/browser/policy', { token: browser.token, assignmentAware: true, clipboardAware: true });
    await deliver();
    await post(`installations/${browser.installationId}/policy-group`, { groupId: group.id }, { expect: 204 });
    const policy = await deliver();
    const newEvent = (fields = {}) => ({ ...contract.event, eventId: randomUUID(), appId: 'chatgpt', decision: 'block',
      timestamp: new Date().toISOString(), policyVersion: baseline.version, assignmentVersion: policy.assignmentVersion, ...fields });
    const emit = async (body) => {
      await call('/v1/browser/events', { token: browser.token, method: 'POST', body, expect: 204 });
      return body;
    };
    const submit = ({ eventId, appId }, options) => call('/v1/browser/prompt-exception-requests',
      { token: browser.token, method: 'POST', body: { eventId, appId }, ...options });
    const [first, secondEvent] = await Promise.all([emit(newEvent()), emit(newEvent())]);
    if (postgres) {
      await stop();
      await retentionFixture(undoPromptRequestSchema);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 45'), '1');
      assert.equal((await admin('events')).length, 2);
    }
    assert.deepEqual(await queue(), []);
    await submit(newEvent(), { expect: 404 });
    await submit({ ...first, appId: 'gemini' }, { expect: 404 });
    await submit(first, { token: other.token, expect: 404 });
    await submit(first, { token: promptRequestAdmin, expect: 401 });
    await submit(first, { body: { ...first, prompt: 'private placeholder' }, expect: 400 });
    await submit(await emit(newEvent({ clipboardPaste: true })), { expect: 404 });
    await submit(await emit(newEvent({ ruleId: 'ai-file-upload', detectorCategory: 'file-upload', uploadMethod: 'picker' })), { expect: 404 });
    await submit(await emit(newEvent({ timestamp: new Date(Date.now() - 7200_000).toISOString() })), { expect: 404 });
    const [receipt, duplicate] = await Promise.all([submit(first), submit(secondEvent)]);
    assert.deepEqual(receipt, duplicate);
    assert.deepEqual(await submit(first), receipt);
    const auditor = await post('access', { name: 'Prompt request auditor', role: 'auditor', hours: 1 });
    const [entry] = await queue('pending', { token: auditor.token });
    assert.equal(entry.id, receipt.id);
    assert.equal(entry.groupId, group.id);
    assert.equal(entry.appId, 'chatgpt');
    assert.equal(entry.ruleId, 'fixture-secret');
    assert.equal(entry.policyVersion, baseline.version);
    assert.equal(entry.status, 'pending');
    assert.doesNotMatch(JSON.stringify(entry), /private placeholder|promptText|token/);
    assert.deepEqual(await queue('pending', { token: impactAdmin }), []);
    await decide(receipt.id, 'declined', { token: impactAdmin, expect: 404 });
    await decide(receipt.id, 'declined', { token: auditor.token, expect: 403 });
    await decide(receipt.id, 'accept', { expect: 400 });
    for (const query of ['status=open', 'status=pending&status=decided', 'organization=other']) {
      await admin(`prompt-exception-requests?${query}`, { expect: 400 });
    }
    assert.deepEqual(await decide(receipt.id, 'exception_available', { expect: 409 }), { code: 'prompt_request_exception_required' });
    const exceptions = [{ appId: 'chatgpt', ruleId: 'fixture-secret', expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      reason: 'Reviewed work request' }];
    await post('policies', { promptExceptions: exceptions });
    await submit(first, { expect: 404 });
    assert.deepEqual(await decide(receipt.id, 'exception_available', { expect: 409 }), { code: 'prompt_request_exception_required' });
    const author = await post('access', { name: 'Request exception author', role: 'administrator', hours: 1 });
    const reviewer = await post('access', { name: 'Request exception reviewer', role: 'administrator', hours: 1 });
    await post('policy-reviews/setting', { required: true }, { expect: 204 });
    const path = `policy-groups/${group.id}/policies`;
    const { reviewId } = await post(path, { promptExceptions: exceptions }, { token: author.token, expectReview: true, expect: 202 });
    await decide(receipt.id, 'exception_available', { expect: 409 });
    const published = await post(`policy-reviews/${reviewId}/decision`, { approve: true }, { token: reviewer.token });
    const accepted = await decide(receipt.id, 'exception_available', { token: reviewer.token });
    assert.deepEqual(await decide(receipt.id, 'exception_available'), accepted);
    assert.deepEqual(await decide(receipt.id, 'declined', { expect: 409 }), { code: 'prompt_request_decided' });
    const [completed] = await queue('decided');
    assert.equal(completed.publishedVersion, published.version);
    assert.equal(completed.decidedBy, reviewer.access.name);
    const renewed = await deliver();
    const deniedEvent = await emit(newEvent({ policyVersion: renewed.version, appId: 'gemini' }));
    const rejected = await submit(deniedEvent);
    await post(`installations/${browser.installationId}/policy-group`, { groupId: null }, { expect: 204 });
    assert.deepEqual(await decide(rejected.id, 'exception_available', { expect: 409 }), { code: 'prompt_request_assignment_changed' });
    await decide(rejected.id, 'declined');
    assert.deepEqual(await queue(), []);
    if (postgres) {
      await post('retention', { securityEventDays: 1, aiObservationDays: null, auditDays: null }, { expect: 204 });
      await retentionFixture(`UPDATE security_events SET occurred_at = now() - interval '2 days'
        WHERE installation_id = '${browser.installationId}';`);
      assert.deepEqual(await queue('decided'), []);
      await post('retention/cleanup', {});
      assert.equal(await retentionFixture(`SELECT count(*) FROM prompt_exception_requests WHERE installation_id = '${browser.installationId}'`), '0');
    }
  });

  await t.test('keeps extension changes atomic, bounded, and scoped to continuous inventory reporting', async () => {
    const admin = (path, options) => call(`/v1/admin/${path}`, { token: inventoryChangesAdmin, ...options });
    const post = (path, body, expect = 200) => admin(path, { method: 'POST', body, expect });
    const browser = await call('/v1/enroll', { method: 'POST', body: { grant: (await post('enrollment-grants')).grant } });
    const path = `extension-inventory/${browser.installationId}`;
    const group = await post('policy-groups', { name: 'Extension changes pilot' });
    const groupPolicies = `policy-groups/${group.id}/policies`;
    await call('/v1/browser/policy', { token: browser.token, assignmentAware: true });
    await post(`installations/${browser.installationId}/policy-group`, { groupId: group.id }, 204);
    let policy = await post('policies', { extensionInventoryEnabled: true });
    let assignmentVersion = 1;
    const history = async (options) => (await admin(path, options)).changeHistory;
    const entry = { id: 'b'.repeat(32), name: 'Private review fixture name', version: '1.0', enabled: true,
      installType: 'normal', siteAccess: 'selected', permissions: ['tabs', 'cookies'] };
    const secondEntry = { ...entry, id: 'c'.repeat(32), name: 'Second private review fixture', permissions: [] };
    let timestamp = Date.now() - 5000;
    const snapshot = (entries, options) => ({ entries, policyVersion: policy.version, assignmentVersion,
      capturedAt: new Date(timestamp++).toISOString(), omitted: 0, status: 'reported', ...options });
    const report = (body, expect = 204) => call('/v1/browser/extension-inventory', { method: 'POST', token: browser.token, body, expect });
    const count = () => retentionFixture(`SELECT count(*) FROM extension_inventory_change_batches WHERE installation_id = '${browser.installationId}'`);
    await report(snapshot([entry]));
    assert.deepEqual(await history(), []);
    if (postgres) {
      await stop();
      await retentionFixture(`${undoExtensionAccessAlertsSchema}
        DELETE FROM schema_migrations WHERE version = 47;
        DROP TABLE extension_inventory_change_batches;`);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 47'), '1');
      assert.deepEqual((await admin(path)).entries, [entry]);
    }
    const renamed = { ...entry, name: 'Updated private fixture name', permissions: ['cookies', 'tabs'] };
    await report(snapshot([renamed]));
    assert.deepEqual(await history(), []);
    const upgraded = { ...renamed, version: '2.0', siteAccess: 'all', permissions: ['tabs', 'debugger', 'cookies'] };
    const update = snapshot([upgraded, secondEntry]);
    if (postgres) {
      await retentionFixture(`
        CREATE FUNCTION test_reject_inventory_changes() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'Synthetic history write failure'; END; $$;
        CREATE TRIGGER test_reject_inventory_changes BEFORE INSERT ON extension_inventory_change_batches
        FOR EACH ROW EXECUTE FUNCTION test_reject_inventory_changes();
      `);
      try {
        const failed = await fetch(`${baseUrl}/v1/browser/extension-inventory`, {
          method: 'POST', headers: { Authorization: `Bearer ${browser.token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify(update), signal: AbortSignal.timeout(5000),
        });
        assert.equal(failed.status, 500);
        assert.deepEqual((await admin(path)).entries, [renamed]);
        assert.deepEqual(await history(), []);
      } finally {
        await retentionFixture(`DROP TRIGGER test_reject_inventory_changes ON extension_inventory_change_batches;
          DROP FUNCTION test_reject_inventory_changes();`);
      }
    }
    await Promise.all([report(update), report(update)]);
    const [batch] = await history();
    assert.equal((await history()).length, 1);
    assert.equal(batch.policyVersion, policy.version);
    assert.equal(batch.changes.length, 2);
    const previous = { version: '1.0', enabled: true, installType: 'normal', siteAccess: 'selected', permissions: ['cookies', 'tabs'] };
    assert.deepEqual(batch.changes[0], { extensionId: entry.id, before: previous, after: { ...previous,
      version: '2.0', siteAccess: 'all', permissions: ['cookies', 'debugger', 'tabs'] }, reviewAccess: true });
    assert.equal(batch.changes[1].before, null);
    assert.doesNotMatch(JSON.stringify(batch), /private fixture|Private review|second private|"name"|hostPermissions/i);
    await report({ ...update, entries: [entry] });
    assert.deepEqual(await history(), [batch]);
    const auditor = await post('access', { name: 'Inventory auditor', role: 'auditor', hours: 1 });
    assert.deepEqual(await history({ token: auditor.token }), [batch]);
    await admin(path, { token: first, expect: 404 });
    await admin(path, { token: browser.token, expect: 401 });
    assert.equal((await admin('extension-inventory'))[0].changeHistory, undefined);

    await report(snapshot([{ ...upgraded, enabled: false }], { omitted: 3 }));
    assert.deepEqual((await history())[0].changes.map(({ extensionId }) => extensionId), [entry.id]);
    await report(snapshot([upgraded, secondEntry]));
    assert.deepEqual((await history())[0].changes.map(({ extensionId }) => extensionId), [entry.id]);
    await report(snapshot([upgraded]));
    assert.deepEqual((await history())[0].changes.map(({ extensionId, after }) => [extensionId, after]), [[secondEntry.id, null]]);
    const countBeforeGap = (await history()).length;
    await report(snapshot([], { status: 'permission_required' }));
    await report(snapshot([entry]));
    assert.equal((await history()).length, countBeforeGap);

    policy = await post('policies', { mode: 'warn' });
    await report(snapshot([upgraded]));
    assert.equal((await history())[0].policyVersion, policy.version);
    policy = await post(groupPolicies, { extensionInventoryEnabled: true });
    const baselineOff = await post('policies', { extensionInventoryEnabled: false });
    await report(snapshot([entry], { policyVersion: baselineOff.version }), 409);
    await report(snapshot([entry]));
    assert.equal((await history())[0].policyVersion, policy.version);

    await post(groupPolicies, { extensionInventoryEnabled: false });
    assert.equal(await history(), undefined);
    policy = await post(groupPolicies, { extensionInventoryEnabled: true });
    assert.deepEqual(await history(), []);
    await report(snapshot([upgraded]));
    assert.deepEqual(await history(), []);
    for (let attempt = 0; attempt < 23; attempt++) {
      await report(snapshot([{ ...entry, version: `3.${attempt}` }]));
    }
    assert.equal((await history()).length, 20);
    assert.equal((await history())[0].changes[0].after.version, '3.22');
    if (postgres) {
      assert.equal(await count(), '20');
      await retentionFixture(`UPDATE extension_inventory_change_batches SET received_at = now() - interval '31 days'
        WHERE installation_id = '${browser.installationId}'`);
      assert.deepEqual(await history(), []);
      await stop();
      await start();
      for (let attempt = 0; await count() !== '0' && attempt < 20; attempt++) await delay(50);
      assert.equal(await count(), '0');
    }
    await report(snapshot([entry]));
    assert.equal((await history()).length, 1);
    policy = await post('policies', { extensionInventoryEnabled: true });
    await post(`installations/${browser.installationId}/policy-group`, { groupId: null }, 204);
    assignmentVersion++;
    assert.deepEqual(await history(), []);
    await report(snapshot([upgraded]));
    assert.deepEqual(await history(), []);
    await report(snapshot([entry]));
    assert.equal((await history()).length, 1);
    const revoke = () => post(`installations/${browser.installationId}/revoke`, {}, 204);
    if (postgres) {
      await retentionFixture(`
        CREATE FUNCTION test_hold_inventory_changes() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN PERFORM pg_sleep(0.6); RETURN NEW; END; $$;
        CREATE TRIGGER test_hold_inventory_changes BEFORE INSERT ON extension_inventory_change_batches
        FOR EACH ROW EXECUTE FUNCTION test_hold_inventory_changes();
      `);
      try {
        const accepted = report(snapshot([upgraded])).then(() => null, (error) => error);
        const waitingForReport = () => retentionFixture(`SELECT count(*) FROM pg_stat_activity
          WHERE datname = current_database() AND wait_event = 'PgSleep' AND query LIKE '%extension_inventory_change_batches%'`);
        for (let attempt = 0; await waitingForReport() === '0' && attempt < 20; attempt++) await delay(25);
        assert.equal(await waitingForReport(), '1');
        await revoke();
        assert.equal(await accepted, null);
      } finally {
        await retentionFixture(`DROP TRIGGER test_hold_inventory_changes ON extension_inventory_change_batches;
          DROP FUNCTION test_hold_inventory_changes();`);
      }
    } else await revoke();
    await admin(path, { expect: 404 });
    if (postgres) assert.equal(await count(), '0');
  });

  await t.test('opens opt-in extension access alerts once and audits review inside the reporting scope', async () => {
    const admin = (path, options) => call(`/v1/admin/${path}`, { token: extensionAlertsAdmin, ...options });
    const post = (path, body, options) => admin(path, { method: 'POST', body, ...options });
    const root = 'alerts/extensions';
    const settings = `${root}/settings`;
    const [reviewer, auditor] = await Promise.all(['administrator', 'auditor'].map((role) =>
      post('access', { name: `Extension alert ${role}`, role, hours: 1 })));
    const configure = (enabled, expectedRevision, options) => post(settings, { enabled, expectedRevision }, { token: reviewer.token, ...options });
    assert.deepEqual(await admin(settings), { enabled: false, revision: 0 });
    const aiSettings = await post('alerts/settings', { enabled: true, threshold: 4, expectedRevision: 0 });
    const baseline = await post('policies', { extensionInventoryEnabled: true });
    const browser = await call('/v1/enroll', { method: 'POST', body: { grant: (await post('enrollment-grants')).grant } });
    const browserPolicy = () => call('/v1/browser/policy', { token: browser.token, assignmentAware: true });
    await browserPolicy();
    const inventory = () => admin(`extension-inventory/${browser.installationId}`);
    const report = (body, expect = 204) => call('/v1/browser/extension-inventory', { method: 'POST', token: browser.token, body, expect });
    const core = { name: 'Private test extension title', version: '1.0', enabled: true, installType: 'normal',
      siteAccess: 'none', permissions: [] };
    const extensions = ['a', 'b', 'c'].map((letter) => ({ ...core, id: letter.repeat(32) }));
    let time = Date.now() - 1500;
    const snapshot = (entries, fields) => ({ policyVersion: baseline.version, assignmentVersion: 0, status: 'reported',
      omitted: 0, entries, capturedAt: new Date(time++).toISOString(), ...fields });
    await report(snapshot(extensions));
    const [entry, other, harmless] = extensions;
    const broad = { ...entry, siteAccess: 'all' };
    await report(snapshot([broad, other, harmless]));
    assert.equal((await inventory()).changeHistory[0].changes[0].reviewAccess, true);
    assert.deepEqual((await admin(root)).entries, []);
    if (postgres) {
      await stop();
      await retentionFixture(`${undoExtensionAccessAlertsSchema}
        UPDATE extension_inventory_change_batches SET changes =
          (SELECT jsonb_agg(change - 'reviewAccess') FROM jsonb_array_elements(changes) change)
        WHERE installation_id = '${browser.installationId}';`);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 48'), '1');
      assert.equal((await inventory()).changeHistory[0].changes[0].reviewAccess, true);
      assert.deepEqual((await admin(root)).entries, []);
    }
    await configure(true, 0, { token: auditor.token, expect: 403 });
    await configure(true, -1, { expect: 400 });
    const enabled = await Promise.all([configure(true, 0), configure(true, 0)]);
    assert.deepEqual(enabled, [{ enabled: true, revision: 1 }, { enabled: true, revision: 1 }]);
    await configure(false, 0, { expect: 409 });
    assert.deepEqual(await admin('alerts/settings'), aiSettings);
    assert.deepEqual((await admin(root)).entries, []);

    await report(snapshot([{ ...broad, version: '1.1' }, other, harmless]));
    await report(snapshot([entry, other, harmless]));
    assert.deepEqual((await admin(root)).entries, []);
    const elevated = { ...other, permissions: ['debugger'] };
    const candidate = snapshot([{ ...entry, siteAccess: 'selected' }, elevated, { ...harmless, version: '2.0' }], { omitted: 1 });
    await Promise.all([report(candidate), report(candidate)]);
    await report({ ...candidate, capturedAt: new Date(time - 3).toISOString() });
    const opened = (await admin(`${root}?status=open`)).entries;
    assert.equal(opened.length, 1);
    const [alert] = opened;
    assert.equal(alert.changeCount, 2);
    assert.deepEqual([alert.installationId, alert.groupName, alert.policyVersion], [browser.installationId, null, baseline.version]);
    const detailPath = `${root}/${alert.id}`;
    const detail = await admin(detailPath, { token: auditor.token });
    assert.deepEqual(detail.changes.map(({ extensionId, reviewAccess }) => [extensionId, reviewAccess]), [[entry.id, true], [other.id, true]]);
    assert.doesNotMatch(JSON.stringify(detail), /Private test extension title|hostPermissions|"name"/);
    await admin(detailPath, { token: first, expect: 404 });
    await admin(detailPath, { token: browser.token, expect: 401 });
    assert.deepEqual((await admin(root, { token: first })).entries, []);
    assert.deepEqual((await admin(`${root}?${new URLSearchParams({ beforeAt: alert.triggeredAt, beforeId: alert.id })}`)).entries, []);
    for (const invalid of ['status=all', 'beforeId=' + alert.id, 'appId=chatgpt', 'status=open&status=acknowledged']) {
      await admin(`${root}?${invalid}`, { expect: 400 });
    }
    const acknowledge = (options) => post(`${detailPath}/acknowledge`, {}, { token: reviewer.token, expect: 204, ...options });
    await acknowledge({ token: auditor.token, expect: 403 });
    await Promise.all([acknowledge(), acknowledge()]);
    assert.deepEqual((await admin(`${root}?status=open`)).entries, []);
    assert.equal((await admin(`${root}?status=acknowledged`)).entries[0].id, alert.id);
    assert.ok((await admin(detailPath)).alert.acknowledgedAt);
    await configure(false, 1);
    await report(snapshot([entry, { ...elevated, installType: 'sideload' }, harmless]));
    assert.equal((await admin(root)).entries.length, 1);
    await configure(true, 2);
    await report(snapshot([entry, elevated, harmless]));
    await report(snapshot([broad, elevated, harmless]));
    const [latest] = (await admin(`${root}?status=open`)).entries;
    assert.ok(latest && latest.id !== alert.id);
    if (postgres) {
      await retentionFixture(`UPDATE extension_inventory_change_batches SET received_at = now() - interval '31 days'
        WHERE alert_id = '${latest.id}'`);
      await admin(`${root}/${latest.id}`, { expect: 404 });
    }
    const group = await post('policy-groups', { name: 'Extension alert scope' });
    await post(`installations/${browser.installationId}/policy-group`, { groupId: group.id }, { expect: 204 });
    await admin(detailPath, { expect: 404 });
    await acknowledge({ expect: 404 });
    const assigned = await browserPolicy();
    const scoped = (entries) => snapshot(entries, { policyVersion: assigned.version, assignmentVersion: assigned.assignmentVersion });
    await report(scoped([entry, other, harmless]));
    await report(scoped([broad, elevated, harmless]));
    const [scopedAlert] = (await admin(root)).entries;
    assert.equal(scopedAlert.groupName, group.name);
    await post('policies', { extensionInventoryEnabled: false });
    assert.deepEqual((await admin(root)).entries, []);
    await admin(`${root}/${scopedAlert.id}`, { expect: 404 });
    const audit = await admin('audit?limit=100');
    const recorded = audit.entries.filter(({ securityAlertChange }) => securityAlertChange?.extensionAccess === true);
    assert.equal(recorded.filter(({ action }) => action === 'security_alert_settings_changed').length, 3);
    assert.deepEqual(recorded.filter(({ action }) => action === 'security_alert_acknowledged').map((entry) =>
      [entry.securityAlertChange.alertId, entry.actorAccess.id]), [[alert.id, reviewer.access.id]]);
    assert.doesNotMatch(JSON.stringify(recorded), /Private test extension title|debugger|hostPermissions/);
  });

  await t.test('versions per-app prompt actions and verifies delivery, event modes and scoped exception behavior', async () => {
    const admin = (path, options) => call(`/v1/admin/${path}`, { token: promptAppModesAdmin, ...options });
    const post = (path, body, options) => admin(path, { method: 'POST', body, ...options });
    const [initial] = await admin('policies');
    const baseline = (body, options) => post('policies', body, options);
    assert.deepEqual(initial.promptAppModes, {});
    if (postgres) {
      await stop();
      await retentionFixture(undoPromptAppModesSchema);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 46'), '1');
      assert.deepEqual((await admin('policies'))[0], initial);
    }
    for (const promptAppModes of [{ chatgpt: 'off' }, { copilot: 'block' }, { gemini: 'BLOCK' }, ['block'], { claude: 42 }]) {
      await baseline({ promptAppModes }, { expect: 400 });
    }
    const browser = await call('/v1/enroll', { method: 'POST', body: { grant: (await post('enrollment-grants')).grant } });
    const browserCall = (route, options) => call(`/v1/browser/${route}`, { token: browser.token, ...options });
    const write = (route, body, expect = 204) => browserCall(route, { method: 'POST', body, expect });
    const caps = { assignmentAware: true, claudeAware: true, privateKeyAware: true, clipboardAware: true,
      fileInspectionAware: true, fileBlockAware: true };
    const deliver = () => browserCall('policy', { ...caps, promptAppModesAware: true });
    const modes = { chatgpt: 'block', gemini: 'warn', claude: 'monitor' };
    const [author, reviewer] = await Promise.all(['App mode author', 'App mode reviewer']
      .map((name) => post('access', { name, role: 'administrator', hours: 1 })));
    await post('policy-reviews/setting', { required: true }, { expect: 204 });
    const lease = { appId: 'gemini', ruleId: 'pem-private-key', expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      reason: 'Synthetic scope exception' };
    const { reviewId } = await baseline({ promptAppModes: modes, claudePromptEnabled: true, privateKeyMode: 'monitor',
      clipboardMode: 'monitor', fileContentModes: { chatgpt: 'block' }, promptExceptions: [lease] },
      { token: author.token, expectReview: true, expect: 202 });
    assert.deepEqual((await deliver()).promptAppModes, {});
    const [{ snapshots }] = (await admin('policy-reviews')).entries;
    assert.deepEqual(snapshots.candidate.promptAppModes, modes);
    const current = await post(`policy-reviews/${reviewId}/decision`, { approve: true }, { token: reviewer.token });

    const event = (appId, decision, fields = {}) => ({ ...contract.event, eventId: randomUUID(), appId, decision,
      policyVersion: current.version, timestamp: new Date().toISOString(), ...fields });
    const heartbeat = { policyVersion: current.version, claudePromptApplied: true, privateKeyModeApplied: true,
      clipboardModeApplied: true, fileInspectionApplied: true, fileContentBlockApplied: true, promptExceptionsApplied: true };
    const legacy = await browserCall('policy', caps);
    assert.equal(legacy.promptAppModes, undefined);
    assert.equal(legacy.promptExceptionLease, undefined);
    await write('heartbeat', heartbeat);
    assert.notEqual((await admin('installations'))[0].appliedPolicyVersion, current.version);
    await write('heartbeat', { ...heartbeat, promptAppModesApplied: true }, 400);
    await write('events', event('chatgpt', 'monitor'), 400);
    await write('events', event('chatgpt', 'block'), 400);
    const delivered = await deliver();
    assert.deepEqual(delivered.promptAppModes, modes);
    assert.equal(delivered.promptExceptionLease.grants[0].ruleId, lease.ruleId);
    await write('heartbeat', { ...heartbeat, promptAppModesApplied: true });
    assert.equal((await admin('installations'))[0].appliedPolicyVersion, current.version);
    const detected = event('chatgpt', 'block');
    await Promise.all([write('events', detected), write('events', detected)]);
    await write('events', event('gemini', 'warn'));
    await write('events', event('gemini', 'warn_override'));
    await write('events', event('claude', 'monitor'));
    await write('events', event('gemini', 'exception_applied', { ruleId: 'pem-private-key', detectorCategory: 'credential' }));
    await write('events', event('chatgpt', 'monitor', { clipboardPaste: true }));
    await write('events', event('chatgpt', 'block', { uploadMethod: 'picker' }));
    for (const incorrect of [event('chatgpt', 'warn'), event('gemini', 'block'), event('claude', 'warn'),
      event('chatgpt', 'block', { clipboardPaste: true }), event('chatgpt', 'block', { ruleId: 'github-classic-pat', detectorCategory: 'credential' }),
      event('chatgpt', 'exception_applied', { ruleId: 'pem-private-key', detectorCategory: 'credential' })]) {
      await write('events', incorrect, 400);
    }
    assert.equal((await admin('events')).length, 7);
    const receipt = await browserCall('prompt-exception-requests', { method: 'POST',
      body: { eventId: detected.eventId, appId: 'chatgpt' } });
    const group = await post('policy-groups', { name: 'Scoped prompt modes' });
    await post('policy-reviews/setting', { required: false }, { expect: 204 });
    const path = `policy-groups/${group.id}/policies`;
    const scoped = await post(path, { promptAppModes: { chatgpt: 'monitor', gemini: null } });
    assert.deepEqual(scoped.promptAppModes, { chatgpt: 'monitor' });
    assert.deepEqual((await admin('policies'))[0].promptAppModes, modes);
    const cleared = await post(path, { promptAppModes: {} });
    assert.deepEqual(cleared.promptAppModes, {});
    assert.deepEqual((await post(`${path}/${scoped.version}/restore`)).promptAppModes, scoped.promptAppModes);
    const reset = await post(`policies/${initial.version}/restore`);
    assert.deepEqual(reset.promptAppModes, {});
    assert.deepEqual((await deliver()).promptAppModes, {});
    const decisionPath = `prompt-exception-requests/${receipt.id}/decision`;
    await post(decisionPath, { status: 'exception_available' }, { expect: 409 });
    await post(decisionPath, { status: 'declined' });
  });

  await t.test('versions cloud credential and classification rules with negotiated delivery and metadata-only evidence', async () => {
    const admin = (path, options) => call(`/v1/admin/${path}`, { token: detectionRulesAdmin, ...options });
    const post = (path, body, options) => admin(path, { method: 'POST', body, ...options });
    const [initial] = await admin('policies');
    assert.equal(initial.cloudCredentialMode, 'off');
    assert.deepEqual(initial.classificationProtection, { mode: 'off', terms: [] });
    if (postgres) {
      await stop();
      await retentionFixture(undoDetectionRulesSchema);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 51'), '1');
      assert.deepEqual((await admin('policies'))[0], initial);
    }
    await post('policies', { cloudCredentialMode: 'always' }, { expect: 400 });
    for (const terms of [['ab'], ['Bluebird', 'BLUEBIRD'], ['(secret|.*)'], ['x'.repeat(65)], ['Ünïcode label'], [null], 'Bluebird',
      Array.from({ length: 17 }, (_, index) => `Label ${index}`)]) {
      await post('policies', { classificationProtection: { mode: 'block', terms } }, { expect: 400 });
    }
    await post('policies', { classificationProtection: { mode: 'warn', terms: [] } }, { expect: 400 });
    await post('policies', { classificationProtection: { mode: 'on', terms: ['Project Bluebird'] } }, { expect: 400 });
    await post('policies', { promptExceptions: [{ appId: 'chatgpt', ruleId: 'aws-access-key-id',
      expiresAt: new Date(Date.now() + 3600_000).toISOString(), reason: 'Synthetic exception' }] }, { expect: 400 });

    const browser = await call('/v1/enroll', { method: 'POST', body: { grant: (await post('enrollment-grants')).grant } });
    const browserCall = (route, options) => call(`/v1/browser/${route}`, { token: browser.token, ...options });
    const write = (route, body, expect = 204) => browserCall(route, { method: 'POST', body, expect });
    const caps = { assignmentAware: true, clipboardAware: true, fileInspectionAware: true, fileBlockAware: true };
    const deliver = () => browserCall('policy', { ...caps, detectionRulesAware: true });
    const policy = await post('policies', { cloudCredentialMode: 'block', clipboardMode: 'block', fileContentModes: { chatgpt: 'block' },
      classificationProtection: { mode: 'warn', terms: ['  project   bluebird ', 'CONFIDENTIAL – INTERNAL'] } });
    assert.equal(policy.cloudCredentialMode, 'block');
    assert.deepEqual(policy.classificationProtection, { mode: 'warn', terms: ['CONFIDENTIAL – INTERNAL', 'project bluebird'] });
    const event = (ruleId, detectorCategory, decision, fields = {}) => ({ ...contract.event, eventId: randomUUID(), appId: 'chatgpt',
      timestamp: new Date().toISOString(), policyVersion: policy.version, ruleId, detectorCategory, decision, ...fields });
    const heartbeat = { policyVersion: policy.version, clipboardModeApplied: true, fileInspectionApplied: true, fileContentBlockApplied: true };
    const legacy = await browserCall('policy', caps);
    assert.equal(legacy.cloudCredentialMode, undefined);
    assert.equal(legacy.classificationProtection, undefined);
    assert.equal((await browserCall('policy', { detectionRulesAware: true })).cloudCredentialMode, undefined, 'requires assignment awareness');
    await write('heartbeat', heartbeat);
    assert.notEqual((await admin('installations'))[0].appliedPolicyVersion, policy.version);
    await write('heartbeat', { ...heartbeat, cloudCredentialModeApplied: true, classificationApplied: true }, 400);
    await write('events', event('aws-access-key-id', 'credential', 'block'), 400);
    const delivered = await deliver();
    assert.equal(delivered.cloudCredentialMode, 'block');
    assert.deepEqual(delivered.classificationProtection, policy.classificationProtection);
    await write('heartbeat', { ...heartbeat, cloudCredentialModeApplied: true });
    assert.notEqual((await admin('installations'))[0].appliedPolicyVersion, policy.version);
    await write('heartbeat', { ...heartbeat, cloudCredentialModeApplied: true, classificationApplied: true });
    assert.equal((await admin('installations'))[0].appliedPolicyVersion, policy.version);

    const detected = event('aws-access-key-id', 'credential', 'block');
    await Promise.all([write('events', detected), write('events', detected)]);
    for (const ruleId of ['slack-token', 'stripe-live-secret-key', 'google-api-key', 'openai-api-key', 'anthropic-api-key']) {
      await write('events', event(ruleId, 'credential', 'block'));
    }
    await write('events', event('organization-classification-rule', 'classification', 'warn'));
    await write('events', event('organization-classification-rule', 'classification', 'warn_override'));
    await write('events', event('slack-token', 'credential', 'block', { clipboardPaste: true }));
    await write('events', event('organization-classification-rule', 'classification', 'block', { uploadMethod: 'picker' }));
    for (const incorrect of [event('aws-access-key-id', 'credential', 'warn'), event('aws-access-key-id', 'classification', 'block'),
      event('organization-classification-rule', 'credential', 'warn'), event('organization-classification-rule', 'classification', 'block'),
      event('aws-access-key-id', 'credential', 'exception_applied'), event('organization-classification-rule', 'classification', 'exception_applied'),
      event('azure-storage-key', 'credential', 'block'), event('aws-access-key-id', 'credential', 'block', { content: 'synthetic private value' })]) {
      await write('events', incorrect, 400);
    }
    await browserCall('prompt-exception-requests', { method: 'POST', body: { eventId: detected.eventId, appId: 'chatgpt' }, expect: 404 });
    const exported = await admin('events/export');
    const rules = exported.entries.map(({ ruleId, detectorCategory }) => `${ruleId}/${detectorCategory}`).sort();
    assert.deepEqual(rules, ['anthropic-api-key/credential', 'aws-access-key-id/credential', 'google-api-key/credential',
      'openai-api-key/credential', 'organization-classification-rule/classification', 'organization-classification-rule/classification',
      'organization-classification-rule/classification', 'slack-token/credential', 'slack-token/credential', 'stripe-live-secret-key/credential']);
    assert.doesNotMatch(JSON.stringify(exported), /synthetic private value/);

    const group = await post('policy-groups', { name: 'Detection pilot' });
    const scoped = await post(`policy-groups/${group.id}/policies`, { classificationProtection: { mode: 'block', terms: ['Restricted Distribution'] } });
    assert.deepEqual(scoped.classificationProtection, { mode: 'block', terms: ['Restricted Distribution'] });
    assert.deepEqual((await admin('policies'))[0].classificationProtection, policy.classificationProtection);
    const restored = await post(`policies/${initial.version}/restore`);
    assert.equal(restored.cloudCredentialMode, 'off');
    assert.deepEqual(restored.classificationProtection, { mode: 'off', terms: [] });
    assert.equal((await deliver()).cloudCredentialMode, 'off');
    await write('events', event('aws-access-key-id', 'credential', 'block', { policyVersion: restored.version }), 400);
  });

  await t.test('versions health identifier rules with negotiated delivery and metadata-only evidence', async () => {
    const admin = (path, options) => call(`/v1/admin/${path}`, { token: healthAdmin, ...options });
    const post = (path, body, options) => admin(path, { method: 'POST', body, ...options });
    const [initial] = await admin('policies');
    assert.deepEqual(initial.healthProtection, { mode: 'off', recordFormats: [] });
    if (postgres) {
      await stop();
      await retentionFixture(undoHealthSchema);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 58'), '1');
      assert.deepEqual((await admin('policies'))[0], initial);
    }
    for (const healthProtection of [{ mode: 'always', recordFormats: [] }, { mode: 'block' }, { mode: 'block', recordFormats: null },
      { mode: 'block', recordFormats: [{ prefix: 'MRN', digits: 8 }] }, { mode: 'block', recordFormats: [{ prefix: 'MRN-', digits: 3 }] },
      { mode: 'block', recordFormats: [{ prefix: 'MRN-', digits: 13 }] }, { mode: 'block', recordFormats: [{ prefix: '1MRN-', digits: 8 }] },
      { mode: 'block', recordFormats: [{ prefix: 'MRN-', digits: 8 }, { prefix: 'mrn-', digits: 6 }] },
      { mode: 'block', recordFormats: Array.from({ length: 17 }, (_, index) => ({ prefix: `MR${String.fromCharCode(65 + index)}-`, digits: 8 })) }]) {
      await post('policies', { healthProtection }, { expect: 400 });
    }
    await post('policies', { promptExceptions: [{ appId: 'chatgpt', ruleId: 'us-national-provider-identifier',
      expiresAt: new Date(Date.now() + 3600_000).toISOString(), reason: 'Synthetic exception' }] }, { expect: 400 });

    const browser = await call('/v1/enroll', { method: 'POST', body: { grant: (await post('enrollment-grants')).grant } });
    const browserCall = (route, options) => call(`/v1/browser/${route}`, { token: browser.token, ...options });
    const write = (route, body, expect = 204) => browserCall(route, { method: 'POST', body, expect });
    const caps = { assignmentAware: true, clipboardAware: true, fileInspectionAware: true, fileBlockAware: true, detectionRulesAware: true };
    const deliver = () => browserCall('policy', { ...caps, healthAware: true });
    const policy = await post('policies', { clipboardMode: 'block', fileContentModes: { chatgpt: 'block' },
      healthProtection: { mode: 'block', recordFormats: [{ prefix: ' mrn- ', digits: 8 }, { prefix: 'chart_', digits: 6 }] } });
    assert.deepEqual(policy.healthProtection, { mode: 'block', recordFormats: [{ prefix: 'CHART_', digits: 6 }, { prefix: 'MRN-', digits: 8 }] });
    const event = (ruleId, detectorCategory, decision, fields = {}) => ({ ...contract.event, eventId: randomUUID(), appId: 'chatgpt',
      timestamp: new Date().toISOString(), policyVersion: policy.version, ruleId, detectorCategory, decision, ...fields });
    const heartbeat = { policyVersion: policy.version, clipboardModeApplied: true, fileInspectionApplied: true, fileContentBlockApplied: true };
    const legacy = await browserCall('policy', caps);
    assert.equal(legacy.healthProtection, undefined, 'an older release keeps its other detectors');
    assert.equal(legacy.clipboardMode, 'block');
    assert.equal((await browserCall('policy', { healthAware: true })).healthProtection, undefined, 'requires assignment awareness');
    await write('heartbeat', heartbeat);
    assert.notEqual((await admin('installations'))[0].appliedPolicyVersion, policy.version, 'an older release stays pending');
    await write('heartbeat', { ...heartbeat, healthIdentifiersApplied: true }, 400);
    await write('events', event('us-national-provider-identifier', 'health', 'block'), 400);
    const delivered = await deliver();
    assert.deepEqual(delivered.healthProtection, policy.healthProtection);
    await write('heartbeat', heartbeat);
    assert.notEqual((await admin('installations'))[0].appliedPolicyVersion, policy.version);
    await write('heartbeat', { ...heartbeat, healthIdentifiersApplied: true });
    assert.equal((await admin('installations'))[0].appliedPolicyVersion, policy.version);

    const detected = event('us-national-provider-identifier', 'health', 'block');
    await Promise.all([write('events', detected), write('events', detected)]);
    for (const ruleId of ['dea-registration-number', 'medicare-beneficiary-identifier', 'medical-record-number']) {
      await write('events', event(ruleId, 'health', 'block'));
    }
    await write('events', event('medicare-beneficiary-identifier', 'health', 'block', { clipboardPaste: true }));
    await write('events', event('us-national-provider-identifier', 'health', 'block', { uploadMethod: 'picker' }));
    for (const incorrect of [event('us-national-provider-identifier', 'health', 'warn'), event('us-national-provider-identifier', 'credential', 'block'),
      event('medical-record-number', 'internal-identifier', 'block'), event('dea-registration-number', 'health', 'exception_applied'),
      event('icd-10-code', 'health', 'block'), event('us-national-provider-identifier', 'health', 'block', { content: 'NPI 1234567893' }),
      event('us-national-provider-identifier', 'health', 'block', { matchedValue: 'synthetic' })]) {
      await write('events', incorrect, 400);
    }
    await browserCall('prompt-exception-requests', { method: 'POST', body: { eventId: detected.eventId, appId: 'chatgpt' }, expect: 404 });
    const exported = await admin('events/export');
    const rules = exported.entries.map(({ ruleId, detectorCategory, uploadMethod }) => `${ruleId}/${detectorCategory}/${uploadMethod ?? 'prompt'}`).sort();
    assert.deepEqual(rules, ['dea-registration-number/health/prompt', 'medical-record-number/health/prompt',
      'medicare-beneficiary-identifier/health/prompt', 'medicare-beneficiary-identifier/health/prompt',
      'us-national-provider-identifier/health/picker', 'us-national-provider-identifier/health/prompt']);
    assert.doesNotMatch(JSON.stringify(exported), /1234567893|synthetic/);

    const group = await post('policy-groups', { name: 'Clinical pilot' });
    const scoped = await post(`policy-groups/${group.id}/policies`, { healthProtection: { mode: 'monitor', recordFormats: [] } });
    assert.deepEqual(scoped.healthProtection, { mode: 'monitor', recordFormats: [] });
    assert.deepEqual((await admin('policies'))[0].healthProtection, policy.healthProtection);
    const restored = await post(`policies/${initial.version}/restore`);
    assert.deepEqual(restored.healthProtection, { mode: 'off', recordFormats: [] });
    assert.deepEqual((await deliver()).healthProtection, { mode: 'off', recordFormats: [] });
    await write('events', event('us-national-provider-identifier', 'health', 'block', { policyVersion: restored.version }), 400);
  });

  await t.test('advances staged rollouts through health gates exactly once with review, rollback, and tenant isolation', async () => {
    const admin = (path, options) => call(`/v1/admin/${path}`, { token: rolloutAdmin, ...options });
    const post = (path, body, options) => admin(path, { method: 'POST', body, ...options });
    const plan = (id, options) => admin(`rollout-plans/${id}`, options);
    const act = (id, operation, options) => post(`rollout-plans/${id}/${operation}`, undefined, options);
    const decide = (id, approve, options) => post(`rollout-plans/${id}/decision`, { approve }, options);
    if (postgres) {
      await stop();
      await retentionFixture(undoRolloutSchema);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 52'), '1');
    }
    assert.deepEqual(await admin('rollout-plans'), []);
    const [initial] = await admin('policies');
    const [canary, pilot, staging] = await Promise.all(['Canary ring', 'Pilot ring', 'Staging ring'].map((name) => post('policy-groups', { name })));
    const source = await post(`policy-groups/${staging.id}/policies`, { mode: 'block', githubPatMode: 'warn' });
    async function enroll(group) {
      const { grant } = await post('enrollment-grants');
      const browser = await call('/v1/enroll', { method: 'POST', body: { grant } });
      browser.policy = () => call('/v1/browser/policy', { token: browser.token, assignmentAware: true });
      await browser.policy();
      if (group) await post(`installations/${browser.installationId}/policy-group`, { groupId: group.id }, { expect: 204 });
      browser.ack = async () => {
        const effective = await browser.policy();
        await call('/v1/browser/heartbeat', { token: browser.token, method: 'POST', expect: 204,
          body: { policyVersion: effective.version, assignmentVersion: effective.assignmentVersion ?? 0 } });
        return effective;
      };
      browser.block = async () => {
        const effective = await browser.policy();
        await call('/v1/browser/events', { token: browser.token, method: 'POST', expect: 204, body: { ...contract.event, eventId: randomUUID(),
          timestamp: new Date().toISOString(), policyVersion: effective.version, assignmentVersion: effective.assignmentVersion ?? 0,
          decision: 'block' } });
      };
      return browser;
    }
    const [canaryBrowser, pilotBrowser, baselineBrowser] = await Promise.all([enroll(canary), enroll(pilot), enroll(null)]);
    const stage = (group, fields = {}) => ({ groupId: group?.id ?? null, minSoakSeconds: 0, minAcknowledgedPercent: 100, ...fields });
    const request = (stages, fields = {}) => ({ requestId: randomUUID(), name: 'Block rollout', sourceVersion: source.version, stages, ...fields });
    const current = async (group) => (await admin(group ? `policy-groups/${group.id}/policies` : 'policies'))[0];
    const rolloutAudit = async (planId) => (await admin('audit?limit=1000')).entries.filter(({ rolloutChange }) => rolloutChange?.planId === planId);

    for (const invalid of [request([]), request([stage(canary), stage(canary)]), request([stage(null), stage(canary)]),
      request([stage(canary, { minAcknowledgedPercent: 101 })]), request([stage(canary, { requireComposerReady: ['other'] })]),
      request([stage(canary, { requireComposerReady: ['chatgpt', 'chatgpt'] })]), request([stage(canary, { minSoakSeconds: -1 })]),
      request([stage(canary, { maxWarnOverridePercent: 101 })]), request([stage(canary)], { name: ' ' }),
      request([stage(canary)], { requestId: '00000000-0000-0000-0000-000000000000' }),
      request(Array.from({ length: 6 }, () => stage(canary))), request([{ minSoakSeconds: 0, minAcknowledgedPercent: 0 }])]) {
      await post('rollout-plans', invalid, { expect: 400 });
    }
    assert.deepEqual(await post('rollout-plans', request([stage(canary)], { sourceVersion: 999_999 }), { expect: 404 }),
      { code: 'rollout_source_unavailable' });
    const foreignGroup = await call('/v1/admin/policy-groups', { method: 'POST', token: second, body: { name: `Foreign ring ${suffix}` } });
    assert.deepEqual(await post('rollout-plans', request([stage(foreignGroup)]), { expect: 404 }), { code: 'rollout_group_unavailable' });
    const auditor = await post('access', { name: 'Rollout auditor', role: 'auditor', hours: 1 });
    await post('rollout-plans', request([stage(canary)]), { token: auditor.token, expect: 403 });

    // Happy path through all stages: canary -> pilot -> baseline.
    const pilotSoak = postgres ? 3600 : 0;
    const happy = request([stage(canary, { maxBlockEvents: 5, maxWarnOverridePercent: 50 }), stage(pilot, { minSoakSeconds: pilotSoak }),
      stage(null, { minAcknowledgedPercent: 50 })]);
    const started = await post('rollout-plans', happy);
    assert.equal(started.status, 'running');
    assert.equal(started.requiresReview, false);
    assert.deepEqual(started.stages.map(({ state }) => state), ['active', 'waiting', 'waiting']);
    const canaryVersion = started.stages[0].publishedVersion;
    assert.equal(started.stages[0].priorVersion, initial.version);
    assert.equal((await current(canary)).version, canaryVersion);
    assert.equal((await current(canary)).mode, 'block');
    assert.deepEqual(await post('rollout-plans', happy, { expect: 409 }), { code: 'rollout_plan_exists' });
    assert.deepEqual(await post('rollout-plans', request([stage(canary)]), { expect: 409 }), { code: 'rollout_scope_busy' });

    // The canary browser has not acknowledged yet, so the soaked stage pauses with the measured numbers.
    const waiting = await plan(started.id, { token: auditor.token });
    assert.equal(waiting.status, 'paused');
    assert.equal(waiting.pauseReason, 'acknowledgment_below_threshold');
    assert.deepEqual(waiting.gate.acknowledgment, { active: 1, acknowledged: 0, threshold: 100, passed: false });
    assert.deepEqual(waiting.gate.blocks, { blocks: 0, threshold: 5, passed: true });
    assert.equal(waiting.nextEvaluationAt, null);
    await act(started.id, 'resume', { token: auditor.token, expect: 403 });
    assert.equal((await canaryBrowser.ack()).version, canaryVersion);
    const resumed = await act(started.id, 'resume');
    assert.equal(resumed.status, 'running');
    assert.equal(resumed.currentStage, 1);
    assert.deepEqual(resumed.stages.map(({ state }) => state), ['passed', 'active', 'waiting']);
    const pilotVersion = resumed.stages[1].publishedVersion;
    assert.equal((await current(pilot)).version, pilotVersion);
    assert.equal((await current(pilot)).githubPatMode, 'warn');
    await act(started.id, 'resume', { expect: 409 });
    await pilotBrowser.ack();
    if (postgres) {
      const soaking = await plan(started.id);
      assert.equal(soaking.status, 'running');
      assert.equal(soaking.gate.soaked, false);
      assert.equal(soaking.gate.passed, true);
      assert.equal(Date.parse(soaking.nextEvaluationAt), Date.parse(soaking.stages[1].publishedAt) + 3600_000);
      await retentionFixture(`UPDATE rollout_stages SET published_at = published_at - interval '2 hours'
        WHERE plan_id = '${started.id}' AND position = 1;`);
    }

    // Many concurrent evaluators, including a second API instance, publish the baseline stage exactly once.
    const secondPort = String(Number(port) + 1);
    const secondInstance = spawn('dotnet', [app], { stdio: 'ignore', env: { ...process.env, DOTNET_ENVIRONMENT: 'Development',
      ASPNETCORE_ENVIRONMENT: 'Development', ConnectionStrings__Control: db, Control__Port: secondPort, Control__RolloutEvaluationSeconds: '1',
      Control__Organizations__0__Slug: `rollout-plans-${suffix}`, Control__Organizations__0__AdminToken: rolloutAdmin } });
    const secondExit = once(secondInstance, 'exit');
    try {
      const fromSecond = () => fetch(`http://127.0.0.1:${secondPort}/v1/admin/rollout-plans/${started.id}`, {
        headers: { Authorization: `Bearer ${rolloutAdmin}` }, signal: AbortSignal.timeout(5000) }).then((response) => response.ok, () => false);
      for (let attempt = 0; attempt < 200 && !await fromSecond(); attempt++) await delay(50);
      await Promise.all([...Array.from({ length: 8 }, () => plan(started.id)), ...Array.from({ length: 4 }, fromSecond), delay(1500)]);
    } finally {
      secondInstance.kill('SIGTERM');
      await secondExit;
    }
    const advanced = await plan(started.id);
    assert.equal(advanced.currentStage, 2);
    const baselineVersion = advanced.stages[2].publishedVersion;
    assert.equal((await current()).version, baselineVersion);
    assert.equal((await admin('policies')).filter(({ version }) => version > pilotVersion).length, 1);
    const published = (await rolloutAudit(started.id)).filter(({ action }) => action === 'policy_published');
    assert.deepEqual(published.map(({ policyVersion }) => policyVersion).sort(), [canaryVersion, pilotVersion, baselineVersion].sort());
    const automatic = published.find(({ policyVersion }) => policyVersion === baselineVersion);
    assert.equal(automatic.actor, 'automated_rollout');
    assert.deepEqual(automatic.rolloutChange, { planId: started.id, planName: 'Block rollout', event: 'stage_published', stage: 2, automatic: true });

    // The baseline cohort is only the unassigned browser; it has not acknowledged, so the next evaluation pauses.
    assert.equal(advanced.status, 'paused');
    assert.equal(advanced.pauseReason, 'acknowledgment_below_threshold');
    await baselineBrowser.ack();
    const completed = await act(started.id, 'resume');
    assert.equal(completed.status, 'completed');
    assert.deepEqual(completed.gate.acknowledgment, { active: 1, acknowledged: 1, threshold: 50, passed: true });
    assert.deepEqual(completed.stages.map(({ state }) => state), ['passed', 'passed', 'passed']);
    await act(started.id, 'pause', { expect: 409 });

    // Rollback restores each touched scope's prior version, newest stage first, and only once.
    const rolledBack = await act(started.id, 'rollback');
    assert.equal(rolledBack.status, 'rolled_back');
    assert.deepEqual(rolledBack.stages.map(({ state }) => state), ['restored', 'restored', 'restored']);
    for (const [group, prior] of [[canary, initial], [pilot, initial], [null, initial]]) {
      const restored = await current(group);
      assert.equal(restored.restoredFrom, prior.version);
      assert.equal(restored.mode, prior.mode);
    }
    assert.equal((await canaryBrowser.ack()).mode, initial.mode);
    await act(started.id, 'rollback', { expect: 409 });
    assert.equal((await rolloutAudit(started.id)).filter(({ action }) => action === 'policy_restored').length, 3);

    // A block event halts the stage during its soak; resume re-checks and halts again; cancel keeps the policy.
    const halted = await post('rollout-plans', request([stage(canary, { minSoakSeconds: 3600, minAcknowledgedPercent: 0, maxBlockEvents: 0 }),
      stage(pilot)], { name: 'Halting rollout' }));
    assert.equal((await plan(halted.id)).status, 'running');
    await canaryBrowser.ack();
    await canaryBrowser.block();
    const blocked = await plan(halted.id);
    assert.equal(blocked.status, 'paused');
    assert.equal(blocked.pauseReason, 'block_events_exceeded');
    assert.deepEqual(blocked.gate.blocks, { blocks: 1, threshold: 0, passed: false });
    assert.equal((await act(halted.id, 'resume')).pauseReason, 'block_events_exceeded');
    const cancelled = await act(halted.id, 'cancel');
    assert.equal(cancelled.status, 'cancelled');
    assert.equal((await current(canary)).version, halted.stages[0].publishedVersion);
    assert.equal((await current(pilot)).restoredFrom, initial.version);

    // An administrator pause and a manual change to the active scope are both respected by rollback.
    const manual = await post('rollout-plans', request([stage(canary, { minSoakSeconds: 3600, minAcknowledgedPercent: 0 })],
      { name: 'Manual pause rollout' }));
    const paused = await act(manual.id, 'pause');
    assert.equal(paused.pauseReason, 'paused_by_administrator');
    await act(manual.id, 'pause', { expect: 409 });
    assert.equal((await act(manual.id, 'resume')).status, 'running');
    const override = await post(`policy-groups/${canary.id}/policies`, { mode: 'warn' });
    const changed = await plan(manual.id);
    assert.equal(changed.pauseReason, 'target_changed');
    assert.equal(changed.gate.currentVersion, override.version);
    assert.deepEqual((await act(manual.id, 'rollback')).stages.map(({ state }) => state), ['changed']);
    assert.equal((await current(canary)).version, override.version);

    // Tenant isolation and auditor read-only access.
    assert.deepEqual(await call('/v1/admin/rollout-plans', { token: second }), []);
    await call(`/v1/admin/rollout-plans/${started.id}`, { token: second, expect: 404 });
    for (const operation of ['pause', 'resume', 'rollback', 'cancel']) {
      await call(`/v1/admin/rollout-plans/${manual.id}/${operation}`, { method: 'POST', token: second, expect: 404 });
      await act(manual.id, operation, { token: auditor.token, expect: 403 });
    }
    assert.equal((await admin('rollout-plans', { token: auditor.token })).length, 3);
    await call('/v1/admin/rollout-plans', { token: canaryBrowser.token, expect: 401 });

    // Two-person review: the plan is approved before it starts and automatic publishes name the approver.
    const [author, reviewer, standby] = await Promise.all(['author', 'reviewer', 'standby reviewer'].map((name) =>
      post('access', { name: `Rollout ${name}`, role: 'administrator', hours: 1 })));
    await post('policy-reviews/setting', { required: true }, { expect: 204 });
    const reviewed = request([stage(canary), stage(pilot, { minAcknowledgedPercent: 0 })], { name: 'Reviewed rollout' });
    assert.deepEqual(await post('rollout-plans', reviewed, { expect: 403 }), { code: 'named_administrator_required' });
    const pending = await post('rollout-plans', reviewed, { token: author.token });
    assert.equal(pending.status, 'pending_review');
    assert.equal(pending.stages[0].publishedVersion, null);
    assert.equal((await current(canary)).version, override.version);
    assert.equal((await plan(pending.id)).status, 'pending_review');
    assert.deepEqual(await decide(pending.id, true, { token: author.token, expect: 403 }), { code: 'self_approval' });
    await decide(pending.id, true, { token: auditor.token, expect: 403 });
    await decide(pending.id, true, { expect: 403 });
    await act(pending.id, 'resume', { token: reviewer.token, expect: 409 });
    const approved = await decide(pending.id, true, { token: reviewer.token });
    assert.equal(approved.status, 'running');
    assert.equal(approved.approver.id, reviewer.access.id);
    await decide(pending.id, true, { token: reviewer.token, expect: 409 });
    await canaryBrowser.ack();
    assert.equal((await plan(pending.id)).currentStage, 1);
    const reviewedDone = await plan(pending.id);
    assert.equal(reviewedDone.status, 'completed');
    const reviewedPublishes = (await rolloutAudit(pending.id)).filter(({ action }) => action === 'policy_published');
    assert.equal(reviewedPublishes.length, 2);
    for (const entry of reviewedPublishes) {
      assert.equal(entry.actorAccess.id, reviewer.access.id);
      assert.equal(entry.rolloutChange.approver.id, reviewer.access.id);
    }
    assert.deepEqual(reviewedPublishes.map(({ rolloutChange }) => rolloutChange.automatic).sort(), [false, true]);

    // A revoked approver stops automation until an administrator rolls the plan back.
    const orphan = await post('rollout-plans', request([stage(canary, { minAcknowledgedPercent: 0 }), stage(pilot)], { name: 'Orphaned rollout' }),
      { token: author.token });
    await decide(orphan.id, true, { token: standby.token });
    await post(`access/${standby.access.id}/revoke`, undefined, { expect: 204 });
    const orphaned = await plan(orphan.id);
    assert.equal(orphaned.pauseReason, 'approver_inactive');
    assert.equal(orphaned.currentStage, 0);
    assert.deepEqual(await act(orphan.id, 'resume', { token: author.token, expect: 409 }), { code: 'rollout_approver_inactive' });
    await act(orphan.id, 'rollback', { expect: 403 });
    assert.equal((await act(orphan.id, 'rollback', { token: author.token })).status, 'rolled_back');

    // Disabling reviews cancels a plan that is still waiting for approval.
    const unreviewed = await post('rollout-plans', request([stage(pilot)], { name: 'Unreviewed rollout' }), { token: author.token });
    await post('policy-reviews/setting', { required: false }, { expect: 204 });
    assert.equal((await plan(unreviewed.id)).status, 'cancelled');
    await decide(unreviewed.id, true, { token: reviewer.token, expect: 409 });
    const lifecycle = (await admin('audit?action=rollout_plan_changed&limit=1000')).entries;
    assert.ok(lifecycle.some(({ rolloutChange }) => rolloutChange.planId === unreviewed.id && rolloutChange.reason === 'review_mode_changed'));
    assert.ok(lifecycle.some(({ rolloutChange, actorAccess }) => rolloutChange.planId === pending.id && rolloutChange.event === 'approved' &&
      actorAccess.id === reviewer.access.id));
    // A read that finds the settings or plan lock held returns the last committed state promptly instead of waiting,
    // and the next read after the lock is released evaluates normally.
    if (postgres) {
      const contended = await post('rollout-plans', request([stage(canary, { minAcknowledgedPercent: 0 })], { name: 'Contended rollout' }));
      assert.equal(contended.status, 'running');
      const holder = `zekvar-lock-${randomBytes(4).toString('hex')}`;
      for (const lock of [
        `SELECT 1 FROM organizations WHERE slug = 'rollout-plans-${suffix}' FOR UPDATE`,
        `SELECT 1 FROM rollout_plans WHERE id = '${contended.id}' FOR UPDATE`,
      ]) {
        const held = sql('docker', ['exec', '-e', `PGAPPNAME=${holder}`, postgres, 'psql', '-XAtq', '-U', 'postgres', '-d', 'zekvar',
          '-c', `BEGIN; ${lock}; SELECT pg_sleep(30); COMMIT;`]).catch(() => undefined);
        const sleeping = `SELECT count(*) FROM pg_stat_activity WHERE application_name = '${holder}' AND wait_event = 'PgSleep'`;
        for (let attempt = 0; attempt < 200 && await retentionFixture(sleeping) !== '1'; attempt++) await delay(50);
        assert.equal(await retentionFixture(sleeping), '1');
        try {
          const startedAt = performance.now();
          const [listed, detailed] = await Promise.all([admin('rollout-plans'), plan(contended.id)]);
          assert.ok(performance.now() - startedAt < 2_000, 'a read waited for a held rollout lock');
          for (const snapshot of [listed.find(({ id }) => id === contended.id), detailed]) {
            assert.equal(snapshot.status, 'running');
            assert.equal(snapshot.currentStage, 0);
            assert.deepEqual(snapshot.gate, contended.gate);
          }
        } finally {
          await retentionFixture(`SELECT pg_cancel_backend(pid) FROM pg_stat_activity WHERE application_name = '${holder}'`);
          await held;
        }
      }
      const evaluated = await plan(contended.id);
      assert.equal(evaluated.status, 'completed');
      assert.equal((await rolloutAudit(contended.id)).filter(({ action }) => action === 'policy_published').length, 1);
      assert.equal((await act(contended.id, 'rollback')).status, 'rolled_back');
    }

    const evidence = JSON.stringify(await admin('rollout-plans'));
    for (const browser of [canaryBrowser, pilotBrowser, baselineBrowser]) {
      assert.ok(!evidence.includes(browser.installationId) && !evidence.includes(browser.token));
    }
  });

  await t.test('versions adapter controls with negotiated delivery, fail-closed host blocks, disabled coverage, and tenant isolation', async () => {
    const admin = (path, options) => call(`/v1/admin/${path}`, { token: adapterAdmin, ...options });
    const post = (path, body, options) => admin(path, { method: 'POST', body, ...options });
    const [initial] = await admin('policies');
    assert.deepEqual(initial.adapterControls, {});
    if (postgres) {
      await stop();
      await retentionFixture(undoAdapterControlsSchema);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 53'), '1');
      assert.deepEqual((await admin('policies'))[0], initial);
    }
    for (const adapterControls of [{ chatgpt: { scope: 'composer', fallback: 'open' } }, { chatgpt: { scope: 'adapter' } },
      { copilot: { scope: 'adapter', fallback: 'open' } }, { gemini: { scope: 'adapter', fallback: 'OPEN' } }, { claude: 'adapter' },
      ['adapter'], { chatgpt: { scope: 'adapter', fallback: 'open', note: 'unexpected' } }]) {
      await post('policies', { adapterControls }, { expect: 400 });
    }
    const group = await post('policy-groups', { name: 'Adapter kill switch ring' });
    const path = `policy-groups/${group.id}/policies`;
    const auditor = await post('access', { name: 'Adapter auditor', role: 'auditor', hours: 1 });
    await post(path, { adapterControls: { chatgpt: { scope: 'adapter', fallback: 'open' } } }, { token: auditor.token, expect: 403 });
    const foreign = await fetch(`${baseUrl}/v1/admin/${path}`, { method: 'POST', body: JSON.stringify({ adapterControls: {} }),
      headers: { Authorization: `Bearer ${second}`, 'Content-Type': 'application/json' }, signal: AbortSignal.timeout(5_000) });
    assert.ok([403, 404].includes(foreign.status), `Another tenant changed this group's adapter controls: ${foreign.status}`);
    assert.deepEqual(await admin(path), []);

    async function enroll(target) {
      const { grant } = await post('enrollment-grants');
      const browser = await call('/v1/enroll', { method: 'POST', body: { grant } });
      await call('/v1/browser/policy', { token: browser.token, assignmentAware: true });
      if (target) await assign(browser, target);
      return browser;
    }
    const assign = (browser, target) => post(`installations/${browser.installationId}/policy-group`, { groupId: target?.id ?? null }, { expect: 204 });
    const [current, legacy, baseline] = await Promise.all([enroll(group), enroll(group), enroll(null)]);
    const caps = { assignmentAware: true, claudeAware: true, aiAppAccessAware: true, fileInspectionAware: true, fileBlockAware: true };
    const deliver = (browser, aware = true) => call('/v1/browser/policy', { token: browser.token, ...caps, adapterControlsAware: aware });
    const beat = (browser, body, expect = 204) => call('/v1/browser/heartbeat', { token: browser.token, method: 'POST', body, expect,
      composerAware: true });
    const applied = async (browser) => (await admin('installations')).find(({ installationId }) => installationId === browser.installationId);
    const readiness = async () => (await admin(`reports/composer-readiness?rolloutGroup=${group.id}`)).apps.find(({ appId }) => appId === 'chatgpt');
    const event = (version, assignmentVersion, fields = {}) => ({ ...contract.event, eventId: randomUUID(), appId: 'chatgpt',
      timestamp: new Date().toISOString(), policyVersion: version, assignmentVersion, decision: initial.mode, ...fields });
    const write = (browser, body, expect) => call('/v1/browser/events', { token: browser.token, method: 'POST', body, expect });
    const files = { fileInspectionApplied: true, fileContentBlockApplied: true };

    // Attachments only, fail open, for one rollout group. Older Browser releases keep inspecting and stay pending.
    const attachmentsOff = { chatgpt: { scope: 'attachments', fallback: 'open' } };
    const attachments = await post(path, { fileContentModes: { chatgpt: 'block' }, adapterControls: attachmentsOff });
    assert.deepEqual(attachments.adapterControls, attachmentsOff);
    assert.deepEqual((await admin('policies'))[0].adapterControls, {});
    const delivered = await deliver(current);
    assert.deepEqual(delivered.adapterControls, attachmentsOff);
    assert.deepEqual(delivered.blockedAiAppHosts, []);
    const older = await deliver(legacy, false);
    assert.equal(older.adapterControls, undefined);
    const ack = { policyVersion: attachments.version, assignmentVersion: delivered.assignmentVersion, ...files };
    await beat(legacy, { ...ack, assignmentVersion: older.assignmentVersion });
    assert.notEqual((await applied(legacy)).appliedPolicyVersion, attachments.version);
    await beat(legacy, { ...ack, assignmentVersion: older.assignmentVersion, adapterControlsApplied: true }, 400);
    await beat(current, ack);
    assert.notEqual((await applied(current)).appliedPolicyVersion, attachments.version);
    await beat(current, { ...ack, adapterControlsApplied: true, chatGptCoverage: 'disabled' }, 400);
    await beat(current, { ...ack, adapterControlsApplied: true, chatGptCoverage: 'ready' });
    assert.equal((await applied(current)).appliedPolicyVersion, attachments.version);
    let chatgpt = await readiness();
    assert.deepEqual([chatgpt.counts.detected, chatgpt.counts.policy_pending, chatgpt.attachmentsDisabled], [1, 1, 1]);
    const fileEvent = { ruleId: contract.event.ruleId, uploadMethod: 'picker', decision: 'block' };
    await write(current, event(attachments.version, delivered.assignmentVersion, fileEvent), 400);
    await write(legacy, event(attachments.version, older.assignmentVersion, fileEvent), 204);
    await write(current, event(attachments.version, delivered.assignmentVersion), 204);

    // The whole adapter, fail open. Disabled is a distinct coverage state that passes composer gates.
    await assign(legacy, null);
    const adapterOff = { chatgpt: { scope: 'adapter', fallback: 'open' } };
    const adapter = await post(path, { adapterControls: adapterOff });
    const disabledDelivery = await deliver(current);
    assert.deepEqual(disabledDelivery.adapterControls, adapterOff);
    const adapterAck = { ...ack, policyVersion: adapter.version, assignmentVersion: disabledDelivery.assignmentVersion, adapterControlsApplied: true };
    await beat(current, { ...adapterAck, chatGptCoverage: 'disabled' });
    assert.equal((await applied(current)).chatGptCoverage, 'disabled');
    chatgpt = await readiness();
    assert.deepEqual([chatgpt.counts.disabled_by_admin, chatgpt.counts.unsupported, chatgpt.counts.detected], [1, 0, 0]);
    await write(current, event(adapter.version, disabledDelivery.assignmentVersion), 400);
    const gated = await post(path, { mode: initial.mode, expectedVersion: adapter.version, requireComposerReady: ['chatgpt'] });
    assert.deepEqual(gated.adapterControls, adapterOff);

    // An automated rollout stage that requires ChatGPT readiness completes when ChatGPT is disabled on purpose.
    const staging = await post('policy-groups', { name: 'Adapter staging' });
    const source = await post(`policy-groups/${staging.id}/policies`, { fileContentModes: { chatgpt: 'block' }, adapterControls: adapterOff });
    const rollout = await post('rollout-plans', { requestId: randomUUID(), name: 'Disabled adapter rollout', sourceVersion: source.version,
      stages: [{ groupId: group.id, minSoakSeconds: 0, minAcknowledgedPercent: 100, requireComposerReady: ['chatgpt'] }] });
    const staged = await deliver(current);
    assert.equal(staged.version, rollout.stages[0].publishedVersion);
    await beat(current, { ...adapterAck, policyVersion: staged.version, assignmentVersion: staged.assignmentVersion, chatGptCoverage: 'disabled' });
    const finished = await admin(`rollout-plans/${rollout.id}`);
    assert.equal(finished.status, 'completed', JSON.stringify(finished.gate));

    // Fail closed reuses the AI app access host block, including for older releases, and needs its acknowledgment.
    await assign(legacy, group);
    const limit = Array.from({ length: 49 }, (_, index) => `limit-${index}.adapter.test`);
    await post(path, { domainRules: { allow: [], block: limit }, adapterControls: { chatgpt: { scope: 'adapter', fallback: 'closed' } } },
      { expect: 400 });
    const closed = await post(path, { adapterControls: { chatgpt: { scope: 'adapter', fallback: 'closed' } } });
    assert.deepEqual(closed.blockedAiAppHosts, []);
    const blocked = await deliver(current);
    assert.deepEqual(blocked.blockedAiAppHosts, ['chat.openai.com', 'chatgpt.com']);
    const olderBlocked = await deliver(legacy, false);
    assert.deepEqual(olderBlocked.blockedAiAppHosts, ['chat.openai.com', 'chatgpt.com']);
    assert.equal(olderBlocked.adapterControls, undefined);
    const closedAck = { ...files, policyVersion: closed.version, assignmentVersion: blocked.assignmentVersion, adapterControlsApplied: true };
    await beat(current, closedAck);
    assert.notEqual((await applied(current)).appliedPolicyVersion, closed.version);
    await beat(current, { ...closedAck, aiAppAccessApplied: true, chatGptCoverage: 'disabled' });
    assert.equal((await applied(current)).appliedPolicyVersion, closed.version);
    const untouched = await deliver(baseline);
    assert.deepEqual([untouched.adapterControls, untouched.blockedAiAppHosts], [{}, []]);
    assert.deepEqual((await call('/v1/admin/policies', { token: second }))[0].adapterControls, {});

    // Re-enabling restores interception; a restored version brings the control back.
    const restored = await post(path, { adapterControls: {} });
    const back = await deliver(current);
    assert.deepEqual([back.adapterControls, back.blockedAiAppHosts], [{}, []]);
    const backAck = { ...files, policyVersion: restored.version, assignmentVersion: back.assignmentVersion };
    await beat(current, { ...backAck, chatGptCoverage: 'disabled' }, 400);
    await beat(current, { ...backAck, chatGptCoverage: 'ready' });
    assert.equal((await applied(current)).appliedPolicyVersion, restored.version);
    assert.equal((await readiness()).counts.detected, 1);
    const reinstated = await post(`${path}/${adapter.version}/restore`);
    assert.deepEqual(reinstated.adapterControls, adapterOff);
    assert.deepEqual((await post(path, { adapterControls: {} })).adapterControls, {});
  });

  await t.test('keeps an opt-in SaaS inventory of catalog IDs and UTC days with classification audit, retention, and isolation', async () => {
    const admin = (path, options) => call(`/v1/admin/${path}`, { token: saasAdmin, ...options });
    const catalog = JSON.parse(await readFile(new URL('../../../contracts/policy/saas-catalog.json', import.meta.url)));
    const inventory = (token = saasAdmin) => call('/v1/admin/saas-apps', { token });
    const row = async (appId, token) => (await inventory(token)).apps.find((entry) => entry.appId === appId);
    const classify = (appId, status, token = saasAdmin, expect = 204) =>
      call(`/v1/admin/saas-apps/${appId}/classification`, { method: 'POST', token, body: { status }, expect });
    const enroll = async () => {
      const { grant } = await admin('enrollment-grants', { method: 'POST' });
      return call('/v1/enroll', { method: 'POST', body: { grant } });
    };
    const fetchPolicy = (browser, saasAware = true) => call('/v1/browser/policy', { token: browser.token, assignmentAware: true, saasAware });
    const observe = (browser, body, expect = 204) => call('/v1/browser/saas-observations', { method: 'POST', token: browser.token, body, expect });
    const day = (offset = 0) => new Date(Date.now() + offset * 86_400_000).toISOString().slice(0, 10);

    // The API catalog mirrors the bundled contract catalog exactly and in order.
    const initial = await inventory();
    assert.equal(initial.catalogVersion, catalog.version);
    assert.equal(initial.discoveryEnabled, false);
    assert.equal(initial.windowDays, 30);
    assert.deepEqual(initial.apps.map(({ appId }) => appId), catalog.apps.map(({ id }) => id));
    assert.ok(initial.apps.every((app) => app.status === 'unclassified' && app.browsersSeen === 0 && app.lastSeenDay === null));

    const browser = await enroll();
    const another = await enroll();
    const legacy = await enroll();
    const off = await fetchPolicy(browser);
    assert.equal(off.saasDiscoveryEnabled, false);
    assert.equal((await fetchPolicy(legacy, false)).saasDiscoveryEnabled, undefined);
    await observe(browser, { appId: 'dropbox', day: day(), policyVersion: off.version }, 400);

    const enabled = await admin('policies', { method: 'POST', body: { saasDiscoveryEnabled: true } });
    assert.equal(enabled.saasDiscoveryEnabled, true);
    assert.equal(enabled.discoveryEnabled, false, 'SaaS inventory is separate from AI discovery.');
    assert.equal((await inventory()).discoveryEnabled, true);
    const delivered = await fetchPolicy(browser);
    assert.equal(delivered.saasDiscoveryEnabled, true);
    await fetchPolicy(another);
    const unaware = await fetchPolicy(legacy, false);
    assert.equal(unaware.saasDiscoveryEnabled, undefined);
    const report = { appId: 'dropbox', day: day(), policyVersion: enabled.version };
    // An older Browser never received the setting, so Control refuses its reports.
    await observe(legacy, report, 400);
    for (const invalid of [{ ...report, appId: 'example' }, { ...report, appId: 'saas:' + 'a'.repeat(64) }, { ...report, appId: 'copilot' },
      { ...report, day: new Date().toISOString() }, { ...report, day: '2026-13-01' }, { ...report, day: day(2) },
      { ...report, day: day(-40) }, { ...report, policyVersion: 999 }, { ...report, assignmentVersion: 4 }]) {
      await observe(browser, invalid, 400);
    }
    // A report carrying a URL, path, or title is rejected outright.
    await observe(browser, { ...report, url: 'https://www.dropbox.com/private?customer=synthetic' }, 400);
    await observe(browser, { ...report, title: 'Synthetic private title' }, 400);
    await Promise.all([observe(browser, report), observe(browser, report), observe(browser, report)]);
    await observe(another, report);
    await observe(another, { ...report, appId: 'github' });
    const columns = await retentionFixture(`SELECT string_agg(column_name, ',' ORDER BY column_name) FROM information_schema.columns
      WHERE table_name = 'saas_app_observations'`);
    assert.equal(columns, 'app_id,first_seen_day,installation_id,last_seen_day,organization_id');
    assert.doesNotMatch(await retentionFixture(`SELECT coalesce(string_agg(t::text, ';'), '') FROM saas_app_observations t`), /synthetic|https/);
    assert.deepEqual(await row('dropbox'), { appId: 'dropbox', status: 'unclassified', browsersSeen: 2, firstSeenDay: day(), lastSeenDay: day() });
    assert.equal((await row('github')).browsersSeen, 1);

    // Heartbeats acknowledge the policy only when Browser applied SaaS inventory with the Chrome permission.
    const heartbeat = (applied) => call('/v1/browser/heartbeat', { method: 'POST', token: browser.token,
      body: { policyVersion: enabled.version, saasDiscoveryApplied: applied }, expect: 204 });
    const applied = async () => (await admin('installations')).find(({ installationId }) => installationId === browser.installationId)
      .appliedPolicyVersion;
    await heartbeat(false);
    assert.equal(await applied(), null);
    await heartbeat(true);
    assert.equal(await applied(), enabled.version);

    // Classification is validated, audited once per change, and limited to owners and administrators.
    await classify('dropbox', 'approved', saasAdmin, 400);
    await classify('unknown-app', 'sanctioned', saasAdmin, 400);
    await classify('dropbox', 'unsanctioned', browser.token, 401);
    await classify('dropbox', 'under_review');
    await Promise.all([classify('dropbox', 'unsanctioned'), classify('dropbox', 'unsanctioned')]);
    assert.equal((await row('dropbox')).status, 'unsanctioned');
    const audit = (await admin('audit?action=saas_app_classified')).entries;
    assert.deepEqual(audit.map(({ saasClassification }) => saasClassification), [
      { appId: 'dropbox', status: 'unsanctioned', previous: 'under_review' },
      { appId: 'dropbox', status: 'under_review', previous: 'unclassified' },
    ]);
    const auditor = await admin('access', { method: 'POST', body: { name: 'SaaS Auditor', role: 'auditor', hours: 1 } });
    assert.equal((await row('dropbox', auditor.token)).status, 'unsanctioned');
    await classify('dropbox', 'sanctioned', auditor.token, 403);

    // Another tenant sees none of this inventory or classification, and its changes stay in its own tenant.
    assert.deepEqual(await row('dropbox', first), { appId: 'dropbox', status: 'unclassified', browsersSeen: 0, firstSeenDay: null, lastSeenDay: null });
    await classify('github', 'sanctioned', first);
    assert.equal((await row('github')).status, 'unclassified');

    // Retention expires browsers last seen before the cutoff day and trims older first-seen days.
    await retentionFixture(`UPDATE saas_app_observations SET first_seen_day = current_date - 10, last_seen_day = current_date - 6
      WHERE installation_id = '${another.installationId}' AND app_id = 'github'`);
    await retentionFixture(`UPDATE saas_app_observations SET first_seen_day = current_date - 10
      WHERE installation_id = '${browser.installationId}' AND app_id = 'dropbox'`);
    assert.equal((await row('dropbox')).firstSeenDay, day(-10));
    await admin('retention', { method: 'POST', body: { securityEventDays: null, aiObservationDays: 3, auditDays: null }, expect: 204 });
    assert.equal((await row('github')).browsersSeen, 0, 'Reads apply the retention cutoff before cleanup.');
    assert.equal((await row('dropbox')).firstSeenDay, day(-3));
    await observe(browser, { ...report, appId: 'github', day: day(-5) }, 400);
    const cleaned = await admin('retention/cleanup', { method: 'POST' });
    assert.equal(cleaned.saasObservations, 1);
    assert.equal(await retentionFixture(`SELECT count(*) FROM saas_app_observations WHERE app_id = 'github'
      AND installation_id = '${another.installationId}'`), '0');
    assert.equal(await retentionFixture(`SELECT first_seen_day = current_date - 3 FROM saas_app_observations
      WHERE installation_id = '${browser.installationId}' AND app_id = 'dropbox'`), 't');
    assert.equal((await admin('retention/cleanup', { method: 'POST' })).saasObservations, undefined);

    // Disabling inventory, revocation, and restarts are respected.
    const disabled = await admin('policies', { method: 'POST', body: { saasDiscoveryEnabled: false } });
    await observe(another, { ...report, appId: 'slack' }, 400);
    assert.equal((await fetchPolicy(another)).saasDiscoveryEnabled, false);
    await observe(another, { ...report, appId: 'slack', policyVersion: disabled.version }, 400);
    await admin(`installations/${browser.installationId}/revoke`, { method: 'POST', expect: 204 });
    await observe(browser, report, 401);
    const before = await inventory();
    await stop();
    await start();
    assert.deepEqual(await inventory(), before);

    // Upgrading an existing database keeps every published policy with SaaS inventory off.
    await stop();
    await retentionFixture(undoSaasInventorySchema);
    await start();
    assert.ok((await admin('policies')).every((policy) => policy.saasDiscoveryEnabled === false));
    assert.ok((await inventory()).apps.every((app) => app.browsersSeen === 0 && app.status === 'unclassified'));
  });

  await t.test('device-manager enrollment keys enroll many profiles into one group with atomic limits, idempotent retries, rotation, and bulk revocation', async () => {
    const admin = (path, options) => call(`/v1/admin/${path}`, { token: enrollmentKeyAdmin, ...options });
    const post = (path, body, options) => admin(path, { method: 'POST', body, ...options });
    const nonce = () => randomBytes(32).toString('hex');
    const sha256 = (value) => createHash('sha256').update(value).digest('hex');
    const create = (fields, options) => post('enrollment-keys', { requestId: randomUUID(), label: 'Device group key', days: 30, ...fields }, options);
    async function redeem(key, value = nonce()) {
      const response = await fetch(`${baseUrl}/v1/enroll/key`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key, nonce: value }), signal: AbortSignal.timeout(10_000) });
      const text = await response.text();
      return { status: response.status, body: text ? JSON.parse(text) : undefined, retryAfter: response.headers.get('retry-after'), nonce: value };
    }
    const keyRow = async (id) => (await admin('enrollment-keys')).find((key) => key.id === id);
    const policy = (token, expect = 200) => call('/v1/browser/policy', { token, assignmentAware: true, expect });

    if (postgres) {
      await create({ label: 'Before migration replay' });
      await stop();
      await retentionFixture(undoEnrollmentKeysSchema);
      await start();
      assert.equal(await retentionFixture('SELECT count(*) FROM schema_migrations WHERE version = 54'), '1');
      assert.deepEqual(await admin('enrollment-keys'), []);
    }

    const group = await post('policy-groups', { name: 'Intune finance devices' });
    const groupPolicy = await post(`policy-groups/${group.id}/policies`, { mode: 'block' });
    for (const body of [{ label: 'x' }, { label: 'Valid', days: 31 }, { label: 'Valid', days: 0 }, { label: 'Valid', maxRedemptions: 0 },
      { label: 'Valid', maxRedemptions: 100_001 }, { label: 'Bad\nlabel' }, { requestId: '00000000-0000-0000-0000-000000000000' },
      { label: 'Valid', groupId: '00000000-0000-0000-0000-000000000000' }, { label: 'Valid', scope: 'admin' }]) {
      await create(body, { expect: 400 });
    }
    assert.deepEqual(await create({ groupId: randomUUID() }, { expect: 404 }), { code: 'enrollment_key_group_unavailable' });

    // Issue once; Control keeps only the hash.
    const requestId = randomUUID();
    const issued = await create({ requestId, label: 'Finance laptops', groupId: group.id, maxRedemptions: 10 });
    assert.match(issued.token, /^zke_[a-f0-9]{64}$/);
    assert.deepEqual([issued.key.status, issued.key.redeemed, issued.key.maxRedemptions, issued.key.groupName, issued.key.label],
      ['active', 0, 10, group.name, 'Finance laptops']);
    assert.ok(Math.abs(Date.parse(issued.key.expiresAt) - Date.now() - 30 * 86_400_000) < 120_000);
    assert.deepEqual(await create({ requestId, label: 'Finance laptops' }, { expect: 409 }), { code: 'enrollment_key_exists' });
    assert.ok(!JSON.stringify(await admin('enrollment-keys')).includes(issued.token.slice(4)));
    if (postgres) {
      assert.equal(await retentionFixture(`SELECT count(*) FROM enrollment_keys WHERE token_hash = '${sha256(issued.token)}'`), '1');
      assert.equal(await retentionFixture(`SELECT count(*) FROM enrollment_keys WHERE token_hash LIKE '%${issued.token.slice(4, 20)}%'`), '0');
    }

    // The key only enrolls. It cannot authenticate to admin, browser, or integration APIs, with or without its prefix.
    for (const bearer of [issued.token, issued.token.slice(4)]) {
      await call('/v1/admin/session', { token: bearer, expect: 401 });
      await call('/v1/admin/enrollment-keys', { token: bearer, expect: 401 });
      await call('/v1/admin/enrollment-grants', { token: bearer, method: 'POST', expect: 401 });
      await call('/v1/browser/policy', { token: bearer, expect: 401 });
      await call('/v1/integrations/events', { token: bearer, expect: 401 });
    }
    await call('/v1/enroll', { method: 'POST', body: { grant: issued.token.slice(4) }, expect: 401 });
    for (const body of [{ key: issued.token }, { key: issued.token, nonce: 'short' }, { key: issued.token.slice(4), nonce: nonce() },
      { key: issued.token, nonce: nonce(), groupId: group.id }]) {
      await call('/v1/enroll/key', { method: 'POST', body, expect: 400 });
    }
    assert.deepEqual(await call('/v1/enroll/key', { method: 'POST', body: { key: `zke_${randomBytes(32).toString('hex')}`, nonce: nonce() },
      expect: 401 }), { code: 'enrollment_key_invalid' });

    // Thirty concurrent profiles race for ten seats.
    const raced = await Promise.all(Array.from({ length: 30 }, () => redeem(issued.token)));
    const enrolled = raced.filter(({ status }) => status === 200);
    assert.equal(enrolled.length, 10, JSON.stringify(raced.map(({ status, body }) => [status, body?.code])));
    assert.ok(raced.filter(({ status }) => status !== 200).every(({ status, body }) => status === 410 && body.code === 'enrollment_key_exhausted'));
    assert.equal(new Set(enrolled.map(({ body }) => body.installationId)).size, 10);
    assert.equal(new Set(enrolled.map(({ body }) => body.token)).size, 10);
    for (const { body } of enrolled) {
      const delivered = await policy(body.token);
      assert.equal(delivered.version, groupPolicy.version);
    }
    const exhausted = await keyRow(issued.key.id);
    assert.deepEqual([exhausted.status, exhausted.redeemed, exhausted.activeInstallations, exhausted.rejected], ['exhausted', 10, 10, 20]);
    assert.ok(exhausted.lastRedeemedAt && exhausted.lastRejectedAt);
    const keyFleet = await admin(`installations/fleet?enrollmentKey=${issued.key.id}`);
    assert.equal(keyFleet.entries.length, 10);
    assert.ok(keyFleet.entries.every(({ groupId }) => groupId === group.id));
    for (const query of ['enrollmentKey=invalid', `enrollmentKey=${issued.key.id}&enrollmentKey=${issued.key.id}`]) {
      await admin(`installations/fleet?${query}`, { expect: 400 });
    }
    await admin(`installations/fleet?enrollmentKey=${randomUUID()}`, { expect: 404 });
    const audit = (await admin('audit?action=browser_enrolled&limit=100')).entries.filter(({ enrollmentKeyChange }) =>
      enrollmentKeyChange?.keyId === issued.key.id);
    assert.equal(audit.length, 10);
    assert.deepEqual(audit.map(({ enrollmentKeyChange }) => enrollmentKeyChange.redeemed).sort((a, b) => a - b), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    assert.ok(audit.every(({ actor, enrollmentKeyChange }) => actor === 'browser_enrollment' && enrollmentKeyChange.maxRedemptions === 10 &&
      enrollmentKeyChange.groupId === group.id));
    const [issuedAudit] = (await admin('audit?action=enrollment_key_issued')).entries.filter(({ enrollmentKeyChange }) =>
      enrollmentKeyChange.keyId === issued.key.id);
    assert.deepEqual([issuedAudit.enrollmentKeyChange.label, issuedAudit.enrollmentKeyChange.maxRedemptions], ['Finance laptops', 10]);
    assert.ok(!JSON.stringify(await admin('audit?limit=1000')).includes(issued.token.slice(4)));

    // A profile that lost the response retries with its nonce: same installation, no extra seat, and only the new credential works.
    const pair = await create({ label: 'Two seats', maxRedemptions: 2 });
    const profile = nonce();
    const lost = await redeem(pair.token, profile);
    const retried = await redeem(pair.token, profile);
    assert.equal(retried.status, 200);
    assert.equal(retried.body.installationId, lost.body.installationId);
    assert.notEqual(retried.body.token, lost.body.token);
    await policy(lost.body.token, 401);
    await policy(retried.body.token);
    assert.equal((await keyRow(pair.key.id)).redeemed, 1);
    assert.equal((await redeem(pair.token)).status, 200);
    assert.equal((await redeem(pair.token)).body.code, 'enrollment_key_exhausted');
    const late = await redeem(pair.token, profile);
    assert.deepEqual([late.status, late.body.installationId], [200, lost.body.installationId]);
    assert.equal((await keyRow(pair.key.id)).redeemed, 2);
    const burst = await create({ label: 'Same profile burst', maxRedemptions: 5 });
    const same = nonce();
    const repeated = await Promise.all(Array.from({ length: 5 }, () => redeem(burst.token, same)));
    assert.ok(repeated.every(({ status }) => status === 200));
    assert.equal(new Set(repeated.map(({ body }) => body.installationId)).size, 1);
    let working = 0;
    for (const { body } of repeated) {
      const response = await fetch(`${baseUrl}/v1/browser/policy`, { headers: { Authorization: `Bearer ${body.token}` }, signal: AbortSignal.timeout(5_000) });
      if (response.status !== 401) working++;
    }
    assert.equal(working, 1);
    assert.equal((await keyRow(burst.key.id)).redeemed, 1);

    // Expiry.
    const expiring = await create({ label: 'Expiring key', days: 1 });
    if (postgres) {
      await retentionFixture(`UPDATE enrollment_keys SET created_at = now() - interval '2 days', expires_at = now() - interval '1 second'
        WHERE id = '${expiring.key.id}';`);
      assert.deepEqual((await redeem(expiring.token)).body, { code: 'enrollment_key_expired' });
      assert.equal((await keyRow(expiring.key.id)).status, 'expired');
      await post(`enrollment-keys/${expiring.key.id}/rotate`, { requestId: randomUUID(), days: 1 }, { expect: 409 });
    }

    // Revocation stops new and retried redemptions but leaves enrolled browsers alone until they are revoked.
    const revocable = await create({ label: 'Revocable key' });
    const kept = await redeem(revocable.token);
    await post(`enrollment-keys/${revocable.key.id}/revoke`, undefined, { expect: 204 });
    await post(`enrollment-keys/${revocable.key.id}/revoke`, undefined, { expect: 204 });
    await post(`enrollment-keys/${randomUUID()}/revoke`, undefined, { expect: 404 });
    assert.deepEqual((await redeem(revocable.token)).body, { code: 'enrollment_key_revoked' });
    assert.deepEqual((await redeem(revocable.token, kept.nonce)).body, { code: 'enrollment_key_revoked' });
    await policy(kept.body.token);
    const revokedAudit = (await admin('audit?action=enrollment_key_revoked')).entries;
    assert.equal(revokedAudit.length, 1);
    assert.deepEqual([revokedAudit[0].enrollmentKeyChange.keyId, revokedAudit[0].enrollmentKeyChange.redeemed], [revocable.key.id, 1]);
    assert.deepEqual((await post(`enrollment-keys/${revocable.key.id}/rotate`, { requestId: randomUUID(), days: 7 }, { expect: 409 })),
      { code: 'enrollment_key_inactive' });

    // Rotation: the new key works while the old one stays valid for the overlap, then the old one is revoked.
    const current = await create({ label: 'Jamf scope key', groupId: group.id, maxRedemptions: 50 });
    for (const body of [{ requestId: randomUUID(), days: 31 }, { requestId: randomUUID(), days: 7, overlapHours: 0 },
      { requestId: randomUUID(), days: 7, overlapHours: 721 }]) {
      await post(`enrollment-keys/${current.key.id}/rotate`, body, { expect: 400 });
    }
    await post(`enrollment-keys/${randomUUID()}/rotate`, { requestId: randomUUID(), days: 7 }, { expect: 404 });
    const rotated = await post(`enrollment-keys/${current.key.id}/rotate`, { requestId: randomUUID(), days: 14, overlapHours: 24 });
    assert.notEqual(rotated.token, current.token);
    assert.deepEqual([rotated.key.rotatedFrom, rotated.key.label, rotated.key.groupId, rotated.key.maxRedemptions, rotated.key.status],
      [current.key.id, 'Jamf scope key', group.id, 50, 'active']);
    const previous = await keyRow(current.key.id);
    assert.equal(previous.status, 'active');
    assert.ok(Math.abs(Date.parse(previous.expiresAt) - Date.now() - 86_400_000) < 120_000);
    const [oldRedeemed, newRedeemed] = await Promise.all([redeem(current.token), redeem(rotated.token)]);
    assert.deepEqual([oldRedeemed.status, newRedeemed.status], [200, 200]);
    assert.equal((await policy(newRedeemed.body.token)).version, groupPolicy.version);
    await post(`enrollment-keys/${current.key.id}/revoke`, undefined, { expect: 204 });
    assert.equal((await redeem(current.token)).body.code, 'enrollment_key_revoked');
    assert.equal((await redeem(rotated.token)).status, 200);
    const rotationAudit = (await admin('audit?action=enrollment_key_issued')).entries.find(({ enrollmentKeyChange }) =>
      enrollmentKeyChange.keyId === rotated.key.id).enrollmentKeyChange;
    assert.equal(rotationAudit.rotatedFrom, current.key.id);
    assert.ok(rotationAudit.previousKeyExpiresAt);
    const plain = await post(`enrollment-keys/${rotated.key.id}/rotate`, { requestId: randomUUID(), days: 3 });
    assert.equal((await keyRow(rotated.key.id)).expiresAt, rotated.key.expiresAt);
    assert.equal(plain.key.rotatedFrom, rotated.key.id);

    // Roles and tenants.
    const operator = await post('access', { name: 'Key operator', role: 'administrator', hours: 1 });
    const auditor = await post('access', { name: 'Key auditor', role: 'auditor', hours: 1 });
    const delegated = await create({ label: 'Delegated key' }, { token: operator.token });
    assert.equal((await admin('audit?action=enrollment_key_issued')).entries.find(({ enrollmentKeyChange }) =>
      enrollmentKeyChange.keyId === delegated.key.id).actorAccess.name, 'Key operator');
    assert.ok((await admin('enrollment-keys', { token: auditor.token })).some(({ id }) => id === issued.key.id));
    assert.equal((await admin(`installations/fleet?enrollmentKey=${issued.key.id}`, { token: auditor.token })).entries.length, 10);
    await create({ label: 'Auditor key' }, { token: auditor.token, expect: 403 });
    await post(`enrollment-keys/${delegated.key.id}/revoke`, undefined, { token: auditor.token, expect: 403 });
    await post(`enrollment-keys/${delegated.key.id}/rotate`, { requestId: randomUUID(), days: 1 }, { token: auditor.token, expect: 403 });
    assert.equal((await keyRow(delegated.key.id)).status, 'active');
    const foreign = (path, options) => call(`/v1/admin/${path}`, { token: second, ...options });
    assert.ok(!(await foreign('enrollment-keys')).some(({ id }) => id === issued.key.id));
    await foreign(`enrollment-keys/${delegated.key.id}/revoke`, { method: 'POST', expect: 404 });
    await foreign(`enrollment-keys/${delegated.key.id}/rotate`, { method: 'POST', body: { requestId: randomUUID(), days: 1 }, expect: 404 });
    await foreign(`installations/fleet?enrollmentKey=${issued.key.id}`, { expect: 404 });
    await foreign('enrollment-keys', { method: 'POST', body: { requestId: randomUUID(), label: 'Foreign', days: 1, groupId: group.id }, expect: 404 });
    const foreignIds = new Set((await foreign('installations')).map(({ installationId }) => installationId));
    assert.ok(enrolled.every(({ body }) => !foreignIds.has(body.installationId)));
    assert.equal((await keyRow(delegated.key.id)).status, 'active');

    // Bulk revocation of everything a leaked key enrolled reuses the audited fleet batch.
    const selections = keyFleet.entries.map(({ installationId, assignmentVersion }) => ({ installationId, assignmentVersion }));
    const change = await post('installations/fleet', { requestId: randomUUID(), operation: 'revoke', groupId: null, expectedPolicyVersion: null,
      selections });
    assert.equal(change.changedInstallations.length, 10);
    for (const { body } of enrolled) await policy(body.token, 401);
    assert.deepEqual((await admin(`installations/fleet?enrollmentKey=${issued.key.id}`)).entries, []);
    assert.equal((await keyRow(issued.key.id)).activeInstallations, 0);
    assert.deepEqual((await redeem(issued.token, enrolled[0].nonce)).body, { code: 'installation_revoked' });
    assert.equal((await admin('audit?action=browser_fleet_changed')).entries[0].fleetChange.changedInstallations.length, 10);

    // Each key has its own attempt budget per minute.
    const flood = await create({ label: 'Rate limited key' });
    const attempts = await Promise.all(Array.from({ length: 45 }, () => redeem(flood.token)));
    const limited = attempts.filter(({ status }) => status === 429);
    assert.equal(limited.length, 5);
    assert.ok(limited.every(({ body, retryAfter }) => body.code === 'enrollment_key_rate_limited' && Number(retryAfter) >= 1 && Number(retryAfter) <= 60));
    assert.equal(attempts.filter(({ status }) => status === 200).length, 40);
    assert.equal((await redeem(delegated.token)).status, 200);

    // At most twenty keys can be active at once.
    const active = (await admin('enrollment-keys')).filter(({ status }) => status === 'active' || status === 'exhausted').length;
    for (let index = active; index < 20; index++) await create({ label: `Capacity ${index}` });
    assert.deepEqual(await create({ label: 'One too many' }, { expect: 409 }), { code: 'enrollment_key_limit' });
  });

  // Self-service deletion: installation erasure, policy history purge, export, and organization offboarding.
  const deletionAdmin = (token) => (path, options) => call(`/v1/admin/${path}`, { token, ...options });
  const deletionPost = (token) => (path, body, options) => call(`/v1/admin/${path}`, { token, method: 'POST', body, ...options });
  async function enrollIn(token) {
    const { grant } = await deletionPost(token)('enrollment-grants');
    return call('/v1/enroll', { method: 'POST', body: { grant } });
  }
  async function sendEvent(browser, policyVersion, fields = {}) {
    const event = { ...contract.event, eventId: randomUUID(), timestamp: new Date().toISOString(), policyVersion, ...fields };
    await call('/v1/browser/events', { token: browser.token, method: 'POST', body: event, expect: 204 });
    return event;
  }
  const tenantTables = async () => (await retentionFixture(`
    SELECT string_agg(c.table_name, ',' ORDER BY c.table_name) FROM information_schema.columns c
    JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name
    WHERE c.table_schema = 'public' AND c.column_name = 'organization_id' AND t.table_type = 'BASE TABLE'`)).split(',');
  async function tenantCounts(organizationId) {
    // zz_ tables are fixtures created by the deletion test below.
    const tables = (await tenantTables()).filter((table) => table !== 'organization_deletions' && !table.startsWith('zz_'));
    const query = tables.map((table) => `SELECT '${table}', count(*) FROM ${table} WHERE organization_id = '${organizationId}'`).join(' UNION ALL ');
    return Object.fromEntries((await retentionFixture(query)).split('\n').map((line) => line.split('|')).map(([table, count]) => [table, Number(count)]));
  }
  const organizationId = async (slug) => retentionFixture(`SELECT id FROM organizations WHERE slug = '${slug}'`);
  const verifyReceipt = (envelope) => createHmac('sha256', Buffer.from(deletionKey, 'hex'))
    .update(JSON.stringify(envelope.receipt)).digest('hex') === envelope.signature.value;
  async function rawFetch(path, token) {
    return fetch(`${baseUrl}${path}`, { headers: token ? { Authorization: `Bearer ${token}` } : {}, signal: AbortSignal.timeout(10_000) });
  }

  await t.test('deletes only a revoked installation and its derived records and leaves a metadata-only tombstone', async () => {
    const admin = deletionAdmin(eraseAdmin);
    const post = deletionPost(eraseAdmin);
    const [initial] = await admin('policies');
    const [doomed, kept] = await Promise.all([enrollIn(eraseAdmin), enrollIn(eraseAdmin)]);
    for (const browser of [doomed, kept]) {
      await call('/v1/browser/policy', { token: browser.token });
      await call('/v1/browser/heartbeat', { token: browser.token, method: 'POST', body: { policyVersion: initial.version }, expect: 204 });
    }
    const doomedEvent = await sendEvent(doomed, initial.version);
    await sendEvent(doomed, initial.version);
    const keptEvent = await sendEvent(kept, initial.version);
    await post(`events/${doomed.installationId}/${doomedEvent.eventId}/triage`, { expectedRevision: 0, status: 'investigating' });
    const { caseId } = await post('cases', { requestId: randomUUID(), category: 'other', installationId: kept.installationId, eventId: keptEvent.eventId });
    const before = await admin(`cases/${caseId}`);
    await post(`cases/${caseId}/membership`, { expectedRevision: before.case.triage.revision, installationId: doomed.installationId,
      eventId: doomedEvent.eventId, linked: true });
    const delegated = await post('access', { name: 'Erasure admin', role: 'administrator', hours: 1 });
    const auditor = await post('access', { name: 'Erasure auditor', role: 'auditor', hours: 1 });

    assert.deepEqual(await post(`installations/${doomed.installationId}/delete`, undefined, { expect: 409 }), { code: 'installation_active' });
    await post(`installations/${doomed.installationId}/revoke`, undefined, { expect: 204 });
    await post(`installations/${doomed.installationId}/delete`, undefined, { token: auditor.token, expect: 403 });
    await call(`/v1/admin/installations/${doomed.installationId}/delete`, { method: 'POST', token: second, expect: 404 });
    await post(`installations/${randomUUID()}/delete`, undefined, { expect: 404 });
    const attempts = await Promise.all([1, 2].map(() => fetch(`${baseUrl}/v1/admin/installations/${doomed.installationId}/delete`, {
      method: 'POST', headers: { Authorization: `Bearer ${delegated.token}` }, signal: AbortSignal.timeout(5_000) })));
    assert.deepEqual(attempts.map(({ status }) => status).sort(), [200, 404]);
    const deleted = await attempts.find(({ status }) => status === 200).json();
    assert.equal(deleted.installationId, doomed.installationId);
    assert.equal(deleted.deletedRows.securityEvents, 2);
    assert.equal(deleted.deletedRows.eventTriage, 1);
    assert.equal(deleted.deletedRows.caseMemberships, 1);
    assert.ok(deleted.deletedRows.deliveryReceipts >= 0);

    const installations = await admin('installations');
    assert.ok(!installations.some(({ installationId }) => installationId === doomed.installationId));
    assert.ok(installations.some(({ installationId }) => installationId === kept.installationId));
    const events = await admin('events');
    assert.deepEqual(events.map(({ installationId }) => installationId), [kept.installationId]);
    const after = await admin(`cases/${caseId}`);
    assert.ok(after.case.triage.revision > before.case.triage.revision + 1);
    assert.equal(after.case.eventCount, 1);
    assert.ok(!after.events.some(({ installationId }) => installationId === doomed.installationId));
    await call('/v1/browser/policy', { token: doomed.token, expect: 401 });
    await call('/v1/browser/policy', { token: kept.token });

    const { entries } = await admin('audit?action=installation_deleted');
    assert.equal(entries.length, 1);
    assert.equal(entries[0].actor, 'named_administrator');
    assert.equal(entries[0].actorAccess.id, delegated.access.id);
    assert.deepEqual(Object.keys(entries[0].dataDeletion).sort(), ['deletedRows', 'installationId']);
    assert.equal(entries[0].dataDeletion.installationId, doomed.installationId);
    assert.deepEqual(entries[0].dataDeletion.deletedRows, deleted.deletedRows);
    assert.equal(entries[0].installationId, null);
    // Earlier enrollment and revocation entries keep only the installation ID.
    const revoked = (await admin('audit?action=browser_revoked')).entries;
    assert.ok(revoked.some(({ installationId }) => installationId === doomed.installationId));
    if (postgres) {
      const remaining = await retentionFixture(`SELECT sum(n) FROM (
        ${['security_events', 'event_triage', 'incident_case_events', 'security_alert_events', 'prompt_exception_requests', 'ai_app_observations',
          'extension_inventory_snapshots', 'extension_inventory_change_batches', 'composer_observations', 'policy_deliveries']
          .map((table) => `SELECT count(*) AS n FROM ${table} WHERE installation_id = '${doomed.installationId}'`).join(' UNION ALL ')}
        UNION ALL SELECT count(*) FROM installations WHERE id = '${doomed.installationId}') counts`);
      assert.equal(remaining, '0');
      assert.equal(await retentionFixture(`SELECT count(*) FROM security_events WHERE installation_id = '${kept.installationId}'`), '1');
    }
  });

  await t.test('purges superseded policy history while keeping current, reviewed, rolled-out, and evidenced versions', async () => {
    const admin = deletionAdmin(purgeAdmin);
    const post = deletionPost(purgeAdmin);
    const [v1] = await admin('policies');
    const eventBrowser = await enrollIn(purgeAdmin);
    await call('/v1/browser/policy', { token: eventBrowser.token });
    await sendEvent(eventBrowser, v1.version);
    const v2 = await post('policies', { mode: 'warn' });
    const appliedBrowser = await enrollIn(purgeAdmin);
    await call('/v1/browser/policy', { token: appliedBrowser.token });
    await call('/v1/browser/heartbeat', { token: appliedBrowser.token, method: 'POST', body: { policyVersion: v2.version }, expect: 204 });
    const v3 = await post('policies', { mode: 'block' });
    const v4 = await post('policies', { mode: 'monitor', githubPatMode: 'warn' });
    const v5 = await post('policies', { mode: 'warn' });
    const [staging, canary] = await Promise.all(['Purge staging', 'Purge canary'].map((name) => post('policy-groups', { name })));
    const source = await post(`policy-groups/${staging.id}/policies`, { mode: 'block' });
    const plan = await post('rollout-plans', { requestId: randomUUID(), name: 'Purge rollout', sourceVersion: source.version,
      stages: [{ groupId: canary.id, minSoakSeconds: 3600, minAcknowledgedPercent: 100 }] });
    assert.equal(plan.status, 'running');
    const stagingCurrent = await post(`policy-groups/${staging.id}/policies`, { mode: 'warn' });

    // The staging source stays while its rollout runs and becomes purgeable once the plan finishes.
    const groupCutoff = new Date().toISOString();
    const running = await post('policy-history/purge', { publishedBefore: groupCutoff, groupId: staging.id, dryRun: true });
    assert.deepEqual(running.versions, []);
    assert.deepEqual(running.kept, { current: 1, openReview: 0, activeRollout: 1, retainedEvent: 0, installation: 0, evidence: 0 });
    await post(`rollout-plans/${plan.id}/cancel`);
    // A concurrent publish serializes with the purge, and the version that is current afterwards is never removed.
    const [finished, newest] = await Promise.all([
      post('policy-history/purge', { publishedBefore: groupCutoff, groupId: staging.id }),
      post(`policy-groups/${staging.id}/policies`, { mode: 'monitor' }),
    ]);
    assert.ok(finished.versions.includes(source.version));
    assert.ok(!finished.versions.includes(newest.version));
    assert.equal((await admin(`policy-groups/${staging.id}/policies`))[0].version, newest.version);
    assert.equal((await admin(`rollout-plans/${plan.id}`)).sourceVersion, source.version);
    assert.ok((await admin('policies')).some(({ version }) => version === v5.version));
    void stagingCurrent;

    const reviewer = await post('access', { name: 'Purge reviewer', role: 'administrator', hours: 1 });
    const requester = await post('access', { name: 'Purge requester', role: 'administrator', hours: 1 });
    const auditor = await post('access', { name: 'Purge auditor', role: 'auditor', hours: 1 });
    await post('policy-reviews/setting', { required: true }, { expect: 204 });
    const { reviewId } = await post(`policies/${v3.version}/restore`, undefined, { token: requester.token, expectReview: true, expect: 202 });

    const cutoff = new Date().toISOString();
    await post('policy-history/purge', { publishedBefore: cutoff, dryRun: true }, { token: auditor.token, expect: 403 });
    await post('policy-history/purge', { publishedBefore: new Date(Date.now() + 60_000).toISOString() }, { expect: 400 });
    await post('policy-history/purge', { dryRun: true }, { expect: 400 });
    await post('policy-history/purge', { publishedBefore: cutoff, groupId: randomUUID() }, { expect: 404 });
    const foreign = await call('/v1/admin/policy-groups', { method: 'POST', token: second, body: { name: `Purge foreign ${suffix}` } });
    await post('policy-history/purge', { publishedBefore: cutoff, groupId: foreign.id }, { expect: 404 });

    const preview = await post('policy-history/purge', { publishedBefore: cutoff, dryRun: true });
    assert.deepEqual(preview.versions, [v4.version]);
    assert.deepEqual(preview.kept, { current: 1, openReview: 1, activeRollout: 0, retainedEvent: 1, installation: 1, evidence: 0 });
    assert.equal((await admin('policies')).length, 5);
    assert.equal((await admin('audit?action=policy_history_purged')).entries.length, 1);

    const purged = await post('policy-history/purge', { publishedBefore: cutoff }, { token: reviewer.token });
    assert.deepEqual(purged.versions, [v4.version]);
    assert.deepEqual((await admin('policies')).map(({ version }) => version), [v5.version, v3.version, v2.version, v1.version]);
    assert.ok((await admin('audit?action=policy_published')).entries.some(({ policyVersion }) => policyVersion === v4.version));
    const [entry] = (await admin('audit?action=policy_history_purged')).entries;
    assert.equal(entry.actorAccess.id, reviewer.access.id);
    assert.deepEqual(entry.dataDeletion.versions, [v4.version]);
    assert.equal(entry.dataDeletion.scope, 'baseline');
    assert.deepEqual((await post('policy-history/purge', { publishedBefore: cutoff })).versions, []);
    assert.equal((await admin('audit?action=policy_history_purged')).entries.length, 2);

    // The pending review still decides against the retained source version.
    assert.ok((await admin('policy-reviews')).entries.some(({ id, status }) => id === reviewId && status === 'pending'));
    const approved = await post(`policy-reviews/${reviewId}/decision`, { approve: true }, { token: reviewer.token });
    assert.equal(approved.restoredFrom, v3.version);
    await post('policy-reviews/setting', { required: false }, { expect: 204 });
    await post(`policies/${v4.version}/restore`, undefined, { expect: 404 });
  });

  await t.test('streams a complete owner-only tenant export without credential hashes', async () => {
    const admin = deletionAdmin(exportAdmin);
    const post = deletionPost(exportAdmin);
    const [initial] = await admin('policies');
    const browser = await enrollIn(exportAdmin);
    await call('/v1/browser/policy', { token: browser.token });
    const events = [];
    for (let index = 0; index < 30; index++) events.push(await sendEvent(browser, initial.version));
    await post('cases', { requestId: randomUUID(), category: 'other', installationId: browser.installationId, eventId: events[0].eventId });
    await post('policies', { mode: 'warn' });
    const delegated = await post('access', { name: 'Export admin', role: 'administrator', hours: 1 });
    const auditor = await post('access', { name: 'Export auditor', role: 'auditor', hours: 1 });
    for (const token of [delegated.token, auditor.token]) assert.equal((await rawFetch('/v1/admin/organization/export', token)).status, 403);
    assert.equal((await rawFetch('/v1/admin/organization/export')).status, 401);

    const response = await rawFetch('/v1/admin/organization/export', exportAdmin);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('content-length'), null);
    assert.match(response.headers.get('content-disposition'), /zekvar-organization-export\.json/);
    const text = await response.text();
    for (const secret of [exportAdmin, browser.token, delegated.token, auditor.token]) assert.ok(!text.includes(secret));
    assert.ok(!text.includes('token_hash'));
    const exported = JSON.parse(text);
    assert.equal(exported.type, 'zekvar.organization_export');
    assert.equal(exported.organization.slug, `export-${suffix}`);
    const org = exported.organization.id;
    assert.equal(exported.datasets.security_events.length, 30);
    assert.deepEqual(new Set(exported.datasets.security_events.map(({ event_id: id }) => id)), new Set(events.map(({ eventId }) => eventId)));
    assert.equal(exported.datasets.installations[0].id, browser.installationId);
    assert.equal(exported.datasets.policy_versions.length, 2);
    assert.equal(exported.datasets.incident_cases.length, 1);
    assert.equal(exported.datasets.control_access.length, 2);
    for (const [name, rows] of Object.entries(exported.datasets)) {
      assert.equal(exported.counts[name], rows.length, name);
      for (const row of rows) assert.equal(row.organization_id, org, name);
    }
    if (postgres) {
      const counts = await tenantCounts(org);
      for (const [name, rows] of Object.entries(exported.datasets)) assert.equal(rows.length, counts[name], name);
      // Every tenant table is exported except credential-only tables.
      assert.deepEqual(Object.keys(counts).filter((table) => !(table in exported.datasets)).sort(), ['admin_memberships', 'enrollment_grants']);
    }
    assert.equal((await admin('audit?action=organization_exported')).entries.length, 1);
  });

  await t.test('locks every credential during the deletion grace period and restores them when the owner cancels', async () => {
    const admin = deletionAdmin(offboardCancelAdmin);
    const post = deletionPost(offboardCancelAdmin);
    const slug = `offboard-cancel-${suffix}`;
    const [initial] = await admin('policies');
    const browser = await enrollIn(offboardCancelAdmin);
    await call('/v1/browser/policy', { token: browser.token });
    const delegated = await post('access', { name: 'Offboard admin', role: 'administrator', hours: 1 });
    const auditor = await post('access', { name: 'Offboard auditor', role: 'auditor', hours: 1 });
    const feed = await post('access/event-feed', { requestId: randomUUID(), name: 'Offboard SIEM', days: 1 });
    const { grant } = await post('enrollment-grants');
    const enrollmentKey = await post('enrollment-keys', { requestId: randomUUID(), label: 'Offboard key', days: 1 });
    const keyNonce = () => randomBytes(32).toString('hex');
    await call('/v1/integrations/events', { token: feed.token });

    assert.deepEqual(await admin('organization/deletion'), { deletion: null, graceDays: 7, available: true });
    await admin('organization/deletion', { token: delegated.token, expect: 403 });
    await admin('organization/deletion', { token: auditor.token, expect: 403 });
    await post('organization/deletion', { confirmSlug: slug }, { token: delegated.token, expect: 403 });
    await admin('organization/export', { token: auditor.token, expect: 403 });
    for (const confirmSlug of [undefined, '', slug.toUpperCase(), `first-${suffix}`])
      assert.equal((await post('organization/deletion', { confirmSlug }, { expect: 400 })).code, 'deletion_confirmation_mismatch');
    await post('organization/deletion/cancel', undefined, { expect: 404 });

    const requested = await post('organization/deletion', { confirmSlug: slug }, { expect: 202 });
    assert.equal(requested.deletion.status, 'pending');
    assert.match(requested.receiptToken, /^[a-f0-9]{64}$/);
    const grace = Date.parse(requested.deletion.purgeAfter) - Date.parse(requested.deletion.requestedAt);
    assert.equal(grace, 7 * 24 * 3600 * 1000);

    // Credentials stop working immediately.
    await admin('policies', { token: delegated.token, expect: 401 });
    await admin('audit', { token: auditor.token, expect: 401 });
    await call('/v1/browser/policy', { token: browser.token, expect: 401 });
    await call('/v1/browser/heartbeat', { token: browser.token, method: 'POST', body: { policyVersion: initial.version }, expect: 401 });
    await call('/v1/browser/events', { token: browser.token, method: 'POST', body: { ...contract.event, eventId: randomUUID() }, expect: 401 });
    await call('/v1/integrations/events', { token: feed.token, expect: 401 });
    await call('/v1/enroll', { method: 'POST', body: { grant }, expect: 401 });
    assert.deepEqual(await call('/v1/enroll/key', { method: 'POST', body: { key: enrollmentKey.token, nonce: keyNonce() }, expect: 401 }),
      { code: 'enrollment_key_invalid' });
    // The owner can only review, export, cancel, or download the receipt.
    for (const path of ['policies', 'installations', 'audit', 'access', 'retention'])
      assert.deepEqual(await admin(path, { expect: 403 }), { code: 'organization_deletion_pending' });
    await post('enrollment-grants', undefined, { expect: 403 });
    await post('organization/deletion', { confirmSlug: slug }, { expect: 403 });
    const session = await admin('session');
    assert.equal(session.deletion.id, requested.deletion.id);
    assert.equal((await admin('organization/deletion')).deletion.status, 'pending');
    assert.equal((await rawFetch('/v1/admin/organization/export', offboardCancelAdmin)).status, 200);
    assert.equal((await admin('policies', { token: first })).length >= 1, true);

    const response = await rawFetch('/v1/admin/organization/deletion/receipt', offboardCancelAdmin);
    assert.match(response.headers.get('content-disposition'), /zekvar-deletion-receipt\.json/);
    const provisional = await response.json();
    assert.ok(verifyReceipt(provisional));
    assert.equal(provisional.receipt.status, 'pending');
    assert.equal(provisional.receipt.rowsMeaning, 'held_at_issue');
    assert.equal(provisional.receipt.tables.find(({ table }) => table === 'installations').rows, 1);
    assert.ok(!verifyReceipt({ ...provisional, receipt: { ...provisional.receipt, totalRows: provisional.receipt.totalRows + 1 } }));
    assert.equal((await rawFetch(`/v1/organization-deletions/${requested.deletion.id}/receipt`, requested.receiptToken)).status, 200);
    assert.equal((await rawFetch(`/v1/organization-deletions/${requested.deletion.id}/receipt`, offboardCancelAdmin)).status, 401);
    assert.equal((await rawFetch(`/v1/organization-deletions/${randomUUID()}/receipt`, requested.receiptToken)).status, 401);

    const cancelled = await post('organization/deletion/cancel');
    assert.equal(cancelled.status, 'cancelled');
    await post('organization/deletion/cancel', undefined, { expect: 404 });
    await admin('policies', { token: delegated.token });
    await admin('audit', { token: auditor.token });
    await call('/v1/browser/policy', { token: browser.token });
    await call('/v1/integrations/events', { token: feed.token });
    await call('/v1/enroll', { method: 'POST', body: { grant } });
    await call('/v1/enroll/key', { method: 'POST', body: { key: enrollmentKey.token, nonce: keyNonce() } });
    assert.equal((await admin('organization/deletion')).deletion.status, 'cancelled');
    assert.equal((await rawFetch(`/v1/organization-deletions/${requested.deletion.id}/receipt`, requested.receiptToken)).status, 401);
    const actions = (await admin('audit?limit=1000')).entries.map(({ action }) => action);
    for (const action of ['organization_deletion_requested', 'organization_deletion_cancelled', 'organization_exported'])
      assert.ok(actions.includes(action), action);
    const [requestAudit] = (await admin('audit?action=organization_deletion_requested')).entries;
    assert.equal(requestAudit.dataDeletion.deletionId, requested.deletion.id);
    if (postgres) assert.equal(await retentionFixture(`SELECT status FROM organization_deletions WHERE id = '${requested.deletion.id}'`), 'cancelled');
  });

  await t.test('accepts exactly one of several concurrent deletion requests and one concurrent cancellation', async () => {
    const post = deletionPost(raceAdmin);
    const slug = `offboard-race-${suffix}`;
    const request = () => fetch(`${baseUrl}/v1/admin/organization/deletion`, { method: 'POST', signal: AbortSignal.timeout(5_000),
      headers: { Authorization: `Bearer ${raceAdmin}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ confirmSlug: slug }) });
    const statuses = (await Promise.all(Array.from({ length: 6 }, request))).map(({ status }) => status);
    assert.equal(statuses.filter((status) => status === 202).length, 1, String(statuses));
    assert.ok(statuses.every((status) => [202, 403, 409].includes(status)), String(statuses));
    const cancel = () => fetch(`${baseUrl}/v1/admin/organization/deletion/cancel`, { method: 'POST', signal: AbortSignal.timeout(5_000),
      headers: { Authorization: `Bearer ${raceAdmin}` } });
    const cancels = (await Promise.all(Array.from({ length: 4 }, cancel))).map(({ status }) => status).sort();
    assert.deepEqual(cancels, [200, 404, 404, 404]);
    if (postgres) {
      assert.equal(await retentionFixture(`SELECT string_agg(status, ',') FROM organization_deletions
        WHERE organization_id = (SELECT id FROM organizations WHERE slug = '${slug}')`), 'cancelled');
    }
    const again = await post('organization/deletion', { confirmSlug: slug }, { expect: 202 });
    assert.equal((await post('organization/deletion/cancel')).id, again.deletion.id);
  });

  await t.test('permanently deletes an organization in resumable batches, verifies zero rows, and signs a reproducible receipt', {
    skip: !postgres && 'Set ZEKVAR_TEST_POSTGRES_CONTAINER to advance the grace period and inject failures.',
  }, async (deletion) => {
    deletion.after(() => retentionFixture(`DROP TABLE IF EXISTS zz_unplanned_feature;
      DROP TRIGGER IF EXISTS zz_block_access_delete ON control_access; DROP FUNCTION IF EXISTS zz_block_access_delete()`));
    const admin = deletionAdmin(offboardAdmin);
    const post = deletionPost(offboardAdmin);
    const slug = `offboard-delete-${suffix}`;
    const org = await organizationId(slug);
    const [initial] = await admin('policies');
    const group = await post('policy-groups', { name: 'Offboard ring' });
    await post(`policy-groups/${group.id}/policies`, { mode: 'block' });
    const [browser, revoked] = await Promise.all([enrollIn(offboardAdmin), enrollIn(offboardAdmin)]);
    for (const installation of [browser, revoked]) await call('/v1/browser/policy', { token: installation.token });
    const events = [];
    for (let index = 0; index < 40; index++) events.push(await sendEvent(index % 2 ? browser : revoked, initial.version));
    await post(`events/${browser.installationId}/${events[1].eventId}/triage`, { expectedRevision: 0, status: 'investigating' });
    await post('cases', { requestId: randomUUID(), category: 'other', installationId: browser.installationId, eventId: events[1].eventId });
    await post(`installations/${revoked.installationId}/revoke`, undefined, { expect: 204 });
    await post('policies', { mode: 'warn' });
    await post('policy-templates', { name: 'Offboard template', sourceVersion: initial.version });
    await post('retention', { securityEventDays: 365, aiObservationDays: null, auditDays: null }, { expect: 204 });
    await post('enrollment-batches', { requestId: randomUUID(), groupId: null, count: 2 });
    const delegated = await post('access', { name: 'Offboard delete admin', role: 'administrator', hours: 1 });
    const feed = await post('access/event-feed', { requestId: randomUUID(), name: 'Offboard delete SIEM', days: 1 });
    const firstPolicies = await call('/v1/admin/policies', { token: first });

    const requested = await post('organization/deletion', { confirmSlug: slug }, { expect: 202 });
    const before = await tenantCounts(org);
    const held = Object.values(before).reduce((sum, count) => sum + count, 0);
    assert.ok(held > 60, `expected a populated tenant, found ${held} rows`);
    const ledger = (column) => retentionFixture(`SELECT ${column} FROM organization_deletions WHERE id = '${requested.deletion.id}'`);
    async function waitFor(check, explanation) {
      for (let attempt = 0; attempt < 150; attempt++) {
        if (await check()) return;
        await delay(200);
      }
      assert.fail(explanation);
    }

    // A table the plan does not handle stops deletion before any row is removed.
    await retentionFixture(`
      CREATE TABLE zz_unplanned_feature (organization_id uuid NOT NULL);
      CREATE FUNCTION zz_block_access_delete() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN RAISE EXCEPTION 'injected deletion failure'; END $$;
      CREATE TRIGGER zz_block_access_delete BEFORE DELETE ON control_access FOR EACH ROW
        WHEN (OLD.organization_id = '${org}') EXECUTE FUNCTION zz_block_access_delete();
      UPDATE organization_deletions SET purge_after = requested_at + interval '1 millisecond' WHERE id = '${requested.deletion.id}'`);
    await waitFor(async () => await ledger('last_error') === 'unhandled_tenant_table', 'deletion did not refuse the unplanned table');
    assert.equal(await ledger('deleted_rows::text'), '{}');
    assert.deepEqual(await tenantCounts(org), before);
    assert.equal((await admin('organization/deletion')).deletion.status, 'deleting');
    assert.deepEqual(await post('organization/deletion/cancel', undefined, { expect: 409 }), { code: 'organization_deletion_in_progress' });
    assert.deepEqual(await admin('organization/export', { expect: 409 }), { code: 'organization_deletion_in_progress' });
    await admin('policies', { token: delegated.token, expect: 401 });

    // An injected failure stops the job part way; committed batches stay deleted and the credentials stay locked.
    await retentionFixture('DROP TABLE zz_unplanned_feature');
    await waitFor(async () => await ledger('last_error') === 'batch_failed', 'deletion did not record the injected failure');
    const partial = JSON.parse(await ledger('deleted_rows::text'));
    assert.equal(partial.security_events, 40);
    assert.equal(partial.control_access, undefined);
    assert.ok(Number(await ledger('batches')) > 1);
    const midway = await tenantCounts(org);
    assert.equal(midway.security_events, 0);
    assert.equal(midway.control_access, before.control_access);
    assert.equal(await retentionFixture(`SELECT count(*) FROM organizations WHERE id = '${org}'`), '1');
    await call('/v1/integrations/events', { token: feed.token, expect: 401 });
    await call('/v1/browser/policy', { token: browser.token, expect: 401 });
    assert.equal((await admin('organization/deletion')).deletion.status, 'deleting');

    // Restarting with the fault removed resumes from the recorded progress.
    await stop();
    await retentionFixture('DROP TRIGGER zz_block_access_delete ON control_access; DROP FUNCTION zz_block_access_delete()');
    await start();
    await waitFor(async () => await ledger('status') === 'completed', 'deletion did not resume and complete');
    assert.equal(await ledger('last_error'), '');

    const after = await tenantCounts(org);
    assert.deepEqual(Object.entries(after).filter(([, count]) => count !== 0), []);
    assert.equal(await retentionFixture(`SELECT count(*) FROM organizations WHERE id = '${org}' OR slug = '${slug}'`), '0');
    assert.equal(await retentionFixture(`SELECT count(*) FROM control_sso_sessions s WHERE NOT EXISTS (
      SELECT 1 FROM control_access c WHERE c.id = s.access_id)`), '0');

    const response = await rawFetch(`/v1/organization-deletions/${requested.deletion.id}/receipt`, requested.receiptToken);
    assert.equal(response.status, 200);
    const final = await response.json();
    assert.ok(verifyReceipt(final));
    const { receipt } = final;
    assert.equal(receipt.status, 'completed');
    assert.equal(receipt.organizationId, org);
    assert.equal(receipt.deletionId, requested.deletion.id);
    // The receipt always prints six fractional digits; the API's JSON drops trailing zeros.
    assert.equal(receipt.requestedAt.replace(/0*Z$/, 'Z'), requested.deletion.requestedAt.replace(/0*Z$/, 'Z'));
    assert.ok(Date.parse(receipt.completedAt) >= Date.parse(receipt.startedAt));
    assert.deepEqual(receipt.verification, { method: 'per_table_zero_count', tablesChecked: (await tenantTables()).length, remainingRows: 0 });
    assert.equal(receipt.backups.notice, 'deleted_data_persists_in_encrypted_backups_until_they_age_out');
    const receiptRows = Object.fromEntries(receipt.tables.map(({ table, rows }) => [table, rows]));
    for (const [table, count] of Object.entries(before)) assert.equal(receiptRows[table], count, table);
    assert.equal(receiptRows.organizations, 1);
    assert.equal(receipt.totalRows, receipt.tables.reduce((sum, { rows }) => sum + rows, 0));
    assert.ok(!JSON.stringify(final).includes(slug));
    // An operator reproduces the signature from the ledger with the server key.
    const stored = await ledger('receipt');
    assert.deepEqual(JSON.parse(stored), receipt);
    assert.equal(createHmac('sha256', Buffer.from(deletionKey, 'hex')).update(stored).digest('hex'), await ledger('receipt_signature'));
    assert.equal(final.signature.value, await ledger('receipt_signature'));

    // Every credential is gone, and a restart does not recreate the organization from configuration.
    await call('/v1/admin/session', { token: offboardAdmin, expect: 401 });
    await call('/v1/admin/session', { token: delegated.token, expect: 401 });
    await stop();
    await start();
    await call('/v1/admin/session', { token: offboardAdmin, expect: 401 });
    assert.equal(await retentionFixture(`SELECT count(*) FROM organizations WHERE slug = '${slug}'`), '0');
    assert.equal((await rawFetch(`/v1/organization-deletions/${requested.deletion.id}/receipt`, requested.receiptToken)).status, 200);
    assert.deepEqual(await call('/v1/admin/policies', { token: first }), firstPolicies);
  });

  await t.test('organization deletion handles every table in the schema in dependency order', {
    skip: !postgres && 'Set ZEKVAR_TEST_POSTGRES_CONTAINER to read the schema.',
  }, async () => {
    const source = await readFile(new URL('../DataDeletion.cs', import.meta.url), 'utf8');
    const plan = source.slice(source.indexOf('// BEGIN tenant deletion plan'), source.indexOf('// END tenant deletion plan'));
    const [ordered, retained] = plan.split('RetainedTables');
    const order = [...ordered.matchAll(/new\("([a-z_]+)"/g)].map(([, name]) => name);
    const kept = [...retained.matchAll(/"([a-z_]+)"/g)].map(([, name]) => name);
    assert.ok(order.length > 30);
    assert.equal(new Set(order).size, order.length);
    const tables = (await retentionFixture(`SELECT string_agg(c.relname, ',' ORDER BY c.relname) FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND NOT c.relispartition`)).split(',');
    const unhandled = tables.filter((table) => !order.includes(table) && !kept.includes(table));
    assert.deepEqual(unhandled, [], `Add these tables to the organization deletion plan in DataDeletion.cs: ${unhandled.join(', ')}`);
    const tenant = (await tenantTables()).filter((table) => !kept.includes(table));
    assert.deepEqual(tenant.filter((table) => !order.includes(table)), []);
    assert.deepEqual(order.filter((table) => !tables.includes(table)), [], 'The deletion plan names a table that does not exist.');
    // Children are deleted before the rows they reference. Groups and versions reference each other; the job clears
    // group pointers before deleting versions.
    const references = (await retentionFixture(`SELECT DISTINCT conrelid::regclass::text || '>' || confrelid::regclass::text
      FROM pg_constraint WHERE contype = 'f' AND conrelid <> confrelid`)).split('\n').map((line) => line.split('>'));
    for (const [child, parent] of references) {
      if (child === 'policy_groups' && parent === 'policy_versions') continue;
      assert.ok(order.indexOf(child) < order.indexOf(parent), `${child} must be deleted before ${parent}`);
    }
  });
});
