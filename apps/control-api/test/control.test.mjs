import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
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
const postgres = process.env.ZEKVAR_TEST_POSTGRES_CONTAINER;
const sql = promisify(execFile);

const undoSsoSchema = `
  DELETE FROM schema_migrations WHERE version = 21;
  DROP TABLE control_sso_sessions;
  ALTER TABLE control_access DROP CONSTRAINT control_access_type_check,
      DROP COLUMN oidc_issuer, DROP COLUMN oidc_subject, ALTER COLUMN expires_at SET NOT NULL,
      ADD CONSTRAINT control_access_check1 CHECK ((revoked_at IS NULL) = (token_hash IS NOT NULL));
`;

async function retentionFixture(query) {
  assert.match(postgres ?? '', /^zekvar-demo-[a-f0-9]{10}$/);
  const { stdout } = await sql('docker', ['exec', postgres, 'psql', '-XAtq', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'zekvar', '-c', query]);
  return stdout.trim();
}

async function call(path, { token, method = 'GET', body, expect = 200, assignmentAware = false, expectReview = false, claudeAware = false } = {}) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (claudeAware) headers['X-Zekvar-Claude-Prompt'] = '1';
  if (assignmentAware) headers['X-Zekvar-Assignment-Aware'] = '1';
  if (expectReview) headers['X-Zekvar-Expect-Review'] = '1';
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

async function start(sweepSeconds = 3600) {
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
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  exited = once(processHandle, 'exit');
  let logs = '';
  let ready = false;
  processHandle.stdout.on('data', (chunk) => {
    logs = (logs + chunk).slice(-4000);
    ready ||= logs.includes(`Now listening on: ${baseUrl}`);
  });
  processHandle.stderr.on('data', (chunk) => { logs = (logs + chunk).slice(-4000); });
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

test('Control persists tenant-scoped policies, enrollment and metadata in PostgreSQL', { timeout: 60_000 }, async (t) => {
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
    assert.deepEqual(await call('/v1/browser/policy', { token: client.token }), current);
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
    assert.deepEqual(metadata, event);
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
    assert.deepEqual(await call('/v1/browser/policy', { token: client.token }), current);
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
    assert.deepEqual(metadata, historical);
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
    assert.deepEqual((await inventory()).map((app) => app.appId), ['chatgpt', 'claude', 'gemini']);
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
    assert.deepEqual((await admin('ai-apps')).map(({ browsersSeen }) => browsersSeen), [1, 0, 0]);
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
    assert.deepEqual(await fetchPolicy(canary), { ...candidate, assignmentVersion: 1 });
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
    assert.deepEqual(await fetchPolicy(canary), { ...newBaseline, assignmentVersion: 2 });
    await browserPost('heartbeat', canary, { ...acknowledgment, policyVersion: restored.version }, 400);
    await browserPost('heartbeat', canary, { policyVersion: newBaseline.version, assignmentVersion: 2 });
    await browserPost('events', canary, scopedEvent);
    await browserPost('ai-app-observations', canary, observation, 400);
    assert.equal((await admin('events')).find(({ eventId }) => eventId === scopedEvent.eventId).policyVersion, candidate.version);
    await admin(`${groupPath}/promote`, { method: 'POST', body: { expectedVersion: candidate.version }, expect: 409 });
    assert.deepEqual(await fetchPolicy(control), newBaseline);
    const promoted = await admin(`${groupPath}/promote`, { method: 'POST', body: { expectedVersion: restored.version } });
    assert.equal(promoted.mode, restored.mode);
    assert.equal(promoted.githubPatMode, restored.githubPatMode);
    assert.equal(promoted.discoveryEnabled, restored.discoveryEnabled);
    assert.deepEqual(promoted.domainRules, restored.domainRules);
    assert.deepEqual(await fetchPolicy(control), promoted);
    const actions = await admin('audit?action=policy_group_assigned');
    assert.deepEqual(actions.entries.map(({ groupChange }) => groupChange.groupId), [null, pilot.id]);
    assert.ok((await admin('audit?action=policy_published')).entries.some(({ policyVersion, groupChange }) =>
      policyVersion === promoted.version && groupChange.groupId === pilot.id && groupChange.sourceVersion === restored.version));
    await stop();
    await start();
    assert.deepEqual(await fetchPolicy(canary), { ...promoted, assignmentVersion: 2 });
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
      'appId', 'decision', 'detectorCategory', 'eventId', 'installationId', 'policyVersion', 'receivedAt', 'ruleId', 'timestamp',
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
    await publish({ uploadModes: { claude: 'block' } }, 400);
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
      {}, { claude: ['.pdf'] }, { chatgpt: [null] }, { chatgpt: '.pdf' }, { chatgpt: ['   '] },
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
        DELETE FROM schema_migrations WHERE version IN (14, 15, 21);
        DROP TABLE control_sso_sessions;
        DROP TABLE policy_reviews;
        ALTER TABLE organizations DROP COLUMN require_policy_review;
        ALTER TABLE control_audit DROP COLUMN review_change, DROP COLUMN actor_access_id, DROP COLUMN subject_access_id;
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
        DELETE FROM schema_migrations WHERE version = 19;
        ALTER TABLE policy_versions DROP COLUMN prompt_exceptions;
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
});
