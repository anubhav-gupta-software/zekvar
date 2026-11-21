import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
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

async function retentionFixture(query) {
  assert.match(postgres ?? '', /^zekvar-demo-[a-f0-9]{10}$/);
  const { stdout } = await sql('docker', ['exec', postgres, 'psql', '-XAtq', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'zekvar', '-c', query]);
  return stdout.trim();
}

async function call(path, { token, method = 'GET', body, expect = 200, assignmentAware = false } = {}) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (assignmentAware) headers['X-Zekvar-Assignment-Aware'] = '1';
  const response = await fetch(`${baseUrl}${path}`, {
    method, headers, body: body !== undefined ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(5_000),
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

test('Control persists tenant-scoped policies, enrollment and metadata in PostgreSQL', { timeout: 30_000 }, async (t) => {
  t.after(stop);
  await start();
  let client;
  let current;
  const event = { ...contract.event, eventId: randomUUID() };

  await t.test('only an admin can issue a short-lived grant, and only one redemption succeeds', async () => {
    await call('/v1/admin/session', { expect: 401 });
    assert.deepEqual(await call('/v1/admin/session', { token: first }), { organization: `first-${suffix}` });
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
});
