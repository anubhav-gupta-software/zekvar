import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

const db = process.env.ZEKVAR_TEST_DATABASE;
assert.ok(db, 'Set ZEKVAR_TEST_DATABASE to a disposable PostgreSQL connection string.');
const contract = JSON.parse(await readFile(new URL('../../../contracts/control/demo-v1.json', import.meta.url)));
const app = fileURLToPath(new URL('../bin/Debug/net10.0/Control.Api.dll', import.meta.url));
const port = process.env.ZEKVAR_TEST_API_PORT ?? '5187';
const baseUrl = `http://127.0.0.1:${port}`;
const suffix = randomBytes(8).toString('hex');
const first = randomBytes(32).toString('hex');
const second = randomBytes(32).toString('hex');

async function call(path, { token, method = 'GET', body, expect = 200 } = {}) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
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

async function start() {
  processHandle = spawn('dotnet', [app], {
    env: {
      ...process.env,
      DOTNET_ENVIRONMENT: 'Development',
      ASPNETCORE_ENVIRONMENT: 'Development',
      ConnectionStrings__Control: db,
      Control__Port: port,
      Control__Organizations__0__Slug: `first-${suffix}`,
      Control__Organizations__0__AdminToken: first,
      Control__Organizations__1__Slug: `second-${suffix}`,
      Control__Organizations__1__AdminToken: second,
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
});
