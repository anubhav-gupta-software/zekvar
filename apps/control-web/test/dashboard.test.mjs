import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { chromium } from 'playwright';

const dashboard = process.env.ZEKVAR_TEST_WEB_ORIGIN ?? 'http://localhost:3000';
const api = `${process.env.ZEKVAR_TEST_API_ORIGIN ?? 'http://127.0.0.1:5187'}/v1`;
const token = process.env.ZEKVAR_TEST_ADMIN_TOKEN;
assert.match(token ?? '', /^[a-f0-9]{64}$/, 'Set ZEKVAR_TEST_ADMIN_TOKEN for a disposable demo organization.');
const { event } = JSON.parse(await readFile(new URL('../../../contracts/control/demo-v1.json', import.meta.url)));

async function post(path, body, bearer) {
  const response = await fetch(`${api}${path}`, {
    method: 'POST',
    headers: {
      ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(5000),
  });
  assert.ok(response.ok, `POST ${path} returned ${response.status}`);
  return response.status === 204 ? undefined : response.json();
}

test('Control dashboard signs in and manages a real browser installation and event', { timeout: 45_000 }, async (t) => {
  const browser = await chromium.launch({ channel: 'chromium' });
  t.after(() => browser.close());
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  const page = await context.newPage();
  page.setDefaultTimeout(5000);
  const clientErrors = [];
  page.on('pageerror', (error) => clientErrors.push(error.message));
  await page.goto(dashboard);

  await t.test('rejects invalid tokens and keeps a successful session HTTP-only', async () => {
    const denied = await context.request.get(`${dashboard}/audit/export`);
    assert.equal(denied.status(), 401);
    assert.equal(denied.headers()['cache-control'], 'no-store');
    assert.equal((await context.request.get(`${dashboard}/events/export`)).status(), 401);
    await page.getByLabel('Control token').fill('0'.repeat(64));
    await page.getByRole('button', { name: 'Sign in' }).click();
    await page.getByRole('alert').filter({ hasText: 'This Control token was rejected.' }).waitFor();
    await page.getByLabel('Control token').fill(token);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await page.getByRole('heading', { name: 'Security overview' }).waitFor();
    await page.reload();
    await page.getByRole('heading', { name: 'Security overview' }).waitFor();
    const [session] = (await context.cookies()).filter(({ name }) => name === 'zekvar_control_session');
    assert.ok(session?.httpOnly);
    assert.equal(session.sameSite, 'Strict');
    assert.notEqual(session.value, token);
    assert.ok(!(await page.content()).includes(token));
  });

  let installation;
  let enrollmentGrant;
  let policyVersion;
  const policyHistory = page.getByRole('table', { name: 'Policy history' });
  const browsers = page.getByRole('table', { name: 'Browser health' });
  const events = page.getByRole('table', { name: 'Security events' });

  await t.test('creates a grant and shows the enrolled browser', async () => {
    await page.getByRole('button', { name: 'Create enrollment grant' }).click();
    await page.getByLabel('Enrollment grant', { exact: true }).waitFor();
    enrollmentGrant = await page.getByLabel('Enrollment grant', { exact: true }).inputValue();
    assert.match(enrollmentGrant, /^[a-f0-9]{64}$/);
    installation = await post('/enroll', { grant: enrollmentGrant });
    await page.reload();
    await browsers.getByText('Awaiting policy', { exact: true }).waitFor();
    assert.equal(await page.getByLabel('Enrollment grant', { exact: true }).count(), 0);
  });

  await t.test('publishes a policy and shows the version applied by the browser', async () => {
    await page.getByLabel('Test marker', { exact: true }).selectOption('warn');
    await page.getByRole('button', { name: 'Publish policy' }).click();
    await page.getByRole('status').filter({ hasText: /published in warn mode/ }).waitFor();
    policyVersion = Number((await policyHistory.locator('tbody tr').first().locator('td').first().textContent()).slice(1));
    assert.ok(policyVersion > 1);
    await post('/browser/heartbeat', { policyVersion }, installation.token);
    await page.reload();
    await browsers.getByText('Current', { exact: true }).waitFor();
  });

  await t.test('shows and filters metadata from a real policy event', async () => {
    await post('/browser/events', {
      ...event, eventId: randomUUID(), policyVersion, decision: 'warn', timestamp: new Date().toISOString(),
    }, installation.token);
    await post('/browser/events', {
      ...event, appId: 'chatgpt', eventId: randomUUID(), policyVersion, decision: 'warn', timestamp: new Date().toISOString(),
    }, installation.token);
    await post('/browser/heartbeat', { policyVersion, chatGptCoverage: 'unsupported' }, installation.token);
    await page.reload();
    await events.getByText('Local prompt fixture', { exact: true }).first().waitFor();
    await events.getByText('ChatGPT', { exact: true }).first().waitFor();
    await browsers.getByText('Unsupported', { exact: true }).first().waitFor();
    await page.getByLabel('Application', { exact: true }).selectOption('chatgpt');
    await page.getByRole('button', { name: 'Apply filters' }).click();
    await page.waitForURL((url) => url.searchParams.get('app') === 'chatgpt');
    await events.getByText('ChatGPT', { exact: true }).first().waitFor();
    assert.equal(await events.getByText('Local prompt fixture', { exact: true }).count(), 0);
    await page.getByLabel('Application', { exact: true }).selectOption('local-prompt-fixture');
    await page.getByLabel('Decision', { exact: true }).selectOption('block');
    await page.getByLabel('Time range', { exact: true }).selectOption('day');
    await page.getByRole('button', { name: 'Apply filters' }).click();
    await page.getByText('No events match these filters.', { exact: true }).waitFor();
    assert.equal(new URL(page.url()).searchParams.get('period'), 'day');
    await page.getByRole('link', { name: 'Clear filters' }).click();
    await events.getByText('Synthetic secret', { exact: true }).first().waitFor();
  });

  await t.test('configures tenant retention and confirms cleanup in Control', async () => {
    const oldEvent = { ...event, eventId: randomUUID(), policyVersion, decision: 'warn',
      timestamp: new Date(Date.now() - 3 * 86_400_000).toISOString() };
    await post('/browser/events', oldEvent, installation.token);
    await page.getByRole('link', { name: 'Data retention', exact: true }).click();
    await page.getByRole('heading', { name: 'Data retention', exact: true }).waitFor();
    const eventDays = page.getByLabel('Security events (days)', { exact: true });
    assert.equal(await eventDays.inputValue(), '');
    await eventDays.fill('1');
    await page.getByLabel('AI observations (days)', { exact: true }).fill('30');
    await page.getByLabel('Audit log (days)', { exact: true }).fill('90');
    page.once('dialog', (dialog) => dialog.accept());
    await page.getByRole('button', { name: 'Save retention' }).click();
    await page.getByText('Retention settings saved.', { exact: true }).waitFor();
    await page.reload();
    assert.equal(await eventDays.inputValue(), '1');
    assert.equal(await page.getByLabel('AI observations (days)', { exact: true }).inputValue(), '30');
    assert.equal(await page.getByLabel('Audit log (days)', { exact: true }).inputValue(), '90');
    const cleanup = page.getByRole('button', { name: 'Run cleanup' });
    page.once('dialog', (dialog) => dialog.dismiss());
    await cleanup.click();
    assert.equal(await page.getByText(/Deleted \d+ security event/).count(), 0);
    page.once('dialog', (dialog) => dialog.accept());
    await cleanup.click();
    await page.getByText('Deleted 1 security event, 0 AI observations, 0 audit entries.', { exact: true }).waitFor();
    const screenshot = process.env.ZEKVAR_TEST_RETENTION_SCREENSHOT;
    if (screenshot) await page.screenshot({ path: screenshot, fullPage: true });
    await page.getByRole('link', { name: 'Audit log', exact: true }).click();
    const audit = page.getByRole('table', { name: 'Control activity' });
    await audit.getByText('Expired records deleted', { exact: true }).first().waitFor();
    await audit.getByText('Security events · 1 day', { exact: true }).first().waitFor();
    await page.getByRole('link', { name: 'Overview', exact: true }).click();
    await events.getByText('Synthetic secret', { exact: true }).first().waitFor();
    assert.equal(await events.locator('tbody tr').count(), 2);
  });

  await t.test('restores an earlier policy and revokes the installation', async () => {
    await page.getByRole('button', { name: 'Restore version 1', exact: true }).click();
    await page.getByRole('status').filter({ hasText: `Version 1 restored as version ${policyVersion + 1}.` }).waitFor();
    await browsers.getByText('Update pending', { exact: true }).waitFor();
    assert.equal(await page.getByLabel('Test marker', { exact: true }).inputValue(), 'monitor');
    page.once('dialog', (dialog) => dialog.accept());
    await page.getByRole('button', { name: `Revoke installation ${installation.installationId}` }).click();
    await browsers.getByText('Revoked', { exact: true }).first().waitFor();
  });

  await t.test('reviews and downloads the tenant audit log with the selected dates and action', async () => {
    await page.getByLabel('Claude classification', { exact: true }).selectOption('approved');
    await page.getByRole('button', { name: 'Save Claude classification' }).click();
    await page.getByText('Claude classification saved.', { exact: true }).waitFor();
    await page.getByRole('link', { name: 'Audit log', exact: true }).click();
    await page.getByRole('heading', { name: 'Audit log', exact: true }).waitFor();
    const audit = page.getByRole('table', { name: 'Control activity' });
    for (const label of ['Policy published', 'Policy restored', 'Enrollment grant issued', 'Browser enrolled', 'Browser revoked', 'AI app classified']) {
      await audit.getByText(label, { exact: true }).first().waitFor();
    }
    await audit.getByText(`v${policyVersion + 1} from v1`, { exact: true }).waitFor();
    await audit.getByText('Claude · Approved', { exact: true }).waitFor();
    assert.ok(![token, enrollmentGrant, installation.token].some((value) => page.url().includes(value)));
    const screenshot = process.env.ZEKVAR_TEST_AUDIT_SCREENSHOT;
    if (screenshot) await page.screenshot({ path: screenshot, fullPage: true });

    const today = new Date().toISOString().slice(0, 10);
    await page.getByLabel('Action', { exact: true }).selectOption('policy_restored');
    await page.getByLabel('From (UTC)', { exact: true }).fill(today);
    await page.getByLabel('Through (UTC)', { exact: true }).fill(today);
    await page.getByRole('button', { name: 'Apply filters' }).click();
    await page.waitForURL((url) => url.searchParams.get('action') === 'policy_restored');
    await audit.getByText('Policy restored', { exact: true }).first().waitFor();
    assert.equal(await audit.getByText('Browser revoked', { exact: true }).count(), 0);
    const link = page.getByRole('link', { name: 'Export JSON', exact: true });
    const exported = await context.request.get(new URL(await link.getAttribute('href'), dashboard).href);
    assert.equal(exported.headers()['cache-control'], 'no-store');
    assert.equal(exported.headers()['x-content-type-options'], 'nosniff');
    assert.match(exported.headers()['content-disposition'], /^attachment/);
    const downloadPromise = page.waitForEvent('download');
    await link.click();
    const download = await downloadPromise;
    assert.equal(download.suggestedFilename(), 'zekvar-control-audit.json');
    const downloaded = await readFile(await download.path(), 'utf8');
    const { organization, exportedAt, entries, next } = JSON.parse(downloaded);
    assert.equal(organization, await page.locator('.eyebrow').textContent());
    assert.ok(Number.isFinite(Date.parse(exportedAt)));
    assert.equal(next, null);
    assert.ok(entries.length >= 1 && entries.every(({ action }) => action === 'policy_restored'));
    assert.ok(entries.some((entry) => entry.policyVersion === policyVersion + 1 && entry.restoredFrom === 1));
    assert.ok(![token, enrollmentGrant, installation.token].some((value) => downloaded.includes(value)));
    const invalid = await context.request.get(`${dashboard}/audit/export?from=2026-02-31`);
    assert.equal(invalid.status(), 400);
    assert.equal((await context.request.get(`${dashboard}/audit/export?action=browser_revoked&action=grant_issued`)).status(), 400);
  });

  await t.test('paginates older activity and exports beyond the visible 100 entries', async () => {
    for (let index = 0; index < 102; index++) {
      await post('/admin/ai-apps/gemini/classification', { status: index % 2 === 0 ? 'approved' : 'unapproved' }, token);
    }
    await page.getByRole('link', { name: 'Clear filters' }).click();
    const audit = page.getByRole('table', { name: 'Control activity' });
    const older = page.getByRole('link', { name: 'Older entries' });
    await older.waitFor();
    assert.equal(await audit.locator('tbody tr').count(), 100);
    const data = await (await context.request.get(`${dashboard}/audit/export`)).json();
    assert.ok(data.entries.length > 100 && data.next === null);
    await older.click();
    await page.waitForURL((url) => url.searchParams.has('beforeAt') && url.searchParams.has('beforeId'));
    await audit.getByText('Browser enrolled', { exact: true }).first().waitFor();
    await page.getByRole('link', { name: 'Newest entries' }).click();
    await older.waitFor();
    await page.getByRole('link', { name: 'Overview', exact: true }).click();
    await page.getByRole('heading', { name: 'Security overview', exact: true }).waitFor();
  });

  await t.test('compares draft policy locally and rejects a stale publish before committing the exact changes', async () => {
    async function currentPolicy() {
      const response = await context.request.get(`${api}/admin/policies`, { headers: { Authorization: `Bearer ${token}` } });
      assert.equal(response.status(), 200);
      return (await response.json())[0];
    }
    const reference = await currentPolicy();
    await page.getByRole('link', { name: 'Policy preview', exact: true }).click();
    await page.getByRole('heading', { name: 'Policy preview', exact: true }).waitFor();
    const marker = page.getByLabel('Draft test marker');
    const allowed = page.getByLabel('Draft allowed domains');
    const blocked = page.getByLabel('Draft blocked domains');
    const allowedPaths = page.getByLabel('Draft allowed paths');
    const blockedPaths = page.getByLabel('Draft blocked paths');
    const prompt = page.getByLabel('Custom prompt', { exact: true });
    const url = page.getByLabel('Custom navigation URL');
    const run = page.getByRole('button', { name: 'Run preview', exact: true });
    const publish = page.getByRole('button', { name: 'Publish previewed policy', exact: true });
    const results = page.getByRole('table', { name: 'Preview results' });
    await run.click();
    await results.waitFor();
    assert.equal(await publish.count(), 0);
    await page.getByLabel('Load draft from').selectOption(String(policyVersion));
    assert.equal(await marker.inputValue(), 'warn');
    await allowed.fill('example.test');
    await blocked.fill('EXAMPLE.TEST.');
    await run.click();
    await page.getByRole('alert').filter({ hasText: 'A hostname can appear in only one list.' }).waitFor();
    assert.equal(await publish.count(), 0);

    async function prepareDraft() {
      await marker.selectOption('block');
      await page.getByLabel('Draft GitHub classic PAT').selectOption('warn');
      await page.getByLabel('Draft payment card number').selectOption('warn');
      await page.getByLabel('Draft ChatGPT file uploads').selectOption('block');
      await page.getByLabel('Draft Gemini file uploads').selectOption('monitor');
      await page.getByLabel('Draft AI app discovery').selectOption('on');
      await allowed.fill('work.pilot.example.test');
      await blocked.fill('Pilot.Example.Test.');
      await allowedPaths.fill('PILOT.EXAMPLE.TEST./start/');
      await blockedPaths.fill('work.pilot.example.test/settings');
    }
    await prepareDraft();
    await url.fill('file:///synthetic-preview');
    await run.click();
    await page.getByRole('alert').filter({ hasText: 'Enter a complete HTTP or HTTPS address' }).waitFor();

    const privatePrompt = 'ZEKVAR_TEST_SECRET preview-private-prompt';
    const privateUrl = 'https://pilot.example.test/preview-private-path?sample=1';
    const requests = [];
    const captureRequest = (request) => requests.push(`${request.url()} ${request.postData() ?? ''}`);
    page.on('request', captureRequest);
    try {
      await prompt.fill(privatePrompt);
      await url.fill(privateUrl);
      await run.click();
      const decisions = [
        ['Clean prompt', 'Allow', 'Allow'],
        ['Synthetic test marker', 'Monitor', 'Block'],
        ['Synthetic GitHub token', 'Allow', 'Warn'],
        ['Both detectors match', 'Monitor', 'Block'],
        ['Token embedded in a longer string', 'Allow', 'Allow'],
        ['Synthetic payment card', 'Allow', 'Warn'],
        ['Payment card with invalid checksum', 'Allow', 'Allow'],
        ['ChatGPT file upload', 'Allow', 'Block'],
        ['Gemini file upload', 'Allow', 'Monitor'],
        ['Custom prompt', 'Monitor', 'Block'],
        ['Sample domain', 'Allow', 'Allow'],
        ['Sample subdomain', 'Allow', 'Allow'],
        ['Similar domain', 'Allow', 'Allow'],
        ['Custom navigation', 'Allow', 'Block'],
      ];
      for (const [sample, before, after] of decisions) {
        const cells = results.getByRole('row', { name: new RegExp(`^${sample} `) }).getByRole('cell');
        await cells.nth(0).getByText(before, { exact: true }).waitFor();
        await cells.nth(1).getByText(after, { exact: true }).waitFor();
      }
      await results.getByRole('row', { name: /^Sample subdomain / }).getByText('work.pilot.example.test', { exact: true }).waitFor();
      await results.getByRole('row', { name: /^Sample domain / }).getByText('pilot.example.test/start', { exact: true }).waitFor();
      await results.getByRole('row', { name: /^Both detectors match / }).getByRole('cell').nth(1)
        .getByText('Test marker', { exact: true }).waitFor();
      const screenshot = process.env.ZEKVAR_TEST_PREVIEW_SCREENSHOT;
      if (screenshot) await page.screenshot({ path: screenshot, fullPage: true });
      await page.setViewportSize({ width: 390, height: 844 });
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth), 390);
      await page.setViewportSize({ width: 1440, height: 1000 });
      assert.deepEqual(requests, []);
      assert.deepEqual(await currentPolicy(), reference);
      page.once('dialog', (dialog) => dialog.dismiss());
      await publish.click();
      assert.deepEqual(requests, []);

      const advanced = await post('/admin/policies', { mode: 'warn' }, token);
      page.once('dialog', (dialog) => dialog.accept());
      await publish.click();
      await page.getByRole('alert').filter({ hasText: 'The policy changed after this preview.' }).waitFor();
      assert.equal((await currentPolicy()).version, advanced.version);
      await page.reload();
      assert.equal(await prompt.inputValue(), '');
      assert.equal(await url.inputValue(), '');
      await prepareDraft();
      await prompt.fill(privatePrompt);
      await url.fill(privateUrl);
      await run.click();
      page.once('dialog', (dialog) => dialog.accept());
      await publish.click();
      await page.getByText(`Previewed policy published as version ${advanced.version + 1}.`, { exact: true }).waitFor();
      const published = await currentPolicy();
      assert.equal(published.mode, 'block');
      assert.equal(published.githubPatMode, 'warn');
      assert.equal(published.paymentCardMode, 'warn');
      assert.deepEqual(published.uploadModes, { chatgpt: 'block', gemini: 'monitor' });
      assert.equal(published.discoveryEnabled, true);
      assert.deepEqual(published.domainRules, { allow: ['work.pilot.example.test'], block: ['pilot.example.test'] });
      assert.deepEqual(published.pathRules, { allow: ['pilot.example.test/start'], block: ['work.pilot.example.test/settings'] });
      assert.equal(requests.some((request) => /preview-private-(prompt|path)/.test(request)), false);
    } finally {
      page.off('request', captureRequest);
    }
    await page.getByRole('link', { name: 'Overview', exact: true }).click();
    await page.getByRole('heading', { name: 'Security overview', exact: true }).waitFor();
  });

  await t.test('investigates older events and exports the complete applied view from Chrome', async () => {
    const { grant } = await post('/admin/enrollment-grants', {}, token);
    const browser = await post('/enroll', { grant });
    const { grant: otherGrant } = await post('/admin/enrollment-grants', {}, token);
    const other = await post('/enroll', { grant: otherGrant });
    const policies = await context.request.get(`${api}/admin/policies`, { headers: { Authorization: `Bearer ${token}` } });
    const [policy] = await policies.json();
    const sample = { ...event, appId: 'chatgpt', decision: policy.mode, policyVersion: policy.version, timestamp: new Date().toISOString() };
    const ids = Array.from({ length: 102 }, () => randomUUID());
    for (let index = 0; index < ids.length; index += 10) {
      await Promise.all(ids.slice(index, index + 10).map((eventId) => post('/browser/events', { ...sample, eventId }, browser.token)));
    }
    await post('/browser/events', { ...sample, eventId: randomUUID() }, other.token);
    await post('/browser/events', { ...sample, eventId: randomUUID(), appId: 'local-prompt-fixture' }, browser.token);
    await post('/browser/events', { ...sample, eventId: randomUUID(), timestamp: new Date(Date.now() - 3 * 86_400_000).toISOString() },
      browser.token).then(() => assert.fail('Expired events must be rejected.'), (error) => assert.match(error.message, /returned 400/));
    await page.reload();
    await page.getByLabel('Application', { exact: true }).selectOption('chatgpt');
    await page.getByLabel('Decision', { exact: true }).selectOption(policy.mode);
    await page.getByLabel('Time range', { exact: true }).selectOption('day');
    const installation = page.getByLabel('Browser installation ID', { exact: true });
    await installation.fill('invalid');
    await page.getByRole('button', { name: 'Apply filters' }).click();
    await page.getByRole('alert').filter({ hasText: 'Enter a complete browser installation ID.' }).waitFor();
    const link = page.getByRole('link', { name: 'Export security events (JSON)', exact: true });
    assert.equal(await link.count(), 0);
    await installation.fill(browser.installationId);
    await page.getByRole('button', { name: 'Apply filters' }).click();
    const older = page.getByRole('link', { name: 'Older events', exact: true });
    await older.waitFor();
    assert.equal(await events.locator('tbody tr').count(), 100);
    const href = await link.getAttribute('href');
    const filters = new URL(href, dashboard).searchParams;
    assert.equal(filters.get('installationId'), browser.installationId);
    assert.equal(filters.get('appId'), 'chatgpt');
    assert.equal(filters.get('decision'), policy.mode);
    assert.ok(filters.get('since'));
    await older.click();
    const newest = page.getByRole('link', { name: 'Newest events', exact: true });
    await newest.waitFor();
    assert.equal(new URL(page.url()).searchParams.get('since'), filters.get('since'));
    assert.equal(await link.getAttribute('href'), href);
    assert.equal(await events.locator('tbody tr').count(), 2);
    const screenshot = process.env.ZEKVAR_TEST_EVENTS_SCREENSHOT;
    if (screenshot) await page.locator('#events').screenshot({ path: screenshot });

    const response = await context.request.get(new URL(href, dashboard).href);
    assert.equal(response.headers()['cache-control'], 'no-store');
    assert.equal(response.headers()['x-content-type-options'], 'nosniff');
    assert.equal(response.headers()['cross-origin-resource-policy'], 'same-origin');
    const downloaded = page.waitForEvent('download');
    await link.click();
    const file = await downloaded;
    assert.equal(file.suggestedFilename(), 'zekvar-security-events.json');
    const data = await readFile(await file.path(), 'utf8');
    const { entries, organization, filters: reported } = JSON.parse(data);
    assert.equal(organization, await page.locator('.eyebrow').textContent());
    assert.equal(Date.parse(reported.since), Date.parse(filters.get('since')));
    assert.deepEqual(entries.map(({ eventId }) => eventId).sort(), ids.sort());
    assert.ok(entries.every((entry) => entry.installationId === browser.installationId && entry.appId === 'chatgpt'));
    assert.equal([token, browser.token, other.token, grant, otherGrant].some((value) => data.includes(value)), false);
    for (const query of ['appId=chatgpt&appId=chatgpt', 'beforeAt=now', 'organization=another-tenant']) {
      assert.equal((await context.request.get(`${dashboard}/events/export?${query}`)).status(), 400);
    }
    await newest.click();
    await older.waitFor();
    const filterBrowser = events.getByRole('link', { name: `Filter events for installation ${browser.installationId}` }).first();
    assert.equal(new URL(await filterBrowser.getAttribute('href'), dashboard).searchParams.get('since'), filters.get('since'));
    await page.getByRole('link', { name: 'Clear filters', exact: true }).click();
    await page.waitForURL((url) => url.search === '');
  });

  await t.test('issues named access in Chrome and restricts the auditor and revoked sessions', async () => {
    await page.getByRole('link', { name: 'Control access', exact: true }).click();
    await page.getByRole('heading', { name: 'Control access', exact: true }).waitFor();
    const credentials = page.getByRole('table', { name: 'Delegated credentials' });
    const issued = page.getByLabel('Issued token', { exact: true });
    await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: dashboard });
    const create = async (name, role) => {
      await page.getByLabel('Name', { exact: true }).fill(name);
      await page.getByLabel('Role', { exact: true }).selectOption(role);
      await page.getByLabel('Expires after', { exact: true }).selectOption('1');
      await page.getByRole('button', { name: 'Issue token', exact: true }).click();
      await page.getByText(`Copy the token for ${name}. Control only shows it at issuance.`, { exact: true }).waitFor();
      await credentials.getByRole('row', { name: new RegExp(`^${name} `) }).getByText('Active', { exact: true }).waitFor();
      const secret = await issued.inputValue();
      assert.match(secret, /^[a-f0-9]{64}$/);
      await page.getByRole('button', { name: 'Copy', exact: true }).click();
      await page.getByText('Copied.', { exact: true }).waitFor();
      assert.equal(await page.evaluate(() => navigator.clipboard.readText()), secret);
      await page.getByRole('button', { name: 'Hide token', exact: true }).click();
      await issued.waitFor({ state: 'detached' });
      return secret;
    };
    const operator = await create('Jordan Demo', 'administrator');
    const reviewer = await create('Kai Review', 'auditor');
    await page.reload();
    await credentials.getByText('Kai Review', { exact: true }).waitFor();
    const reloaded = await page.content();
    assert.ok(![operator, reviewer].some((secret) => reloaded.includes(secret)));
    assert.equal(await issued.count(), 0);
    const screenshot = process.env.ZEKVAR_TEST_ACCESS_SCREENSHOT;
    if (screenshot) await page.screenshot({ path: screenshot, fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth), 390);
    await page.setViewportSize({ width: 1440, height: 1000 });

    const operatorContext = await browser.newContext();
    const reviewerContext = await browser.newContext();
    async function signInAs(profile, secret) {
      const tab = await profile.newPage();
      tab.setDefaultTimeout(5000);
      await tab.goto(dashboard);
      await tab.getByLabel('Control token', { exact: true }).fill(secret);
      await tab.getByRole('button', { name: 'Sign in', exact: true }).click();
      await tab.getByRole('heading', { name: 'Security overview', exact: true }).waitFor();
      assert.equal((await tab.content()).includes(secret), false);
      return tab;
    }

    try {
      const adminPage = await signInAs(operatorContext, operator);
      const auditPage = await signInAs(reviewerContext, reviewer);
      await adminPage.getByText('Jordan Demo · Administrator', { exact: true }).waitFor();
      await auditPage.getByText('Kai Review · Auditor', { exact: true }).waitFor();
      for (const tab of [adminPage, auditPage]) {
        assert.equal(await tab.getByRole('link', { name: 'Control access', exact: true }).count(), 0);
        await tab.goto(`${dashboard}/access`);
        await tab.getByRole('alert').filter({ hasText: 'Only the organization owner can manage Control access.' }).waitFor();
        assert.equal(await tab.getByRole('table', { name: 'Delegated credentials' }).count(), 0);
        await tab.goto(dashboard);
      }
      assert.equal(await auditPage.getByRole('button', { name: /^(Publish|Create enrollment grant|Restore|Revoke)/ }).count(), 0);
      await auditPage.getByRole('link', { name: 'Policy preview', exact: true }).click();
      await auditPage.getByLabel('Draft test marker').selectOption('warn');
      await auditPage.getByRole('button', { name: 'Run preview', exact: true }).click();
      await auditPage.getByRole('table', { name: 'Preview results' }).waitFor();
      assert.equal(await auditPage.getByRole('button', { name: 'Publish previewed policy', exact: true }).count(), 0);
      await auditPage.getByRole('link', { name: 'Rollout groups', exact: true }).click();
      await auditPage.getByRole('heading', { name: 'Rollout groups', exact: true }).waitFor();
      assert.equal(await auditPage.getByRole('button', { name: /^(Create group|Publish|Promote|Restore|Save assignment)/ }).count(), 0);
      await auditPage.getByRole('link', { name: 'Data retention', exact: true }).click();
      await auditPage.getByRole('heading', { name: 'Retention windows', exact: true }).waitFor();
      assert.equal(await auditPage.getByRole('button', { name: /^(Save retention|Run cleanup)$/ }).count(), 0);

      await adminPage.getByLabel('Test marker', { exact: true }).selectOption('warn');
      await adminPage.getByRole('button', { name: 'Publish policy', exact: true }).click();
      await adminPage.getByRole('status').filter({ hasText: /published in warn mode/ }).waitFor();
      await auditPage.getByRole('link', { name: 'Audit log', exact: true }).click();
      const named = auditPage.getByRole('table', { name: 'Control activity' }).getByRole('row').filter({ hasText: 'Jordan Demo' });
      await named.filter({ hasText: 'Policy published' }).waitFor();
      const response = await reviewerContext.request.get(`${dashboard}/audit/export`);
      assert.equal(response.status(), 200);
      const payload = await response.text();
      assert.ok(![operator, reviewer].some((secret) => payload.includes(secret)));
      assert.ok(JSON.parse(payload).entries.some(({ action, actorAccess }) => action === 'policy_published' && actorAccess?.name === 'Jordan Demo'));

      const revoke = async (name) => {
        page.once('dialog', (dialog) => dialog.accept());
        await credentials.getByRole('button', { name: `Revoke token for ${name}`, exact: true }).click();
        await credentials.getByRole('row', { name: new RegExp(`^${name} `) }).getByText('Revoked', { exact: true }).waitFor();
      };
      await revoke('Jordan Demo');
      await adminPage.getByRole('button', { name: 'Publish policy', exact: true }).click();
      await adminPage.getByRole('heading', { name: 'Sign in to Control', exact: true }).waitFor();
      await adminPage.getByRole('alert').filter({ hasText: 'Your session ended. Sign in again.' }).waitFor();
      assert.ok(!(await operatorContext.cookies()).some(({ name }) => name === 'zekvar_control_session'));
      assert.equal((await operatorContext.request.get(`${dashboard}/events/export`)).status(), 401);
      await revoke('Kai Review');
      assert.equal((await reviewerContext.request.get(`${dashboard}/audit/export`)).status(), 401);
      await auditPage.reload();
      await auditPage.getByRole('heading', { name: 'Sign in to Control', exact: true }).waitFor();
    } finally {
      await operatorContext.close();
      await reviewerContext.close();
    }
    await page.goto(dashboard);
  });

  await t.test('a different administrator must approve the exact previewed policy in Control', async () => {
    const credentials = await Promise.all(['Review author', 'Review approver'].map((name) =>
      post('/admin/access', { name, role: 'administrator', hours: 1 }, token)));
    const history = async () => {
      const response = await context.request.get(`${api}/admin/policies`, { headers: { Authorization: `Bearer ${token}` } });
      assert.equal(response.status(), 200);
      return response.json();
    };
    const [prior] = await history();
    await page.getByRole('link', { name: 'Policy reviews', exact: true }).click();
    await page.getByRole('heading', { name: 'Policy reviews', exact: true }).waitFor();
    page.once('dialog', (dialog) => dialog.accept());
    await page.getByRole('button', { name: 'Require policy reviews', exact: true }).click();
    await page.getByText('Required', { exact: true }).waitFor();
    await page.goto(dashboard);
    assert.equal(await page.getByRole('button', { name: 'Publish policy', exact: true }).count(), 0);

    const contexts = await Promise.all([browser.newContext(), browser.newContext()]);
    try {
      const [author, approver] = await Promise.all(contexts.map(async (profile, index) => {
        const tab = await profile.newPage();
        tab.setDefaultTimeout(5000);
        await tab.goto(dashboard);
        await tab.getByLabel('Control token', { exact: true }).fill(credentials[index].token);
        await tab.getByRole('button', { name: 'Sign in', exact: true }).click();
        await tab.getByRole('heading', { name: 'Security overview', exact: true }).waitFor();
        return tab;
      }));
      await author.getByRole('link', { name: 'Policy preview', exact: true }).click();
      await author.getByLabel('Draft test marker', { exact: true }).selectOption('block');
      await author.getByLabel('Draft blocked paths', { exact: true }).fill('work.review.test/private');
      await author.getByRole('button', { name: 'Run preview', exact: true }).click();
      author.once('dialog', (dialog) => dialog.accept());
      await author.getByRole('button', { name: 'Request review of previewed policy', exact: true }).click();
      const requestLink = author.getByRole('link', { name: 'Open review request', exact: true });
      await requestLink.waitFor();
      assert.deepEqual((await history())[0], prior);
      const href = await requestLink.getAttribute('href');
      const hash = new URL(href, dashboard).hash;
      await requestLink.click();
      const submitted = author.locator(hash);
      await submitted.getByText('Pending', { exact: true }).waitFor();
      assert.equal(await submitted.getByRole('button', { name: 'Approve and publish', exact: true }).count(), 0);
      await submitted.getByRole('button', { name: 'Withdraw request', exact: true }).waitFor();

      await approver.goto(new URL(href, dashboard).href);
      const reviewed = approver.locator(hash);
      await reviewed.getByText('work.review.test/private', { exact: true }).waitFor();
      await reviewed.getByText(`Reference v${prior.version}`, { exact: true }).waitFor();
      const screenshot = process.env.ZEKVAR_TEST_REVIEW_SCREENSHOT;
      if (screenshot) await approver.screenshot({ path: screenshot, fullPage: true });
      await approver.setViewportSize({ width: 390, height: 844 });
      assert.equal(await approver.evaluate(() => document.documentElement.scrollWidth), 390);
      approver.once('dialog', (dialog) => dialog.accept());
      await reviewed.getByRole('button', { name: 'Approve and publish', exact: true }).click();
      await reviewed.getByText('Approved', { exact: true }).waitFor();
      await reviewed.getByText('Approved by Review approver', { exact: true }).waitFor();
      const [current] = await history();
      assert.equal(current.version, prior.version + 1);
      assert.equal(current.mode, 'block');
      assert.deepEqual(current.pathRules.block, ['work.review.test/private']);
      await approver.getByRole('link', { name: 'Audit log', exact: true }).click();
      const audit = approver.getByRole('table', { name: 'Control activity' });
      await audit.getByRole('row').filter({ hasText: 'Policy review decided' }).getByText('Review approver', { exact: true }).waitFor();
    } finally {
      await Promise.all(contexts.map((profile) => profile.close()));
    }
    await page.goto(`${dashboard}/reviews`);
    page.once('dialog', (dialog) => dialog.accept());
    await page.getByRole('button', { name: 'Disable required reviews', exact: true }).click();
    await page.getByText('Optional', { exact: true }).waitFor();
    await page.goto(dashboard);
  });

  await t.test('fits a mobile viewport and clears the session on sign-out', async () => {
    const screenshot = process.env.ZEKVAR_TEST_SCREENSHOT;
    if (screenshot) await page.screenshot({ path: screenshot, fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth), 390);
    await page.getByRole('button', { name: 'Sign out' }).click();
    await page.getByRole('heading', { name: 'Sign in to Control' }).waitFor();
    assert.ok(!(await context.cookies()).some(({ name }) => name === 'zekvar_control_session'));
    assert.equal((await context.request.get(`${dashboard}/audit/export`)).status(), 401);
    assert.equal((await context.request.get(`${dashboard}/events/export`)).status(), 401);
    assert.deepEqual(clientErrors, []);
  });
});
