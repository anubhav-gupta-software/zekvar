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

async function post(path, body, bearer, headers = {}) {
  const response = await fetch(`${api}${path}`, {
    method: 'POST',
    headers: {
      ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}),
      'Content-Type': 'application/json',
      ...headers,
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(5000),
  });
  assert.ok(response.ok, `POST ${path} returned ${response.status}`);
  return response.status === 204 ? undefined : response.json();
}

async function assertFitsViewport(page) {
  const { width, clientWidth, scrollWidth } = await page.evaluate(() => ({
    width: window.innerWidth, clientWidth: document.documentElement.clientWidth, scrollWidth: document.documentElement.scrollWidth,
  }));
  assert.equal(width, page.viewportSize().width);
  assert.equal(scrollWidth, clientWidth);
}

test('Control dashboard signs in and manages a real browser installation and event', { timeout: 45_000 }, async (t) => {
  const browser = await chromium.launch({ channel: 'chromium', headless: process.env.ZEKVAR_DEMO_HEADED !== '1' });
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
    const report = await context.request.get(`${dashboard}/reports/export`);
    assert.equal(report.status(), 401);
    assert.equal(report.headers()['cache-control'], 'no-store');
    assert.equal((await context.request.get(`${dashboard}/reports/composer-readiness/export`)).status(), 401);
    assert.equal(new URL((await context.request.get(`${dashboard}/reports`)).url()).pathname, '/');
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

  await t.test('shows the reported extension release separately from the applied policy', async () => {
    const row = browsers.getByRole('row').filter({ hasText: installation.installationId.slice(0, 13) });
    const rollout = page.getByRole('table', { name: 'Extension rollout' });
    await row.getByText('Unreported', { exact: true }).waitFor();
    await rollout.getByRole('rowheader', { name: 'Unreported', exact: true }).waitFor();
    const report = async (version) => {
      const response = await fetch(`${api}/browser/policy`, { headers: {
        Authorization: `Bearer ${installation.token}`, 'X-Zekvar-Extension-Version': version,
      }, signal: AbortSignal.timeout(5000) });
      assert.ok(response.ok);
      assert.equal((await response.json()).version, policyVersion);
    };
    await report('0.20.0');
    await page.getByRole('button', { name: 'Refresh browser health' }).click();
    const version = row.locator('code').filter({ hasText: /^0\.20\.0$/ });
    await version.waitFor();
    const releaseCell = row.getByRole('cell').filter({ has: page.locator('code').filter({ hasText: /^0\.20\.0$/ }) });
    assert.ok(await releaseCell.locator('time').getAttribute('datetime'));
    assert.deepEqual(await rollout.getByRole('row').filter({ hasText: '0.20.0' }).getByRole('cell').allTextContents(), ['1', '1']);
    await row.getByText(`v${policyVersion}`, { exact: true }).waitFor();
    await report('0.21.0');
    await page.getByRole('button', { name: 'Refresh browser health' }).click();
    await row.getByText('0.21.0', { exact: true }).waitFor();
    assert.equal(await rollout.getByRole('rowheader', { name: '0.20.0', exact: true }).count(), 0);
    assert.deepEqual(await rollout.getByRole('row').filter({ hasText: '0.21.0' }).getByRole('cell').allTextContents(), ['1', '1']);
    const screenshot = process.env.ZEKVAR_TEST_RELEASE_SCREENSHOT;
    if (screenshot) await page.locator('#browsers').screenshot({ path: screenshot });
    await page.setViewportSize({ width: 390, height: 820 });
    await rollout.getByRole('rowheader', { name: '0.21.0' }).waitFor();
    assert.ok(await browsers.evaluate((table) => table.scrollWidth > table.parentElement.clientWidth));
    await page.setViewportSize({ width: 1440, height: 1000 });
  });

  await t.test('filters browser health by rollout group and release independently of events', async () => {
    const group = await post('/admin/policy-groups', { name: 'Release canary' }, token);
    const { grant } = await post('/admin/enrollment-grants', {}, token);
    const candidate = await post('/enroll', { grant });
    const response = await fetch(`${api}/browser/policy`, { headers: { Authorization: `Bearer ${candidate.token}`,
      'X-Zekvar-Assignment-Aware': '1', 'X-Zekvar-Extension-Version': '0.20.1' }, signal: AbortSignal.timeout(5000) });
    assert.ok(response.ok);
    await post(`/admin/installations/${candidate.installationId}/policy-group`, { groupId: group.id }, token);
    await page.getByRole('link', { name: 'Rollout groups', exact: true }).click();
    await page.getByRole('link', { name: 'Review browser rollout', exact: true }).click();
    const browserSection = page.locator('#browsers');
    const selectedGroup = browserSection.getByLabel('Rollout group', { exact: true });
    const candidateId = candidate.installationId.slice(0, 13);
    const baselineId = installation.installationId.slice(0, 13);
    await browsers.getByText(candidateId, { exact: true }).waitFor();
    assert.equal(await selectedGroup.inputValue(), group.id);
    assert.equal(await browsers.getByText(baselineId, { exact: true }).count(), 0);
    await page.getByRole('table', { name: 'Extension rollout' }).getByRole('link', { name: '0.20.1', exact: true }).click();
    await page.waitForURL((url) => url.searchParams.get('browserVersion') === '0.20.1');
    await browsers.getByText(candidateId, { exact: true }).waitFor();
    await page.getByLabel('Application', { exact: true }).selectOption('chatgpt');
    await page.getByRole('button', { name: 'Apply filters', exact: true }).click();
    await page.waitForURL((url) => url.searchParams.get('app') === 'chatgpt' && url.searchParams.get('rolloutGroup') === group.id);
    await browsers.getByText(candidateId, { exact: true }).waitFor();
    const coverageLink = browserSection.getByRole('link', { name: 'Export composer readiness (JSON)', exact: true });
    const exportPath = await coverageLink.getAttribute('href');
    const coverageUrl = new URL(exportPath, dashboard);
    assert.deepEqual(Object.fromEntries(coverageUrl.searchParams), { rolloutGroup: group.id, browserVersion: '0.20.1' });
    const [coverageFile] = await Promise.all([page.waitForEvent('download'), coverageLink.click()]);
    assert.equal(coverageFile.suggestedFilename(), 'zekvar-composer-readiness.json');
    const data = await readFile(await coverageFile.path(), 'utf8');
    const captured = JSON.parse(data);
    assert.equal(captured.activeInstallations, 1);
    assert.equal(captured.apps.find(({ appId }) => appId === 'chatgpt').counts.policy_pending, 1);
    assert.deepEqual(captured.scope, { rolloutGroup: group.id, rolloutGroupName: group.name,
      browserVersion: '0.20.1', targetPolicyVersion: policyVersion });
    assert.ok(!data.includes(candidate.installationId) && !data.includes(candidate.token));
    const repeat = await context.request.get(coverageUrl.href);
    assert.equal(repeat.status(), 200);
    assert.equal(repeat.headers()['cache-control'], 'no-store');
    assert.deepEqual((await repeat.json()).apps, captured.apps);
    assert.equal((await context.request.get(`${coverageUrl.href}&browserVersion=0.20.2`)).status(), 400);
    const screenshot = process.env.ZEKVAR_TEST_BROWSER_GROUP_SCREENSHOT;
    if (screenshot) await browserSection.screenshot({ path: screenshot });

    await browserSection.getByLabel('Reported extension version', { exact: true }).fill('0.21.0');
    await browserSection.getByRole('button', { name: 'Apply browser filters', exact: true }).click();
    await browserSection.getByText('No installations match these browser filters.', { exact: true }).waitFor();
    await browserSection.getByText('No active browsers match these filters.', { exact: true }).waitFor();
    const emptyReport = await context.request.get(new URL(await coverageLink.getAttribute('href'), dashboard).href);
    assert.equal((await emptyReport.json()).activeInstallations, 0);
    await page.getByRole('table', { name: 'Extension rollout' }).getByRole('link', { name: '0.20.1', exact: true }).waitFor();
    await selectedGroup.selectOption('baseline');
    await browserSection.getByRole('button', { name: 'Apply browser filters', exact: true }).click();
    await browsers.getByText(baselineId, { exact: true }).waitFor();
    assert.equal(await browsers.getByText(candidateId, { exact: true }).count(), 0);
    assert.equal(new URL(page.url()).searchParams.get('app'), 'chatgpt');

    await page.goto(`${dashboard}/?rolloutGroup=${group.id}&browserVersion=ZEKVAR_TEST_SECRET#browsers`);
    await browserSection.getByRole('alert').filter({ hasText: 'enter an exact extension' }).waitFor();
    assert.equal(await browsers.count(), 0);
    assert.equal(await coverageLink.count(), 0);
    assert.equal(await browserSection.getByLabel('Reported extension version', { exact: true }).inputValue(), '');
    assert.equal(await page.locator('#events input[name="browserVersion"]').count(), 0);
    await page.goto(`${dashboard}/?rolloutGroup=${randomUUID()}#browsers`);
    await browserSection.getByRole('alert').filter({ hasText: 'This browser rollout view is unavailable.' }).waitFor();
    assert.equal(await coverageLink.count(), 0);
    await browserSection.getByRole('link', { name: 'Clear browser filters' }).click();
    await browsers.getByText(baselineId, { exact: true }).waitFor();
    await browsers.getByText(candidateId, { exact: true }).waitFor();
  });

  await t.test('shows and filters metadata from a real policy event', async () => {
    await post('/browser/events', {
      ...event, eventId: randomUUID(), policyVersion, decision: 'warn', timestamp: new Date().toISOString(),
    }, installation.token);
    await post('/browser/events', {
      ...event, appId: 'chatgpt', eventId: randomUUID(), policyVersion, decision: 'warn', timestamp: new Date().toISOString(),
    }, installation.token);
    await post('/browser/heartbeat', { policyVersion, chatGptCoverage: 'unsupported' }, installation.token,
      { 'X-Zekvar-Composer-Coverage': '1' });
    await page.reload();
    await events.getByText('Local prompt fixture', { exact: true }).first().waitFor();
    await events.getByText('ChatGPT', { exact: true }).first().waitFor();
    await browsers.getByText('Unsupported', { exact: true }).first().waitFor();
    const readiness = page.getByRole('table', { name: 'Composer readiness', exact: true });
    const row = readiness.getByRole('row', { name: /^ChatGPT / });
    assert.deepEqual(await row.getByRole('cell').allTextContents(), ['2', '0', '1', '0', '0', '1', '0']);
    const screenshot = process.env.ZEKVAR_TEST_COVERAGE_SCREENSHOT;
    if (screenshot) await readiness.screenshot({ path: screenshot });
    await page.setViewportSize({ width: 390, height: 820 });
    await assertFitsViewport(page);
    assert.ok(await readiness.evaluate((table) => table.scrollWidth > table.parentElement.clientWidth));
    await page.setViewportSize({ width: 1440, height: 1000 });
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

  await t.test('opens the AI enforcement report, filters in Chrome, and downloads the displayed counts', async () => {
    await page.getByRole('link', { name: 'Reports', exact: true }).click();
    await page.getByRole('heading', { name: 'AI enforcement report', exact: true }).waitFor();
    const apps = page.getByRole('table', { name: 'By AI application', exact: true });
    const rules = page.getByRole('table', { name: 'By policy rule', exact: true });
    const daily = page.getByRole('table', { name: 'Daily policy events', exact: true });
    const filter = page.getByRole('button', { name: 'Apply report filters' });
    const app = page.getByLabel('AI application', { exact: true });
    const totals = page.getByRole('region', { name: 'Summary of policy events', exact: true });
    await apps.getByRole('rowheader', { name: 'ChatGPT', exact: true }).waitFor();
    assert.deepEqual(await totals.locator('strong').allTextContents(), ['1', '1', '0']);
    assert.equal(await apps.locator('tbody tr').count(), 1);
    assert.deepEqual(await rules.getByRole('row').filter({ hasText: 'Synthetic secret' }).getByRole('cell').allTextContents(), ['0', '1', '0', '0', '0', '1']);
    assert.equal(await daily.locator('tbody tr').count(), 7);
    await app.selectOption('gemini');
    await filter.click();
    await page.getByText('No retained policy events match this report.', { exact: true }).waitFor();
    assert.deepEqual(await totals.locator('strong').allTextContents(), ['0', '0', '0']);
    await page.getByLabel('Reporting window (UTC)', { exact: true }).selectOption('30');
    await app.selectOption('chatgpt');
    await page.getByLabel('Recorded rollout group', { exact: true }).selectOption('baseline');
    await filter.click();
    await apps.getByRole('rowheader', { name: 'ChatGPT', exact: true }).waitFor();
    assert.equal(await daily.locator('tbody tr').count(), 30);
    const link = page.getByRole('link', { name: 'Export report (JSON)', exact: true });
    const href = await link.getAttribute('href');
    const anchor = Number(new URL(href, dashboard).searchParams.get('asOf'));
    const [file] = await Promise.all([page.waitForEvent('download'), link.click()]);
    assert.equal(file.suggestedFilename(), 'zekvar-ai-enforcement.json');
    const serialized = await readFile(await file.path(), 'utf8');
    const downloaded = JSON.parse(serialized);
    assert.equal(Date.parse(downloaded.asOf), anchor);
    assert.equal(downloaded.appId, 'chatgpt');
    assert.equal(downloaded.rolloutGroup, 'baseline');
    assert.equal(downloaded.days, 30);
    assert.equal(downloaded.daily.length, 30);
    assert.deepEqual(downloaded.counts, { monitor: 0, warn: 1, block: 0, warn_override: 0, exception_applied: 0 });
    assert.deepEqual(downloaded.bySource, [{ id: 'prompt', counts: downloaded.counts }]);
    assert.ok(![installation.installationId, installation.token, token, enrollmentGrant].some((secret) => serialized.includes(secret)));
    const response = await context.request.get(`${dashboard}${href}`);
    assert.equal(response.status(), 200);
    assert.equal(response.headers()['cache-control'], 'no-store');
    assert.equal(response.headers()['cross-origin-resource-policy'], 'same-origin');
    assert.deepEqual(await response.json(), downloaded);
    assert.equal((await context.request.get(`${dashboard}/reports/export?appId=chatgpt&appId=gemini`)).status(), 400);
    assert.equal((await context.request.get(`${dashboard}/reports/export?rolloutGroup=baseline&rolloutGroup=unattributed`)).status(), 400);
    assert.equal((await context.request.get(`${dashboard}/reports/export?asOf=0`)).status(), 400);
    await page.setViewportSize({ width: 390, height: 820 });
    await assertFitsViewport(page);
    assert.ok(await daily.evaluate((table) => table.scrollWidth > table.parentElement.clientWidth));
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.goto(`${dashboard}/reports?days=7&days=30`);
    await page.getByRole('alert').filter({ hasText: 'Choose a valid AI application, reporting window, and rollout group.' }).waitFor();
    assert.equal(await link.count(), 0);
    await filter.click();
    await link.waitFor();
    await page.getByRole('link', { name: 'Investigate security events', exact: true }).click();
    await events.getByText('ChatGPT', { exact: true }).first().waitFor();
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
    const geminiTypes = page.getByLabel('Draft Gemini file types', { exact: true });
    const file = page.getByLabel('Custom file name', { exact: true });
    const mime = page.getByLabel('Custom media type', { exact: true });
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
      await page.getByLabel('Draft private key', { exact: true }).selectOption('block');
      await page.getByLabel('Draft ChatGPT file uploads').selectOption('block');
      await page.getByLabel('Draft Gemini file uploads').selectOption('monitor');
      await page.getByLabel('Draft ChatGPT file content protection', { exact: true }).selectOption('block');
      await page.getByLabel('Draft ChatGPT file types', { exact: true }).fill('IMAGE/*, .PDF');
      await geminiTypes.fill('application/x-zekvar-private-type');
      await page.getByLabel('Draft app discovery').selectOption('on');
      await allowed.fill('work.pilot.example.test');
      await blocked.fill('Pilot.Example.Test.');
      await allowedPaths.fill('PILOT.EXAMPLE.TEST./start/');
      await blockedPaths.fill('work.pilot.example.test/settings');
    }
    await prepareDraft();
    await url.fill('file:///synthetic-preview');
    await run.click();
    await page.getByRole('alert').filter({ hasText: 'Enter a complete HTTP or HTTPS address' }).waitFor();
    await url.clear();
    await geminiTypes.fill('image/*/*');
    await run.click();
    await page.getByRole('alert').filter({ hasText: 'Enter up to 25 valid file extensions or media types' }).waitFor();
    assert.equal(await publish.count(), 0);
    await prepareDraft();

    const keyMaterial = 'V1ZB'.repeat(16);
    const privatePrompt = ['ZEKVAR_TEST_SECRET preview-private-prompt', '-----BEGIN PRIVATE KEY-----', keyMaterial,
      '-----END PRIVATE KEY-----'].join('\n');
    const privateUrl = 'https://pilot.example.test/preview-private-path?sample=1';
    const requests = [];
    const captureRequest = (request) => requests.push(`${request.url()} ${request.postData() ?? ''}`);
    page.on('request', captureRequest);
    try {
      await prompt.fill(privatePrompt);
      await url.fill(privateUrl);
      await file.fill('preview-private-file.PDF');
      await mime.fill('application/x-zekvar-private-type; charset=utf-8');
      await run.click();
      const decisions = [
        ['Clean prompt', 'Allow', 'Allow'],
        ['Synthetic test marker', 'Monitor', 'Block'],
        ['Synthetic GitHub token', 'Allow', 'Warn'],
        ['Both detectors match', 'Monitor', 'Block'],
        ['Token embedded in a longer string', 'Allow', 'Allow'],
        ['Synthetic payment card', 'Allow', 'Warn'],
        ['Payment card with invalid checksum', 'Allow', 'Allow'],
        ['Synthetic private key block', 'Allow', 'Block'],
        ['ChatGPT TXT upload', 'Allow', 'Allow'],
        ['ChatGPT PNG upload', 'Allow', 'Block'],
        ['ChatGPT custom file upload', 'Allow', 'Block'],
        ['ChatGPT synthetic text file', 'Allow', 'Block'],
        ['ChatGPT clean text file', 'Allow', 'Allow'],
        ['ChatGPT unscannable PDF sample', 'Allow', 'Block'],
        ['Gemini TXT upload', 'Allow', 'Allow'],
        ['Gemini custom file upload', 'Allow', 'Monitor'],
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
      await results.getByRole('row', { name: /^Custom prompt / }).getByRole('cell').nth(1)
        .getByText('Private key', { exact: true }).waitFor();
      const screenshot = process.env.ZEKVAR_TEST_PREVIEW_SCREENSHOT;
      if (screenshot) await page.screenshot({ path: screenshot, fullPage: true });
      await page.setViewportSize({ width: 390, height: 844 });
      await assertFitsViewport(page);
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
      assert.equal(await file.inputValue(), '');
      assert.equal(await mime.inputValue(), '');
      await prepareDraft();
      await prompt.fill(privatePrompt);
      await url.fill(privateUrl);
      await file.fill('preview-private-file.pdf');
      await mime.fill('application/x-zekvar-private-type; charset=utf-8');
      await run.click();
      page.once('dialog', (dialog) => dialog.accept());
      await publish.click();
      await page.getByText(`Previewed policy published as version ${advanced.version + 1}.`, { exact: true }).waitFor();
      const published = await currentPolicy();
      assert.equal(published.mode, 'block');
      assert.equal(published.githubPatMode, 'warn');
      assert.equal(published.paymentCardMode, 'warn');
      assert.equal(published.privateKeyMode, 'block');
      assert.deepEqual(published.uploadModes, { chatgpt: 'block', gemini: 'monitor' });
      assert.deepEqual(published.fileInspection, { chatgpt: true, gemini: false });
      assert.deepEqual(published.fileContentModes, { chatgpt: 'block', gemini: 'off' });
      assert.deepEqual(published.uploadTypes, { chatgpt: ['.pdf', 'image/*'], gemini: ['application/x-zekvar-private-type'] });
      assert.equal(published.discoveryEnabled, true);
      assert.deepEqual(published.domainRules, { allow: ['work.pilot.example.test'], block: ['pilot.example.test'] });
      assert.deepEqual(published.pathRules, { allow: ['pilot.example.test/start'], block: ['work.pilot.example.test/settings'] });
      assert.equal(requests.some((request) => request.includes(keyMaterial) || /preview-private-(prompt|path|file)|charset=utf-8/.test(request)), false);
    } finally {
      page.off('request', captureRequest);
    }
    await page.getByRole('link', { name: 'Overview', exact: true }).click();
    await page.getByRole('heading', { name: 'Security overview', exact: true }).waitFor();
    const directTypes = page.getByLabel('ChatGPT file types', { exact: true });
    const directPublish = page.getByRole('button', { name: 'Publish policy', exact: true });
    const current = await currentPolicy();
    await directTypes.fill('*.pdf');
    await directPublish.click();
    await page.getByRole('alert').filter({ hasText: 'Enter up to 25 valid file extensions or media types' }).waitFor();
    assert.equal((await currentPolicy()).version, current.version);
    const concurrent = await post('/admin/policies', { uploadTypes: { chatgpt: ['.zip'] } }, token);
    await directTypes.fill('.pdf image/*');
    await directPublish.click();
    await page.getByRole('alert').filter({ hasText: 'The policy changed. Reload and review the policy' }).waitFor();
    assert.deepEqual((await currentPolicy()).uploadTypes.chatgpt, ['.zip']);
    await page.reload();
    assert.equal(await directTypes.inputValue(), '.zip');
    await directTypes.fill('.pdf image/*');
    await directPublish.click();
    await page.getByText(`Version ${concurrent.version + 1} published in block mode.`, { exact: true }).waitFor();
    assert.deepEqual((await currentPolicy()).uploadTypes.chatgpt, ['.pdf', 'image/*']);
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
    await page.getByLabel('Recorded rollout group', { exact: true }).selectOption('baseline');
    const installation = page.getByLabel('Browser installation ID', { exact: true });
    await installation.fill('invalid');
    await page.getByRole('button', { name: 'Apply filters' }).click();
    await page.getByRole('alert').filter({ hasText: 'Enter a complete browser installation ID.' }).waitFor();
    const link = page.getByRole('link', { name: 'Export security events (JSON)', exact: true });
    assert.equal(await link.count(), 0);
    await page.getByLabel('Recorded rollout group', { exact: true }).selectOption('baseline');
    await installation.fill(browser.installationId);
    await page.getByLabel('Triage status', { exact: true }).selectOption('needs_review');
    await page.getByLabel('Triage assignee', { exact: true }).selectOption('unassigned');
    await page.getByRole('button', { name: 'Apply filters' }).click();
    const older = page.getByRole('link', { name: 'Older events', exact: true });
    await older.waitFor();
    assert.equal(await events.locator('tbody tr').count(), 100);
    const href = await link.getAttribute('href');
    const filters = new URL(href, dashboard).searchParams;
    assert.equal(filters.get('installationId'), browser.installationId);
    assert.equal(filters.get('appId'), 'chatgpt');
    assert.equal(filters.get('decision'), policy.mode);
    assert.equal(filters.get('rolloutGroup'), 'baseline');
    assert.equal(filters.get('triageStatus'), 'needs_review');
    assert.equal(filters.get('triageAssignee'), 'unassigned');
    assert.ok(filters.get('since'));
    await older.click();
    const newest = page.getByRole('link', { name: 'Newest events', exact: true });
    await newest.waitFor();
    assert.equal(new URL(page.url()).searchParams.get('since'), filters.get('since'));
    assert.equal(new URL(page.url()).searchParams.get('eventGroup'), 'baseline');
    assert.equal(await link.getAttribute('href'), href);
    assert.equal(await events.locator('tbody tr').count(), 2);
    const cursor = new URL(page.url()).searchParams.get('beforeEventId');
    await events.getByRole('link', { name: 'Needs review', exact: true }).first().click();
    await page.getByRole('heading', { name: 'Security event', exact: true }).waitFor();
    const desktop = page.viewportSize();
    await page.setViewportSize({ width: 390, height: 844 });
    await assertFitsViewport(page);
    await page.setViewportSize(desktop);
    await page.getByRole('link', { name: 'Back to security events', exact: true }).click();
    await newest.waitFor();
    assert.equal(new URL(page.url()).searchParams.get('beforeEventId'), cursor);
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
    assert.equal(reported.rolloutGroup, 'baseline');
    assert.equal(reported.triageStatus, 'needs_review');
    assert.equal(reported.triageAssignee, 'unassigned');
    assert.deepEqual(entries.map(({ eventId }) => eventId).sort(), ids.sort());
    assert.ok(entries.every((entry) => entry.installationId === browser.installationId && entry.appId === 'chatgpt'));
    assert.ok(entries.every(({ rollout }) => rollout.kind === 'baseline'));
    assert.equal([token, browser.token, other.token, grant, otherGrant].some((value) => data.includes(value)), false);
    for (const query of ['appId=chatgpt&appId=chatgpt', 'beforeAt=now', 'organization=another-tenant',
      'rolloutGroup=baseline&rolloutGroup=unattributed', 'rolloutGroup=invalid']) {
      assert.equal((await context.request.get(`${dashboard}/events/export?${query}`)).status(), 400);
    }
    await newest.click();
    await older.waitFor();
    const filterBrowser = events.getByRole('link', { name: `Filter events for installation ${browser.installationId}` }).first();
    assert.equal(new URL(await filterBrowser.getAttribute('href'), dashboard).searchParams.get('since'), filters.get('since'));
    await page.getByRole('link', { name: 'Clear filters', exact: true }).click();
    await page.waitForURL((url) => url.search === '');
    await page.goto(`${dashboard}/?eventGroup=baseline&eventGroup=unattributed#events`);
    await page.getByRole('alert').filter({ hasText: 'Choose a valid recorded rollout group.' }).waitFor();
    assert.equal(await link.count(), 0);
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
    await assertFitsViewport(page);
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
      await auditPage.getByLabel('Import test pack', { exact: true }).setInputFiles({ name: 'auditor-pack.json', mimeType: 'application/json',
        buffer: Buffer.from(JSON.stringify({ version: 1, cases: [
          { id: 'auditor-marker', kind: 'prompt', app: 'chatgpt', text: 'ZEKVAR_TEST_SECRET', expect: 'warn' },
        ] })) });
      await auditPage.getByText('Loaded 1 case.', { exact: true }).waitFor();
      await auditPage.getByRole('button', { name: 'Run preview', exact: true }).click();
      await auditPage.getByRole('table', { name: 'Test pack results', exact: true }).getByRole('row', { name: /auditor-marker.*(?:Pass|Fixed)/ }).waitFor();
      await auditPage.getByRole('table', { name: 'Preview results' }).waitFor();
      assert.equal(await auditPage.getByRole('button', { name: 'Publish previewed policy', exact: true }).count(), 0);
      await auditPage.getByRole('link', { name: 'Rollout groups', exact: true }).click();
      await auditPage.getByRole('heading', { name: 'Rollout groups', exact: true }).waitFor();
      assert.equal(await auditPage.getByRole('button', { name: /^(Create group|Publish|Promote|Restore|Save assignment)/ }).count(), 0);
      await auditPage.getByRole('link', { name: 'Data retention', exact: true }).click();
      await auditPage.getByRole('heading', { name: 'Retention windows', exact: true }).waitFor();
      assert.equal(await auditPage.getByRole('button', { name: /^(Save retention|Run cleanup)$/ }).count(), 0);
      await auditPage.getByRole('link', { name: 'Reports', exact: true }).click();
      await auditPage.getByRole('heading', { name: 'AI enforcement report', exact: true }).waitFor();
      assert.equal((await reviewerContext.request.get(`${dashboard}/reports/export`)).status(), 200);

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
      assert.equal((await operatorContext.request.get(`${dashboard}/reports/export`)).status(), 401);
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

  await t.test('runs reusable test packs locally against a rollout policy and an unpublished draft', async () => {
    const group = await post('/admin/policy-groups', { name: 'Test pack lab' }, token);
    const scope = `/admin/policy-groups/${group.id}/policies`;
    const published = await post(scope, {
      mode: 'warn', githubPatMode: 'off', clipboardMode: 'monitor', claudePromptEnabled: false,
      domainRules: { allow: [], block: ['workflow.example.test'] },
      pathRules: { allow: ['workflow.example.test/allowed'], block: [] },
      fileContentModes: { chatgpt: 'off', gemini: 'monitor' },
      uploadModes: { chatgpt: 'off', gemini: 'off' }, promptExceptions: [],
    }, token);
    const readApi = async (route) => {
      const response = await context.request.get(`${api}${route}`, { headers: { Authorization: `Bearer ${token}` } });
      assert.equal(response.status(), 200);
      return response.json();
    };
    const marker = 'ZEKVAR_TEST_SECRET';
    const sentinel = 'private-synthetic-pack-78ae1';
    const sample = `${sentinel} ${marker}`;
    const cases = [
      { id: 'blocked-prompt', kind: 'prompt', app: 'chatgpt', expect: 'block', text: sample },
      { id: 'warn-prompt', kind: 'prompt', app: 'gemini', expect: 'warn', text: marker },
      { id: 'clean-prompt', kind: 'prompt', app: 'chatgpt', expect: 'allow', text: 'Synthetic meeting notes.' },
      { id: 'disabled-claude', kind: 'prompt', app: 'claude', expect: 'block', text: marker },
      { id: 'blocked-paste', kind: 'clipboard', app: 'gemini', expect: 'block', text: marker },
      { id: 'missing-paste', kind: 'clipboard', app: 'chatgpt', expect: 'allow' },
      { id: 'oversized-paste', kind: 'clipboard', app: 'chatgpt', expect: 'block', text: 'x'.repeat(64_001) },
      { id: 'allowed-path', kind: 'navigation', expect: 'allow', url: `https://work.workflow.example.test/allowed/start?demo=${sentinel}` },
      { id: 'blocked-path', kind: 'navigation', expect: 'block', url: 'https://work.workflow.example.test/elsewhere' },
      { id: 'lookalike-host', kind: 'navigation', expect: 'allow', url: 'https://workflow.example.test.other.test/' },
      { id: 'file-contents', kind: 'upload', app: 'gemini', expect: 'block', file: { name: `${sentinel}.txt`, type: 'text/plain' }, text: sample },
      { id: 'unavailable-file', kind: 'upload', app: 'gemini', expect: 'block', file: { name: 'sample.pdf', type: 'application/pdf' } },
    ];
    const toFile = (value) => ({ name: 'test-pack.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(value)) });
    const [history, audit] = await Promise.all([readApi(scope), readApi('/admin/audit?action=policy_published')]);
    await page.goto(`${dashboard}/preview?group=${group.id}`);
    const packInput = page.getByLabel('Import test pack', { exact: true });
    const run = page.getByRole('button', { name: 'Run preview', exact: true });
    const table = page.getByRole('table', { name: 'Test pack results', exact: true });
    const getDownload = async (name) => {
      const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name, exact: true }).click()]);
      return { filename: download.suggestedFilename(), value: JSON.parse(await readFile(await download.path(), 'utf8')) };
    };
    const requests = [];
    const capture = (request) => requests.push({ url: request.url(), body: request.postData(), method: request.method() });
    page.on('request', capture);
    try {
      const starter = await getDownload('Download starter pack');
      assert.equal(starter.filename, 'zekvar-test-pack.json');
      await packInput.setInputFiles(toFile(starter.value));
      await page.getByText(`Loaded ${starter.value.cases.length} cases.`, { exact: true }).waitFor();
      await run.click();
      await table.waitFor();
      await page.getByRole('button', { name: 'Clear test pack', exact: true }).click();
      await table.waitFor({ state: 'detached' });

      const invalidPacks = [
        [toFile({ version: 2, cases }), /Use test pack version 1/],
        [toFile({ version: 1, cases: [cases[0], { ...cases[0], id: 'BLOCKED-PROMPT' }] }), /unique case ID in case 2/],
        [toFile({ version: 1, cases: [{ ...cases[7], url: 'javascript:alert(1)' }] }), /fields and expected outcome in case 1/],
        [toFile({ version: 1, cases: [{ ...cases[0], text: { value: sample } }] }), /fields and expected outcome in case 1/],
        [toFile({ version: 1, cases: [{ ...cases[10], app: 'claude' }] }), /fields and expected outcome in case 1/],
        [toFile({ version: 1, cases: [{ ...cases[1], payload: sample }] }), /fields and expected outcome in case 1/],
        [{ ...toFile({}), buffer: Buffer.from('{') }, /valid JSON/],
        [{ ...toFile({}), buffer: Buffer.alloc(256 * 1024 + 1, 32) }, /256 KiB/],
      ];
      for (const [file, error] of invalidPacks) {
        await packInput.setInputFiles(file);
        await page.getByRole('alert').filter({ hasText: error }).waitFor();
        assert.equal(await table.count(), 0);
      }
      await packInput.setInputFiles(toFile({ version: 1, cases }));
      await page.getByText(`Loaded ${cases.length} cases.`, { exact: true }).waitFor();
      await page.getByLabel('Draft test marker', { exact: true }).selectOption('block');
      await page.getByLabel('Draft clipboard paste protection', { exact: true }).selectOption('block');
      await page.getByLabel('Draft Gemini file content protection', { exact: true }).selectOption('block');
      await run.click();
      const expected = [
        ['warn', 'block', 'fixed'], ['warn', 'block', 'regression'], ['allow', 'allow', 'pass'], ['allow', 'allow', 'mismatch'],
        ['monitor', 'block', 'fixed'], ['allow', 'block', 'regression'], ['allow', 'block', 'fixed'], ['allow', 'allow', 'pass'],
        ['block', 'block', 'pass'], ['allow', 'allow', 'pass'], ['monitor', 'block', 'fixed'], ['allow', 'block', 'fixed'],
      ];
      await table.getByRole('row', { name: /blocked-prompt.*Fixed/ }).waitFor();
      await table.getByRole('row', { name: /warn-prompt.*Regression/ }).waitFor();
      await page.setViewportSize({ width: 390, height: 844 });
      await assertFitsViewport(page);
      await page.setViewportSize({ width: 1440, height: 1000 });
      const screenshot = process.env.ZEKVAR_TEST_PACK_SCREENSHOT;
      if (screenshot) {
        await table.scrollIntoViewIfNeeded();
        await page.screenshot({ path: screenshot });
      }
      const report = await getDownload('Download test results');
      assert.equal(report.filename, 'zekvar-test-results.json');
      assert.equal(report.value.version, 1);
      assert.equal(report.value.scope, group.name);
      assert.equal(report.value.currentVersion, published.version);
      assert.equal(report.value.draftSourceVersion, published.version);
      assert.ok(Number.isFinite(Date.parse(report.value.evaluatedAt)));
      assert.deepEqual(report.value.summary, { currentPassed: 6, draftPassed: 9, fixes: 5, regressions: 2 });
      assert.deepEqual(report.value.cases, cases.map(({ id, kind, app, expect }, index) => {
        const [current, draft, result] = expected[index];
        return { id, kind, ...(app && { app }), expect, current, draft, result };
      }));
      const privateData = new RegExp(`${sentinel}|${marker}|workflow\\.example\\.test/allowed/start`);
      assert.doesNotMatch(JSON.stringify(report.value), privateData);
      assert.ok(!requests.some(({ url, body, method }) => privateData.test(`${url} ${body}`) || method !== 'GET'));
      assert.deepEqual(await readApi(scope), history);
      assert.deepEqual(await readApi('/admin/audit?action=policy_published'), audit);

      await page.getByLabel('Draft test marker', { exact: true }).selectOption('warn');
      await table.waitFor({ state: 'detached' });
      assert.equal(await page.getByRole('button', { name: 'Download test results', exact: true }).count(), 0);
      await run.click();
      await table.getByRole('row', { name: /warn-prompt.*Pass/ }).waitFor();
      await page.getByRole('button', { name: 'Add prompt exception', exact: true }).click();
      const exception = page.getByRole('group', { name: 'Exception 1', exact: true });
      await exception.getByLabel('App', { exact: true }).selectOption('gemini');
      await exception.getByLabel('Expires (UTC)', { exact: true }).fill(new Date(Date.now() + 120_000).toISOString().slice(0, 16));
      await exception.getByLabel('Reason', { exact: true }).fill('Test pack exception');
      await packInput.setInputFiles(toFile({ version: 1, cases: [
        { ...cases[1], expect: 'exception_applied' }, cases[4],
      ] }));
      await page.getByText('Loaded 2 cases.', { exact: true }).waitFor();
      await run.click();
      await table.getByRole('row', { name: /warn-prompt.*Exception.*Fixed/ }).waitFor();
      await table.getByRole('row', { name: /blocked-paste.*Fixed/ }).waitFor();
      await packInput.setInputFiles(toFile({ version: 1, cases: [] }));
      await table.waitFor({ state: 'detached' });
      await packInput.setInputFiles(toFile({ version: 1, cases }));
      await page.getByText(`Loaded ${cases.length} cases.`, { exact: true }).waitFor();
      await page.reload();
      await run.click();
      await table.waitFor({ state: 'detached' });
      await page.getByRole('table', { name: 'Preview results', exact: true }).waitFor();
      assert.equal(await page.getByRole('button', { name: 'Clear test pack', exact: true }).count(), 0);
    } finally {
      page.off('request', capture);
    }
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
      await author.getByLabel('Draft extension inventory', { exact: true }).selectOption('on');
      await author.getByLabel('Custom app catalog', { exact: true }).fill('workspace.review.test, Review Workspace');
      await author.getByRole('button', { name: 'Add prompt exception', exact: true }).click();
      await author.getByLabel('Expires (UTC)', { exact: true }).fill(new Date(Date.now() + 600_000).toISOString().slice(0, -1));
      await author.getByLabel('Reason', { exact: true }).fill('Review fixture change EX-101');
      await author.getByLabel('Draft ChatGPT file types', { exact: true }).fill('.csv');
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
      await reviewed.getByText('Extension inventory · Off → On', { exact: true }).waitFor();
      await reviewed.getByText('workspace.review.test', { exact: true }).waitFor();
      await reviewed.getByText(/Review fixture change EX-101/).waitFor();
      await reviewed.getByText(/ChatGPT file types .* → \.csv$/).waitFor();
      await reviewed.getByText(`Reference v${prior.version}`, { exact: true }).waitFor();
      const screenshot = process.env.ZEKVAR_TEST_REVIEW_SCREENSHOT;
      if (screenshot) await approver.screenshot({ path: screenshot, fullPage: true });
      await approver.setViewportSize({ width: 390, height: 844 });
      await assertFitsViewport(approver);
      approver.once('dialog', (dialog) => dialog.accept());
      await reviewed.getByRole('button', { name: 'Approve and publish', exact: true }).click();
      await reviewed.getByText('Approved', { exact: true }).waitFor();
      await reviewed.getByText('Approved by Review approver', { exact: true }).waitFor();
      const [current] = await history();
      assert.ok(current.version > prior.version);
      await reviewed.getByText(`Reference v${prior.version} · Published v${current.version}`, { exact: true }).waitFor();
      assert.equal(current.mode, 'block');
      assert.equal(current.extensionInventoryEnabled, true);
      assert.equal(current.promptExceptions[0].reason, 'Review fixture change EX-101');
      assert.deepEqual(current.customApps.map(({ host, name }) => ({ host, name })), [{ host: 'workspace.review.test', name: 'Review Workspace' }]);
      assert.deepEqual(current.uploadTypes.chatgpt, ['.csv']);
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
    await assertFitsViewport(page);
    await page.getByRole('button', { name: 'Sign out' }).click();
    await page.getByRole('heading', { name: 'Sign in to Control' }).waitFor();
    assert.ok(!(await context.cookies()).some(({ name }) => name === 'zekvar_control_session'));
    assert.equal((await context.request.get(`${dashboard}/audit/export`)).status(), 401);
    assert.equal((await context.request.get(`${dashboard}/events/export`)).status(), 401);
    assert.deepEqual(clientErrors, []);
  });
});
