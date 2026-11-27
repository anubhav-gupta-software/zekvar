import { readBrowserState } from './browser-state.mjs';
import assert from 'node:assert/strict';
import { execFile, execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { chromium } from 'playwright';

const {
  ZEKVAR_DEMO_API: api, ZEKVAR_DEMO_WEB: web, ZEKVAR_DEMO_TOKEN: token, ZEKVAR_DEMO_OTHER_TOKEN: otherToken,
  ZEKVAR_DEMO_POSTGRES: postgres, ZEKVAR_DEMO_ARTIFACTS: artifacts,
} = process.env;
assert.match(api ?? '', /^http:\/\/127\.0\.0\.1:\d+$/);
assert.match(web ?? '', /^http:\/\/localhost:\d+$/);
assert.match(token ?? '', /^[a-f0-9]{64}$/);
assert.match(otherToken ?? '', /^[a-f0-9]{64}$/);
const catalog = JSON.parse(await readFile(new URL('../../../contracts/policy/saas-catalog.json', import.meta.url)));
const sql = promisify(execFile);

async function until(check, message) {
  for (let count = 0; count < 80; count++) {
    if (await check()) return;
    await delay(100);
  }
  assert.fail(message);
}

test('SaaS inventory reports only bundled catalog IDs and days, and Control classifies and blocks from the inventory', { timeout: 150_000 }, async (t) => {
  const scratch = await mkdtemp(join(tmpdir(), 'zekvar-saas-inventory-'));
  const dist = join(scratch, 'extension');
  const browsers = new Set();
  const bodies = [];
  const reports = [];
  const proxy = createServer(async (request, response) => {
    try {
      if (!request.url?.startsWith('/v1/browser/') && request.url !== '/v1/enroll') return response.writeHead(404).end();
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      // Every request body Browser sends to Control is kept for the privacy assertions below.
      bodies.push(request.url + ' ' + body.toString());
      if (request.url === '/v1/browser/saas-observations') reports.push(JSON.parse(body.toString()));
      const forwarded = Object.fromEntries(Object.entries(request.headers).filter(([name]) =>
        name === 'authorization' || name.startsWith('x-zekvar-')));
      const upstream = await fetch(api + request.url, {
        method: request.method,
        headers: { ...forwarded, ...(body.length ? { 'Content-Type': 'application/json' } : {}) },
        body: body.length ? body : undefined, signal: AbortSignal.timeout(5000),
      });
      response.writeHead(upstream.status, { 'Content-Type': 'application/json' }).end(await upstream.text());
    } catch {
      response.writeHead(502).end();
    }
  });
  t.after(async () => {
    await Promise.allSettled([...browsers].map((browser) => browser.close()));
    await new Promise((done) => { proxy.close(done); proxy.closeAllConnections(); });
    await rm(scratch, { recursive: true, force: true });
  });
  proxy.listen(0, '127.0.0.1');
  await once(proxy, 'listening');
  execFileSync(process.execPath, ['build.mjs'], {
    cwd: fileURLToPath(new URL('..', import.meta.url)),
    env: { ...process.env, ZEKVAR_CONTROL_PORT: String(proxy.address().port), ZEKVAR_EXTENSION_OUTDIR: dist },
  });

  async function admin(path, body, status = 200, credential = token) {
    const response = await fetch(api + '/v1/admin/' + path, {
      method: body ? 'POST' : 'GET',
      headers: { Authorization: `Bearer ${credential}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body && JSON.stringify(body), signal: AbortSignal.timeout(5000),
    });
    assert.equal(response.status, status, path);
    return response.ok && status !== 204 ? response.json() : undefined;
  }
  async function launch(name) {
    const browser = await chromium.launchPersistentContext(join(scratch, name), {
      channel: 'chromium', headless: process.env.ZEKVAR_DEMO_HEADED !== '1',
      args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`],
    });
    browsers.add(browser);
    browser.setDefaultTimeout(8000);
    const worker = browser.serviceWorkers()[0] ?? await browser.waitForEvent('serviceworker');
    const popup = await browser.newPage();
    await popup.goto(new URL('popup.html', worker.url()).href);
    return { browser, worker, popup };
  }
  // Grant the optional webNavigation permission to one profile, as a user would from the popup.
  const manifestPath = join(dist, 'manifest.json');
  const optionalManifest = await readFile(manifestPath, 'utf8');
  const seedManifest = JSON.parse(optionalManifest);
  seedManifest.optional_permissions = seedManifest.optional_permissions.filter((value) => value !== 'webNavigation');
  seedManifest.permissions.push('webNavigation');
  await writeFile(manifestPath, JSON.stringify(seedManifest));
  const seed = await launch('consented');
  await seed.browser.close();
  browsers.delete(seed.browser);
  await writeFile(manifestPath, optionalManifest);
  const consented = await launch('consented');
  const unconsented = await launch('unconsented');
  const allowed = (profile) => profile.worker.evaluate(() => chrome.permissions.contains({ permissions: ['webNavigation'] }));
  assert.equal(await allowed(consented), true);
  assert.equal(await allowed(unconsented), false);

  async function enroll(profile) {
    const { grant } = await admin('enrollment-grants', {});
    await profile.popup.getByLabel('Enrollment grant').fill(grant);
    await profile.popup.getByRole('button', { name: 'Enroll this browser', exact: true }).click();
    await profile.popup.getByText(/^Connected to Control/).waitFor();
    return (await readBrowserState(profile.worker)).enrollment.installationId;
  }
  async function sync(profile) {
    await profile.popup.getByRole('button', { name: 'Sync now', exact: true }).click();
    await profile.popup.waitForFunction(() => !document.querySelector('#sync').disabled);
  }
  const privatePath = '/s/local-private-folder/quarterly.xlsx?customer=synthetic-private-account#preview';
  const secretTitle = 'Synthetic private document title';
  async function visit(profile, url, body = `<title>${secretTitle}</title><h1>Controlled catalog page</h1>`) {
    const tab = await profile.browser.newPage();
    try {
      await tab.route('**/*', (route) => route.fulfill({
        contentType: 'text/html', body: route.request().isNavigationRequest() && route.request().frame() === tab.mainFrame() ?
          body : '<p>Frame fixture</p>',
      }));
      await tab.goto(url, { waitUntil: 'load' });
      await tab.locator('h1').waitFor();
    } finally { await tab.close(); }
  }
  const saasRow = async (appId, credential = token) =>
    (await admin('saas-apps', undefined, 200, credential)).apps.find((entry) => entry.appId === appId);

  // Disabled by default: an enrolled, permitted browser sends nothing for catalog sites.
  const consentedId = await enroll(consented);
  const unconsentedId = await enroll(unconsented);
  const [initial] = await admin('policies');
  assert.equal(initial.saasDiscoveryEnabled, false);
  await visit(consented, 'https://www.dropbox.com' + privatePath);
  await sync(consented);
  assert.deepEqual(reports, []);
  assert.equal((await readBrowserState(consented.worker)).saasObservations, undefined);

  // Enable SaaS inventory through Policy preview, separately from AI discovery.
  const dashboard = await consented.browser.newPage();
  await dashboard.setViewportSize({ width: 1440, height: 1000 });
  await dashboard.goto(web);
  await dashboard.getByLabel('Control token', { exact: true }).fill(token);
  await dashboard.getByRole('button', { name: 'Sign in', exact: true }).click();
  await dashboard.getByRole('heading', { name: 'Security overview' }).waitFor();
  await dashboard.goto(web + '/preview');
  await dashboard.getByLabel('Draft SaaS app inventory', { exact: true }).selectOption('on');
  await dashboard.getByRole('button', { name: 'Run preview', exact: true }).click();
  const changes = dashboard.getByRole('list', { name: 'Policy setting changes' });
  await changes.getByText('SaaS app inventory · Off → On', { exact: true }).waitFor();
  dashboard.once('dialog', (dialog) => dialog.accept());
  await dashboard.getByRole('button', { name: 'Publish previewed policy', exact: true }).click();
  await dashboard.getByText(/^Previewed policy published as version \d+\.$/).waitFor();
  const [enabled] = await admin('policies');
  assert.equal(enabled.saasDiscoveryEnabled, true);
  assert.equal(enabled.discoveryEnabled, false);
  await sync(consented);
  await sync(unconsented);
  await consented.popup.getByText(/^SaaS app inventory is on\./).waitFor();
  await unconsented.popup.getByRole('button', { name: 'Allow catalog discovery', exact: true }).waitFor();
  const installations = async () => Object.fromEntries((await admin('installations')).map((row) => [row.installationId, row]));
  await until(async () => (await installations())[consentedId].appliedPolicyVersion === enabled.version,
    'The permitted browser did not acknowledge SaaS inventory.');
  assert.notEqual((await installations())[unconsentedId].appliedPolicyVersion, enabled.version,
    'A browser without the Chrome permission must not acknowledge SaaS inventory.');

  // Non-catalog hosts, look-alike hosts, other schemes and ports, and frames are never reported.
  await visit(unconsented, 'https://www.dropbox.com' + privatePath);
  for (const url of ['https://unlisted.example.test' + privatePath, 'https://dropbox.com.other.test' + privatePath,
    'https://notdropbox.com/', 'http://www.dropbox.com' + privatePath, 'https://www.dropbox.com:8443' + privatePath,
    'https://google.com/', 'https://www.google.com/search?q=synthetic-private-account']) {
    await visit(consented, url);
  }
  await visit(consented, 'https://unlisted.example.test/', `<h1>Unlisted page</h1><iframe src="https://www.dropbox.com${privatePath}"></iframe>`);
  await sync(consented);
  await sync(unconsented);
  assert.deepEqual(reports, []);

  // Catalog hosts report their catalog ID only. Exact hosts win over a parent domain.
  const visits = [['https://www.dropbox.com', 'dropbox'], ['https://acme.slack.com', 'slack'], ['https://gist.github.com', 'github-gist'],
    ['https://mail.google.com', 'gmail'], ['https://github.com', 'github']];
  for (const [origin, appId] of visits) {
    await visit(consented, origin + privatePath);
    await until(async () => (await saasRow(appId)).browsersSeen === 1, `Expected one browser for ${appId}.`);
  }
  assert.deepEqual(reports.map(({ appId }) => appId), visits.map(([, appId]) => appId));
  const today = new Date().toISOString().slice(0, 10);
  for (const report of reports) {
    assert.deepEqual(Object.keys(report).sort(), ['appId', 'day', 'policyVersion']);
    assert.equal(report.day, today);
    assert.equal(report.policyVersion, enabled.version);
  }
  // The same app on the same day is reported once.
  await visit(consented, 'https://www.dropbox.com/another' + privatePath);
  await sync(consented);
  assert.equal(reports.filter(({ appId }) => appId === 'dropbox').length, 1);
  const everything = bodies.join('\n');
  assert.doesNotMatch(everything, /local-private|synthetic-private-account|quarterly|Synthetic private document|dropbox\.com|slack\.com|github\.com|google\.com/);
  assert.ok(catalog.apps.some(({ id }) => id === 'dropbox'));
  assert.deepEqual(await saasRow('dropbox'), { appId: 'dropbox', status: 'unclassified', browsersSeen: 1, firstSeenDay: today, lastSeenDay: today });

  // Classify from the SaaS inventory page, filtered by risk.
  await dashboard.goto(web);
  await dashboard.getByRole('link', { name: 'SaaS inventory', exact: true }).click();
  await dashboard.getByRole('heading', { name: 'SaaS inventory', exact: true }).waitFor();
  await dashboard.getByLabel('Risk', { exact: true }).selectOption('personal-file-sharing');
  await dashboard.getByLabel('Activity', { exact: true }).selectOption('seen');
  await dashboard.getByRole('button', { name: 'Apply filters', exact: true }).click();
  await dashboard.waitForURL(/risk=personal-file-sharing/);
  const table = dashboard.getByRole('table', { name: 'SaaS apps', exact: true });
  const rows = table.locator('tbody tr');
  await until(async () => await rows.count() === 1, 'The risk filter did not narrow the inventory to Dropbox.');
  const dropbox = rows.filter({ hasText: 'Dropbox' });
  await dropbox.getByText('Personal file sharing', { exact: true }).waitFor();
  await dropbox.getByRole('cell', { name: '1', exact: true }).waitFor();
  await dropbox.getByLabel('Dropbox classification', { exact: true }).selectOption('unsanctioned');
  await dropbox.getByRole('button', { name: 'Save Dropbox classification', exact: true }).click();
  await dropbox.getByText('Dropbox classification saved.', { exact: true }).waitFor();
  assert.equal((await saasRow('dropbox')).status, 'unsanctioned');
  if (artifacts) await dashboard.screenshot({ path: join(artifacts, '45-control-saas-inventory.png'), fullPage: true });
  await dashboard.goto(web + '/saas?category=developer');
  assert.ok((await table.locator('tbody tr').allTextContents()).every((text) => text.includes('Developer tools')));
  await dashboard.setViewportSize({ width: 390, height: 844 });
  await dashboard.goto(web + '/saas');
  assert.ok(await dashboard.evaluate(() => document.documentElement.scrollWidth === document.documentElement.clientWidth),
    'The SaaS inventory page scrolls horizontally at 390px.');
  if (artifacts) await dashboard.screenshot({ path: join(artifacts, '46-control-saas-inventory-mobile.png') });
  await dashboard.setViewportSize({ width: 1440, height: 1000 });
  await dashboard.getByRole('link', { name: 'Audit log', exact: true }).click();
  await dashboard.getByText('Dropbox · Unclassified → Unsanctioned', { exact: true }).waitFor();

  // Block the unsanctioned app through the existing domain rules, with the preview and confirmation.
  await dashboard.goto(web + '/saas?status=unsanctioned');
  await dashboard.getByRole('link', { name: 'Block Dropbox in policy preview', exact: true }).click();
  await dashboard.getByRole('heading', { name: 'Policy preview', exact: true }).waitFor();
  await dashboard.getByRole('status').filter({ hasText: 'Draft blocks Dropbox from SaaS inventory' }).waitFor();
  assert.equal(await dashboard.getByLabel('Draft blocked domains', { exact: true }).inputValue(), 'dropbox.com');
  await dashboard.getByRole('button', { name: 'Run preview', exact: true }).click();
  await changes.waitFor();
  let confirmation;
  dashboard.once('dialog', (dialog) => { confirmation = dialog.message(); void dialog.dismiss(); });
  await dashboard.getByRole('button', { name: 'Publish previewed policy', exact: true }).click();
  await until(() => confirmation, 'Publishing did not ask for confirmation.');
  assert.deepEqual((await admin('policies'))[0].domainRules.block, [], 'Dismissing the confirmation must not publish.');
  dashboard.once('dialog', (dialog) => dialog.accept());
  await dashboard.getByRole('button', { name: 'Publish previewed policy', exact: true }).click();
  await dashboard.getByText(/^Previewed policy published as version \d+\.$/).waitFor();
  const [blocked] = await admin('policies');
  assert.deepEqual(blocked.domainRules.block, ['dropbox.com']);
  assert.equal(blocked.saasDiscoveryEnabled, true);
  await sync(consented);
  await until(async () => (await installations())[consentedId].appliedPolicyVersion === blocked.version,
    'The browser did not acknowledge the block.');
  const tab = await consented.browser.newPage();
  await assert.rejects(tab.goto('https://www.dropbox.com/blocked-check'), /ERR_BLOCKED_BY_CLIENT/);
  await tab.close();

  // Auditors read the inventory but cannot classify or block; another tenant sees nothing.
  const auditor = await admin('access', { name: 'SaaS inventory auditor', role: 'auditor', hours: 1 });
  await admin('saas-apps/dropbox/classification', { status: 'sanctioned' }, 403, auditor.token);
  const viewer = await chromium.launch({ channel: 'chromium', headless: process.env.ZEKVAR_DEMO_HEADED !== '1' });
  browsers.add(viewer);
  const audit = await viewer.newPage();
  await audit.goto(web);
  await audit.getByLabel('Control token', { exact: true }).fill(auditor.token);
  await audit.getByRole('button', { name: 'Sign in', exact: true }).click();
  await audit.getByRole('heading', { name: 'Security overview' }).waitFor();
  await audit.goto(web + '/saas?status=unsanctioned');
  const auditRow = audit.getByRole('table', { name: 'SaaS apps', exact: true }).locator('tbody tr').filter({ hasText: 'Dropbox' });
  await auditRow.getByText('Unsanctioned', { exact: true }).waitFor();
  assert.equal(await auditRow.getByRole('button').count(), 0);
  assert.equal(await auditRow.getByRole('link').count(), 0);
  assert.deepEqual(await saasRow('dropbox', otherToken),
    { appId: 'dropbox', status: 'unclassified', browsersSeen: 0, firstSeenDay: null, lastSeenDay: null });

  // Retention expires inventory with the AI observations window.
  await t.test('expires SaaS inventory with the observation retention window', { skip: !postgres }, async () => {
    assert.match(postgres, /^zekvar-demo-[a-f0-9]{10}$/);
    await sql('docker', ['exec', postgres, 'psql', '-XAtq', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'zekvar', '-c',
      `UPDATE saas_app_observations SET first_seen_day = current_date - 9, last_seen_day = current_date - 8
       WHERE installation_id = '${consentedId}' AND app_id = 'slack'`]);
    assert.equal((await saasRow('slack')).browsersSeen, 1);
    const retention = await admin('retention');
    await admin('retention', { ...retention, aiObservationDays: 2 }, 204);
    assert.equal((await saasRow('slack')).browsersSeen, 0);
    assert.ok((await admin('retention/cleanup', {})).saasObservations >= 1);
    assert.equal((await saasRow('dropbox')).browsersSeen, 1);
    await admin('retention', retention, 204);
    assert.equal((await saasRow('slack')).browsersSeen, 0, 'Expired SaaS records stay deleted after the window widens.');
  });

  // Removing the Chrome permission drops queued reports, stops reporting, and withdraws the acknowledgment.
  await consented.popup.getByRole('button', { name: 'Remove catalog discovery permission', exact: true }).click();
  await consented.popup.getByRole('button', { name: 'Allow catalog discovery', exact: true }).waitFor();
  await until(async () => (await installations())[consentedId].appliedPolicyVersion === null,
    'Control still considers SaaS inventory applied after permission removal.');
  const sent = reports.length;
  await visit(consented, 'https://www.notion.so' + privatePath);
  await sync(consented);
  assert.equal(reports.length, sent);
  assert.equal((await saasRow('notion')).browsersSeen, 0);
});
