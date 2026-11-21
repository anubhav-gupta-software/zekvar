import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const { ZEKVAR_DEMO_API: api, ZEKVAR_DEMO_WEB: web, ZEKVAR_DEMO_TOKEN: token, ZEKVAR_DEMO_ARTIFACTS: artifacts } = process.env;
assert.match(api ?? '', /^http:\/\/127\.0\.0\.1:\d+$/);
assert.match(web ?? '', /^http:\/\/localhost:\d+$/);
assert.match(token ?? '', /^[a-f0-9]{64}$/);

async function until(check, message) {
  for (let count = 0; count < 80; count++) {
    if (await check()) return;
    await delay(100);
  }
  assert.fail(message);
}

test('Control custom app catalog reports only assigned HTTPS sites with optional Chrome permission', { timeout: 90_000 }, async (t) => {
  const scratch = await mkdtemp(join(tmpdir(), 'zekvar-app-catalog-'));
  const dist = join(scratch, 'extension');
  const browsers = new Set();
  const submissions = [];
  let offline = false;
  let loseNextAcknowledgment = false;
  const proxy = createServer(async (request, response) => {
    try {
      if (!request.url?.startsWith('/v1/browser/') && request.url !== '/v1/enroll') return response.writeHead(404).end();
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      const observation = request.url === '/v1/browser/ai-app-observations';
      if (observation) submissions.push(JSON.parse(body.toString()));
      if (offline) return response.writeHead(503).end();
      const upstream = await fetch(api + request.url, {
        method: request.method,
        headers: {
          ...(request.headers.authorization ? { Authorization: request.headers.authorization } : {}),
          ...(request.headers['x-zekvar-assignment-aware'] ? { 'X-Zekvar-Assignment-Aware': '1' } : {}),
          ...(body.length ? { 'Content-Type': 'application/json' } : {}),
        },
        body: body.length ? body : undefined,
        signal: AbortSignal.timeout(5000),
      });
      if (observation && upstream.ok && loseNextAcknowledgment) {
        loseNextAcknowledgment = false;
        return response.writeHead(503).end();
      }
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

  async function admin(path, body, status = 200) {
    const response = await fetch(api + '/v1/admin/' + path, {
      method: body ? 'POST' : 'GET',
      headers: { Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body && JSON.stringify(body), signal: AbortSignal.timeout(5000),
    });
    assert.equal(response.status, status);
    return status === 204 ? undefined : response.json();
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
  const manifestPath = join(dist, 'manifest.json');
  const optionalManifest = await readFile(manifestPath, 'utf8');
  const seedManifest = JSON.parse(optionalManifest);
  seedManifest.optional_permissions = seedManifest.optional_permissions.filter((value) => value !== 'webNavigation');
  seedManifest.permissions.push('webNavigation');
  await writeFile(manifestPath, JSON.stringify(seedManifest));
  const seed = await launch('prior-consent');
  assert.equal(await seed.worker.evaluate(() => chrome.permissions.contains({ permissions: ['webNavigation'] })), true);
  await seed.browser.close();
  browsers.delete(seed.browser);
  await writeFile(manifestPath, optionalManifest);

  let enrolled = await launch('prior-consent');
  const unconsented = await launch('no-consent');
  const allowed = (profile) => profile.worker.evaluate(() => chrome.permissions.contains({ permissions: ['webNavigation'] }));
  assert.equal(await allowed(enrolled), true);
  assert.equal(await allowed(unconsented), false);
  const dashboard = await enrolled.browser.newPage();
  await dashboard.goto(web);
  await dashboard.getByLabel('Control token', { exact: true }).fill(token);
  await dashboard.getByRole('button', { name: 'Sign in', exact: true }).click();
  await dashboard.getByRole('heading', { name: 'Security overview' }).waitFor();
  await dashboard.getByRole('link', { name: 'Edit app catalog', exact: true }).click();
  await dashboard.getByRole('heading', { name: 'Policy preview', exact: true }).waitFor();
  const editor = dashboard.getByLabel('Custom app catalog', { exact: true });
  const runPreview = dashboard.getByRole('button', { name: 'Run preview', exact: true });
  await editor.fill('https://workspace.example.test/private, Example Workspace');
  await runPreview.click();
  await dashboard.getByRole('alert').filter({ hasText: 'Enter up to 25 unique app domains and names' }).waitFor();
  await editor.fill(' WORKSPACE.EXAMPLE.TEST. , Example Workspace');
  await dashboard.getByLabel('Draft app discovery', { exact: true }).selectOption('on');
  await runPreview.click();
  await dashboard.getByRole('list', { name: 'Policy setting changes' }).getByText('workspace.example.test', { exact: true }).waitFor();
  dashboard.once('dialog', (dialog) => dialog.accept());
  await dashboard.getByRole('button', { name: 'Publish previewed policy', exact: true }).click();
  await dashboard.getByText('Previewed policy published as version 2.', { exact: true }).waitFor();
  await dashboard.getByRole('link', { name: 'Overview', exact: true }).click();
  const [published] = await admin('policies');
  const [{ id, host }] = published.customApps;
  assert.equal(host, 'workspace.example.test');

  async function enroll(profile) {
    const { grant } = await admin('enrollment-grants', {});
    await profile.popup.getByLabel('Enrollment grant').fill(grant);
    await profile.popup.getByRole('button', { name: 'Enroll this browser', exact: true }).click();
    await profile.popup.getByText(/^Connected to Control/).waitFor();
    return profile.worker.evaluate(async () => (await chrome.storage.local.get('controlState')).controlState.enrollment.installationId);
  }
  async function sync(profile) {
    await profile.popup.getByRole('button', { name: 'Sync now', exact: true }).click();
    await profile.popup.waitForFunction(() => !document.querySelector('#sync').disabled);
  }
  const installationId = await enroll(enrolled);
  const unconsentedId = await enroll(unconsented);
  await unconsented.popup.getByRole('button', { name: 'Allow custom app discovery', exact: true }).waitFor();
  await enrolled.popup.getByText('Custom app discovery enabled for 1 cataloged site.', { exact: true }).waitFor();
  await until(async () => (await admin('installations')).find((row) => row.installationId === installationId).appliedPolicyVersion === 2,
    'The permitted browser did not acknowledge custom discovery.');
  assert.equal((await admin('installations')).find((row) => row.installationId === unconsentedId).appliedPolicyVersion, null);

  const privatePath = '/local-private-catalog-data?customer=synthetic-private-account';
  const target = 'https://' + host;
  async function visit(profile, url, body = '<h1>Controlled catalog page</h1>') {
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
  await visit(unconsented, target + privatePath);
  await visit(enrolled, 'https://sub.' + host + privatePath);
  await visit(enrolled, target + '.other.test' + privatePath);
  await visit(enrolled, 'http://' + host + privatePath);
  await visit(enrolled, target + ':8443' + privatePath);
  await visit(enrolled, 'https://unlisted.example.test/', `<h1>Unlisted page</h1><iframe src="${target}${privatePath}"></iframe>`);
  await sync(unconsented);
  await sync(enrolled);
  assert.deepEqual(submissions, []);

  const app = async () => (await admin('ai-apps')).find((entry) => entry.appId === id);
  await visit(enrolled, target + privatePath);
  await until(async () => (await app())?.browsersSeen === 1, 'The cataloged app did not report.');
  assert.deepEqual(Object.keys(submissions[0]).sort(), ['appId', 'observedAt', 'policyVersion']);
  assert.equal(submissions[0].appId, id);
  await dashboard.getByRole('button', { name: 'Refresh app inventory', exact: true }).click();
  const inventory = dashboard.getByRole('table', { name: 'App inventory', exact: true });
  const row = inventory.getByRole('row').filter({ hasText: 'Example Workspace' });
  await row.getByText('1', { exact: true }).waitFor();
  await row.getByLabel('Example Workspace at workspace.example.test classification', { exact: true }).selectOption('approved');
  await row.getByRole('button', { name: 'Save Example Workspace at workspace.example.test classification' }).click();
  await row.getByText('App classification saved.', { exact: true }).waitFor();
  assert.equal((await app()).status, 'approved');
  if (artifacts) await inventory.screenshot({ path: join(artifacts, '25-control-app-catalog.png') });
  await dashboard.setViewportSize({ width: 390, height: 844 });
  assert.ok(await dashboard.evaluate(() => document.documentElement.scrollWidth === document.documentElement.clientWidth));

  offline = true;
  await sync(enrolled);
  const oldTime = (await app()).lastObservedAt;
  await visit(enrolled, target + '/offline' + privatePath);
  await until(async () => enrolled.worker.evaluate((id) =>
    chrome.storage.local.get('controlState').then(({ controlState }) => Boolean(controlState.observations?.[id])), id),
  'Chrome did not queue the observation during the outage.');
  assert.equal((await app()).lastObservedAt, oldTime);
  offline = false;
  loseNextAcknowledgment = true;
  await sync(enrolled);
  await until(() => !loseNextAcknowledgment, 'The proxy did not interrupt the first acknowledgment.');
  await sync(enrolled);
  const [failed, retry] = submissions.slice(-2);
  assert.deepEqual(retry, failed);
  assert.equal((await app()).browsersSeen, 1);
  assert.equal(Date.parse((await app()).lastObservedAt), Date.parse(retry.observedAt));
  assert.doesNotMatch(JSON.stringify(submissions), /workspace\.example\.test|local-private|synthetic-private-account/);

  await enrolled.browser.close();
  browsers.delete(enrolled.browser);
  enrolled = await launch('prior-consent');
  await enrolled.popup.getByText('Custom app discovery enabled for 1 cataloged site.', { exact: true }).waitFor();
  await visit(enrolled, target + '/after-restart');
  await until(async () => Date.parse((await app()).lastObservedAt) > Date.parse(retry.observedAt),
    'Discovery did not recover after restarting Chrome.');
  assert.equal((await app()).browsersSeen, 1);

  await t.test('reports a configured public example site without its URL', {
    skip: process.env.ZEKVAR_DEMO_LIVE !== '1',
  }, async (live) => {
    const publicCatalog = await admin('policies', { customApps: [
      { host, name: 'Example Workspace' }, { host: 'example.com', name: 'Public Example Site' },
    ] });
    await sync(enrolled);
    await enrolled.popup.getByText('Custom app discovery enabled for 2 cataloged sites.', { exact: true }).waitFor();
    const report = publicCatalog.customApps.find((entry) => entry.host === 'example.com');
    const tab = await enrolled.browser.newPage();
    try {
      const response = await tab.goto('https://example.com/?synthetic-live-catalog', { waitUntil: 'domcontentloaded', timeout: 12_000 })
        .catch(() => undefined);
      if (!response?.ok()) return live.skip('The public example site was unavailable.');
      await until(async () => (await admin('ai-apps')).find((entry) => entry.appId === report.id)?.browsersSeen === 1,
        'The configured public app did not report.');
      assert.doesNotMatch(JSON.stringify(submissions), /example\.com|synthetic-live-catalog/);
    } finally { await tab.close(); }
  });

  await enrolled.popup.getByRole('button', { name: 'Remove custom app discovery permission', exact: true }).click();
  await enrolled.popup.getByRole('button', { name: 'Allow custom app discovery', exact: true }).waitFor();
  await until(async () => (await admin('installations')).find((row) => row.installationId === installationId).appliedPolicyVersion === null,
    'Control still considers discovery applied after permission removal.');
  const count = submissions.length;
  await visit(enrolled, target + '/after-permission-removal');
  await sync(enrolled);
  assert.equal(submissions.length, count);
  await admin('policies', { customApps: [] });
  assert.equal(await app(), undefined);
});
