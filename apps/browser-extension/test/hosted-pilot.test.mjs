import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { preparePreflight } from './preflight-fixture.mjs';

const {
  ZEKVAR_HOSTED_TEST_API_PORT: apiPort, ZEKVAR_HOSTED_TEST_WEB_PORT: webPort,
  ZEKVAR_DEMO_TOKEN: owner, ZEKVAR_DEMO_ARTIFACTS: artifacts, ZEKVAR_CADDY: caddy = 'caddy',
} = process.env;
assert.match(apiPort ?? '', /^\d+$/);
assert.match(webPort ?? '', /^\d+$/);
assert.match(owner ?? '', /^[a-f0-9]{64}$/);

async function availablePort() {
  const server = createServer().listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();
  await new Promise((done) => server.close(done));
  return port;
}

async function until(check, message) {
  for (let count = 0; count < 80; count++) {
    const value = await check();
    if (value) return value;
    await delay(100);
  }
  assert.fail(message);
}

test('the TLS pilot keeps administration private and enrolls Chrome on its configured origin', { timeout: 100_000 }, async (t) => {
  const scratch = await mkdtemp(join(tmpdir(), 'zekvar-pilot-tls-'));
  const extension = join(scratch, 'extension');
  const profile = join(scratch, 'profile');
  const dashboardHost = 'control.zekvar.test';
  const browserHost = 'browser.zekvar.test';
  const updatesHost = 'updates.zekvar.test';
  const cert = join(scratch, 'site.pem');
  const key = join(scratch, 'site.key');
  const ca = join(scratch, 'ca.pem');
  const caddyfile = join(scratch, 'Caddyfile');
  const fixture = await readFile(new URL('./guest-chatgpt-composer.html', import.meta.url), 'utf8');
  let edge;
  let browser;
  let edgeLog = '';
  t.after(async () => {
    await browser?.close();
    await stopEdge();
    await rm(scratch, { recursive: true, force: true });
  });

  const openssl = (...args) => execFileSync('openssl', args, { cwd: scratch, stdio: 'pipe' });
  openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=Zekvar Test CA',
    '-keyout', 'ca.key', '-out', 'ca.pem');
  openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=' + dashboardHost, '-keyout', 'site.key', '-out', 'site.csr');
  await writeFile(join(scratch, 'extensions.cnf'), `subjectAltName=DNS:${dashboardHost},DNS:${browserHost},DNS:${updatesHost}\nextendedKeyUsage=serverAuth\n`);
  openssl('x509', '-req', '-in', 'site.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial',
    '-days', '2', '-extfile', 'extensions.cnf', '-out', 'site.pem');
  const trust = await readFile(ca);
  const certificate = new X509Certificate(await readFile(cert));
  const pin = createHash('sha256').update(certificate.publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
  const tlsPort = await availablePort();
  const httpPort = await availablePort();
  const dashboardOrigin = `https://${dashboardHost}:${tlsPort}`;
  const browserOrigin = `https://${browserHost}:${tlsPort}`;
  const source = await readFile(new URL('../../../deploy/pilot/Caddyfile', import.meta.url), 'utf8');
  // The lab runs on unprivileged ports. Direct each cleartext test host to its full HTTPS origin.
  await writeFile(caddyfile, source.replace('{\n', `{\n\tdefault_bind 127.0.0.1\n\thttp_port ${httpPort}\n\thttps_port ${tlsPort}\n`)
    .replaceAll(/(\{\$ZEKVAR_(?:DASHBOARD|BROWSER)_HOST\} \{)/g, `$1\n\ttls "${cert}" "${key}"`)
    + `\nhttp://${dashboardHost} {\n\tredir ${dashboardOrigin}{uri} 308\n}\nhttp://${browserHost} {\n\tredir ${browserOrigin}{uri} 308\n}\n`);
  const preflight = await preparePreflight(t, { scratch, key, cert, ca, dashboardOrigin, browserOrigin, httpPort, updatesHost });

  function call(url, { method = 'GET', headers = {}, body, validate = true } = {}) {
    return new Promise((resolve, reject) => {
      const transport = url.startsWith('https:') ? httpsRequest : httpRequest;
      const request = transport(url, {
        method, headers, agent: false, ca: validate ? trust : undefined,
        lookup: (_host, options, done) => options.all ? done(null, [{ address: '127.0.0.1', family: 4 }]) : done(null, '127.0.0.1', 4),
        timeout: 3000,
      }, (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => resolve({
          status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks).toString(),
        }));
      });
      request.on('error', reject);
      request.on('timeout', () => request.destroy(new Error('Edge request timed out')));
      request.end(body);
    });
  }

  async function startEdge(networks) {
    const env = {
      ...process.env,
      XDG_DATA_HOME: join(scratch, 'data'), XDG_CONFIG_HOME: join(scratch, 'config'),
      ZEKVAR_DASHBOARD_HOST: dashboardHost, ZEKVAR_BROWSER_HOST: browserHost, ZEKVAR_ADMIN_NETWORKS: networks,
      ZEKVAR_ACME_EMAIL: 'fixture@example.test', ZEKVAR_API_PORT: apiPort, ZEKVAR_WEB_PORT: webPort,
    };
    edgeLog = '';
    const child = spawn(caddy, ['run', '--config', caddyfile, '--adapter', 'caddyfile'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    for (const stream of [child.stdout, child.stderr]) stream.on('data', (chunk) => { edgeLog = (edgeLog + chunk).slice(-2500); });
    edge = { child, closed: once(child, 'close') };
    await until(async () => (await call(browserOrigin + '/health').catch(() => undefined))?.status === 200 || child.exitCode !== null,
      'The TLS edge did not start.');
    assert.equal(child.exitCode, null, edgeLog);
  }
  async function stopEdge() {
    if (!edge) return;
    edge.child.kill('SIGTERM');
    await edge.closed;
    edge = undefined;
  }

  await startEdge('192.0.2.10/32');
  assert.equal((await call(dashboardOrigin + '/', { headers: { 'X-Forwarded-For': '192.0.2.10' } })).status, 403);
  await t.test('preflight proves dashboard denial and public update availability outside the admin allowlist', async () => {
    const evidence = await preflight.verify('denied');
    if (artifacts) await writeFile(join(artifacts, 'preflight-denied.json'), JSON.stringify(evidence, null, 2) + '\n');
  });
  await stopEdge();
  await startEdge('127.0.0.1/32');
  await assert.rejects(call(browserOrigin + '/health', { validate: false }), /certificate|issuer/i);
  const redirect = await call(`http://${browserHost}:${httpPort}/health`);
  assert.equal(redirect.status, 308);
  assert.equal(redirect.headers.location, `${browserOrigin}/health`);
  await t.test('preflight verifies the allowed dashboard and recovers after release and TLS failures', async () => {
    await preflight.verify('allowed');
    const evidence = await preflight.failures();
    if (artifacts) await writeFile(join(artifacts, 'preflight-allowed.json'), JSON.stringify(evidence, null, 2) + '\n');
  });
  for (const origin of [browserOrigin, dashboardOrigin]) {
    for (const path of ['/v1/admin/session', '/v1/admin/browser-releases', '/v1/admin/browser-health?rolloutGroup=baseline',
      '/v1/admin/enrollment-batches', '/v1/admin/reports/ai-enforcement']) {
      const blocked = await call(origin + path, { headers: { Authorization: `Bearer ${owner}` } });
      assert.equal(blocked.status, 404);
      assert.equal(blocked.headers['cache-control'], 'no-store');
      assert.match(blocked.headers['strict-transport-security'], /^max-age=/);
    }
  }
  assert.equal((await call(dashboardOrigin + '/v1/browser/policy')).status, 404);
  assert.equal((await call(browserOrigin + '/')).status, 404);
  assert.equal((await call(browserOrigin + '/reports/export')).status, 404);
  assert.equal((await call(browserOrigin + '/v1/enroll')).status, 404);
  assert.equal((await call(browserOrigin + '/v1/browser/policy', { headers: { Authorization: `Bearer ${owner}` } })).status, 401);
  assert.equal((await call(browserOrigin + '/v1/enroll', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant: '0'.repeat(64) }) })).status, 401);

  async function admin(path, body) {
    const response = await fetch(`http://127.0.0.1:${apiPort}/v1/admin/${path}`, {
      method: body ? 'POST' : 'GET',
      headers: { Authorization: `Bearer ${owner}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body && JSON.stringify(body), signal: AbortSignal.timeout(5000),
    });
    assert.equal(response.status, 200, 'Private Control operation failed');
    return response.json();
  }

  function build(hosted) {
    const { ZEKVAR_CONTROL_ORIGIN: _origin, ZEKVAR_CONTROL_PORT: _port, ...env } = process.env;
    execFileSync(process.execPath, ['build.mjs'], {
      cwd: fileURLToPath(new URL('..', import.meta.url)),
      env: { ...env, ZEKVAR_EXTENSION_OUTDIR: extension,
        ...(hosted ? { ZEKVAR_CONTROL_ORIGIN: browserOrigin } : { ZEKVAR_CONTROL_PORT: apiPort }) },
    });
  }

  async function launch(reload = false) {
    browser = await chromium.launchPersistentContext(profile, {
      channel: 'chromium', headless: process.env.ZEKVAR_DEMO_HEADED !== '1',
      args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`, '--no-proxy-server',
        `--host-resolver-rules=MAP ${dashboardHost} 127.0.0.1, MAP ${browserHost} 127.0.0.1`,
        `--ignore-certificate-errors-spki-list=${pin}`],
    });
    browser.setDefaultTimeout(9000);
    if (reload) {
      const manager = await browser.newPage();
      await manager.goto('chrome://extensions/');
      const developerMode = manager.locator('#devMode');
      await developerMode.waitFor();
      if (await developerMode.getAttribute('aria-checked') !== 'true') await developerMode.click();
      const card = manager.locator('extensions-item').filter({ hasText: 'Zekvar Browser' });
      await card.locator('#dev-reload-button').click();
      await manager.close();
    }
    const manifest = JSON.parse(await readFile(join(extension, 'manifest.json'), 'utf8'));
    const currentWorker = (worker) => new URL(worker.url()).pathname === '/' + manifest.background.service_worker;
    const worker = browser.serviceWorkers().find(currentWorker) ?? await browser.waitForEvent('serviceworker', currentWorker);
    const popup = await browser.newPage();
    await popup.goto(new URL('popup.html', worker.url()).href);
    return { popup, worker };
  }
  const label = (popup, text) => popup.getByText(text, { exact: true });
  const installation = (worker) => worker.evaluate(async () =>
    (await chrome.storage.local.get('controlState')).controlState.enrollment?.installationId);

  build(false);
  let { popup, worker } = await launch();
  const initialVersion = await admin('policies', { domainRules: { allow: [], block: ['old-browser.example.test'] } });
  const { grant: oldGrant } = await admin('enrollment-grants', {});
  await popup.getByLabel('Enrollment grant').fill(oldGrant);
  await popup.getByRole('button', { name: 'Enroll this browser', exact: true }).click();
  await label(popup, `Connected to Control · MONITOR v${initialVersion.version}`).waitFor();
  await label(popup, 'Active domain rules: 1').waitFor();
  const oldId = await installation(worker);
  await browser.close();
  const enrollmentSeen = (await admin('installations')).find((row) => row.installationId === oldId).lastSeenAt;

  build(true);
  const manifest = JSON.parse(await readFile(join(extension, 'manifest.json'), 'utf8'));
  assert.deepEqual(manifest.host_permissions, [browserOrigin + '/*']);
  assert.ok(manifest.content_scripts.every(({ matches }) => matches.every((pattern) => pattern.startsWith('https://'))));
  ({ popup, worker } = await launch(true));
  await label(popup, browserOrigin).waitFor();
  await label(popup, 'Control changed. Enroll with a new grant from this destination.').waitFor();
  assert.equal(await installation(worker), undefined);
  assert.equal(await worker.evaluate(() => chrome.declarativeNetRequest.getDynamicRules().then((rules) => rules.length)), 0);
  const dashboard = await browser.newPage();
  await dashboard.goto(dashboardOrigin);
  await dashboard.getByLabel('Control token', { exact: true }).fill(owner);
  await dashboard.getByRole('button', { name: 'Sign in', exact: true }).click();
  await dashboard.getByRole('heading', { name: 'Security overview', exact: true }).waitFor();
  await dashboard.getByText('Hosted pilot', { exact: true }).waitFor();
  const cookies = await browser.cookies(dashboardOrigin);
  const session = cookies.find(({ name }) => name === '__Host-zekvar_control_session');
  assert.ok(session?.secure && session.httpOnly && session.path === '/' && session.sameSite === 'Strict');
  assert.equal((await browser.cookies(browserOrigin)).some(({ name }) => name === session.name), false);
  assert.equal(await dashboard.evaluate(async () => (await fetch('/')).headers.get('cache-control')), 'no-store');

  const group = await admin('policy-groups', { name: 'Hosted enrollment pilot' });
  const groupPath = `policy-groups/${group.id}/policies`;
  const firstGroupPolicy = await admin(groupPath, { mode: 'block' });
  await dashboard.goto(`${dashboardOrigin}/groups?group=${group.id}`);
  const enrollmentLink = await dashboard.getByRole('link', { name: 'Enroll browsers in group', exact: true }).getAttribute('href');
  const scriptPattern = '**/_next/static/**/*.js';
  const delayScripts = Promise.withResolvers();
  await dashboard.route(scriptPattern, async (route) => { await delayScripts.promise; await route.continue(); });
  const createBatch = dashboard.getByRole('button', { name: 'Create enrollment batch', exact: true });
  try {
    await dashboard.goto(new URL(enrollmentLink, dashboardOrigin).href, { waitUntil: 'commit' });
    await createBatch.waitFor();
    assert.ok(await createBatch.isDisabled());
  } finally { delayScripts.resolve(); }
  await dashboard.getByLabel('Grant count', { exact: true }).fill('2');
  assert.equal(await dashboard.getByLabel('Rollout group', { exact: true }).inputValue(), group.id);
  await createBatch.click();
  await dashboard.unroute(scriptPattern);
  const codeField = dashboard.getByLabel('Enrollment grant codes', { exact: true });
  await codeField.waitFor();
  const grants = (await codeField.inputValue()).split('\n');
  assert.equal(grants.length, 2);
  const [grant, unusedGrant] = grants;
  assert.equal((await call(browserOrigin + '/v1/enroll', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant }) })).status, 401);
  await dashboard.getByRole('button', { name: 'Hide grant codes', exact: true }).click();
  await codeField.waitFor({ state: 'detached' });
  await dashboard.reload();
  assert.equal(await codeField.count(), 0);
  const chromePolicy = await browser.newPage();
  await chromePolicy.goto('chrome://policy/test');
  const row = chromePolicy.locator('policy-test-row').first();
  const extensionId = new URL(worker.url()).hostname;
  async function managedSetting(field, value) {
    await row.locator('select.namespace').selectOption(extensionId);
    await row.locator('input.name').fill(field);
    await row.locator('input.value').fill(value);
    await row.locator('select.preset').selectOption({ label: 'Local machine' });
    await chromePolicy.getByRole('button', { name: 'Apply policies', exact: true }).click();
  }
  await managedSetting('EnrollmentGrant', grant);
  await label(popup, 'Chrome policy must specify this build’s Control origin before it can enroll.').waitFor();
  assert.equal((await admin('installations')).length, 1);
  // Set both managed properties in one Chrome policy batch, as a device manager would.
  await chromePolicy.locator('#add-policy-btn').click();
  const originRow = chromePolicy.locator('policy-test-row').nth(1);
  await originRow.locator('select.namespace').selectOption(extensionId);
  await originRow.locator('input.name').fill('ControlOrigin');
  await originRow.locator('input.value').fill(dashboardOrigin);
  await originRow.locator('select.preset').selectOption({ label: 'Local machine' });
  const applyPolicy = chromePolicy.getByRole('button', { name: 'Apply policies', exact: true });
  await applyPolicy.click();
  await until(() => worker.evaluate(async (wrong) => (await chrome.storage.managed.get('ControlOrigin')).ControlOrigin === wrong, dashboardOrigin),
    'Chrome did not expose the mismatched origin.');
  assert.equal((await admin('installations')).length, 1);
  await originRow.locator('input.value').fill(browserOrigin);
  await applyPolicy.click();
  await label(popup, 'Enrolled by Chrome policy.').waitFor();
  await label(popup, `Connected to Control · BLOCK v${firstGroupPolicy.version}`).waitFor();
  const newId = await installation(worker);
  assert.ok(newId && newId !== oldId);
  const installations = await admin('installations');
  assert.equal(installations.find((row) => row.installationId === oldId).lastSeenAt, enrollmentSeen);
  assert.equal(installations.find((row) => row.installationId === newId).policyGroupId, group.id);
  assert.equal((await call(browserOrigin + '/v1/enroll', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant }) })).status, 401);
  await chromePolicy.close();

  await dashboard.getByRole('button', { name: 'Refresh enrollment batches' }).click();
  const batchRow = dashboard.getByRole('table', { name: 'Recent batches' }).getByRole('row').filter({ hasText: group.name });
  await batchRow.getByText('1 of 2', { exact: true }).waitFor();
  dashboard.once('dialog', (dialog) => dialog.accept());
  await batchRow.getByRole('button', { name: /^Cancel unused grants for / }).click();
  await batchRow.getByText('Cancelled', { exact: true }).waitFor();
  assert.equal((await call(browserOrigin + '/v1/enroll', { method: 'POST', headers: {
    'Content-Type': 'application/json', 'X-Zekvar-Scoped-Enrollment': '1',
  }, body: JSON.stringify({ grant: unusedGrant }) })).status, 401);
  const cleanPage = await dashboard.content();
  assert.ok(grants.every((value) => !cleanPage.includes(value)));
  if (artifacts) await dashboard.locator('section').filter({ has: dashboard.getByRole('heading', { name: 'Recent batches', exact: true }) })
    .screenshot({ path: join(artifacts, '33-enrollment-batch.png') });

  await dashboard.goto(`${dashboardOrigin}/groups?group=${group.id}`);
  await dashboard.getByLabel('Test marker', { exact: true }).selectOption('block');
  await dashboard.getByRole('button', { name: 'Publish group policy', exact: true }).click();
  const version = firstGroupPolicy.version + 1;
  await dashboard.getByText(`Version ${version} published in block mode.`, { exact: true }).waitFor();
  await popup.getByRole('button', { name: 'Sync now', exact: true }).click();
  await label(popup, `Connected to Control · BLOCK v${version}`).waitFor();
  const { version: extensionVersion } = JSON.parse(await readFile(join(extension, 'manifest.json'), 'utf8'));
  assert.equal((await admin('installations')).find(({ installationId }) => installationId === newId).extensionVersion, extensionVersion);
  await dashboard.goto(dashboardOrigin);
  await dashboard.getByRole('table', { name: 'Browser health', exact: true }).getByRole('row')
    .filter({ hasText: newId.slice(0, 13) }).getByText(extensionVersion, { exact: true }).waitFor();
  const chat = await browser.newPage();
  await chat.route('https://chatgpt.com/**', (route) => route.fulfill({ contentType: 'text/html', body: fixture }));
  await chat.goto('https://chatgpt.com/');
  await chat.getByText(new RegExp(`^Zekvar · BLOCK v${version}`)).waitFor();
  await chat.getByPlaceholder('Ask ChatGPT', { exact: true }).fill('Synthetic pilot draft ZEKVAR_TEST_SECRET');
  await chat.getByRole('button', { name: 'Send message', exact: true }).click();
  await chat.getByRole('alert').filter({ hasText: 'Submission blocked' }).waitFor();
  assert.equal(await chat.locator('#fixture-sends').textContent(), '0');
  await until(async () => (await admin('events')).find(({ installationId, decision }) => installationId === newId && decision === 'block'),
    'The hosted browser did not report a decision.');
  await dashboard.reload();
  await dashboard.getByRole('table', { name: 'Security events', exact: true }).getByText('ChatGPT', { exact: true }).waitFor();
  if (artifacts) await dashboard.screenshot({ path: join(artifacts, '27-hosted-control.png'), fullPage: true });
  const exported = await dashboard.evaluate(async () => {
    const response = await fetch('/events/export');
    return { status: response.status, body: await response.text() };
  });
  assert.equal(exported.status, 200);
  assert.doesNotMatch(exported.body, /Synthetic pilot draft|ZEKVAR_TEST_SECRET/);

  const claudePolicy = await admin(groupPath, { claudePromptEnabled: true });
  await popup.getByRole('button', { name: 'Sync now', exact: true }).click();
  await label(popup, `Connected to Control · BLOCK v${claudePolicy.version}`).waitFor();
  const claude = await browser.newPage();
  const claudeFixture = await readFile(new URL('./claude-composer.html', import.meta.url), 'utf8');
  await claude.route('https://claude.ai/**', (route) => route.fulfill({ contentType: 'text/html', body: claudeFixture }));
  await claude.goto('https://claude.ai/new');
  await claude.getByText(new RegExp(`^Zekvar · BLOCK v${claudePolicy.version}`)).waitFor();
  await claude.getByRole('textbox', { name: 'Fixture prompt' }).fill('Synthetic TLS Claude draft ZEKVAR_TEST_SECRET');
  await claude.locator('#composer button').click();
  await claude.getByRole('alert').filter({ hasText: 'Submission blocked' }).waitFor();
  assert.equal(await claude.locator('#submitted').textContent(), '0');
  await until(async () => (await admin('events?appId=claude')).find(({ installationId }) => installationId === newId),
    'The managed Chrome profile did not report its Claude decision through HTTPS.');
  await dashboard.reload();
  await dashboard.getByRole('table', { name: 'Security events' }).getByText('Claude', { exact: true }).waitFor();
  await dashboard.getByRole('link', { name: 'Reports', exact: true }).click();
  const reportApps = dashboard.getByRole('table', { name: 'By AI application', exact: true });
  await reportApps.getByRole('rowheader', { name: 'Claude', exact: true }).waitFor();
  assert.equal(await reportApps.locator('tbody tr').count(), 2);
  const reportLink = dashboard.getByRole('link', { name: 'Export report (JSON)', exact: true });
  const href = await reportLink.getAttribute('href');
  const report = await dashboard.evaluate(async (path) => {
    const response = await fetch(path);
    return { status: response.status, report: await response.json() };
  }, href);
  assert.equal(report.status, 200);
  assert.equal(report.report.counts.block, 2);
  assert.deepEqual(report.report.byApp.map(({ id }) => id), ['chatgpt', 'claude']);
  assert.doesNotMatch(JSON.stringify(report.report), /Synthetic (?:pilot|TLS Claude) draft|ZEKVAR_TEST_SECRET|installationId|eventId/);
  await dashboard.getByRole('button', { name: 'Sign out', exact: true }).click();
  await dashboard.getByRole('heading', { name: 'Sign in to Control', exact: true }).waitFor();
  assert.equal((await browser.cookies(dashboardOrigin)).some(({ name }) => name === session.name), false);
  assert.equal(await dashboard.evaluate(async () => (await fetch('/events/export')).status), 401);
  assert.equal(await dashboard.evaluate(async () => (await fetch('/reports/export')).status), 401);
});
