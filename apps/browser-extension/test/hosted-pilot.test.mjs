import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { once } from 'node:events';
import { officeFile, textXml } from './office-fixture.mjs';
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

test('the TLS pilot keeps administration private and enrolls Chrome on its configured origin', { timeout: 120_000 }, async (t) => {
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
      '/v1/admin/enrollment-batches', '/v1/admin/reports/ai-enforcement', '/v1/admin/events/triage-assignees']) {
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

  async function admin(path, body, expected = 200) {
    const response = await fetch(`http://127.0.0.1:${apiPort}/v1/admin/${path}`, {
      method: body ? 'POST' : 'GET',
      headers: { Authorization: `Bearer ${owner}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body && JSON.stringify(body), signal: AbortSignal.timeout(5000),
    });
    assert.equal(response.status, expected, 'Private Control operation failed');
    return response.status === 204 ? undefined : response.json();
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
  const detected = await until(async () => (await admin(`events?rolloutGroup=${group.id}`)).find(({ installationId, decision }) =>
    installationId === newId && decision === 'block'),
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

  const claudePolicy = await admin(groupPath, { claudePromptEnabled: true, privateKeyMode: 'block', fileInspection: { chatgpt: true } });
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
  const keyBlock = ['-----BEGIN ENCRYPTED PRIVATE KEY-----', 'WnJB'.repeat(16), '-----END ENCRYPTED PRIVATE KEY-----'].join('\\n');
  await claude.getByRole('textbox', { name: 'Fixture prompt' }).fill(`fixture ${keyBlock}`);
  await claude.locator('#composer button').click();
  await claude.getByRole('alert').filter({ hasText: 'looks like a private key' }).waitFor();
  assert.equal(await claude.locator('#submitted').textContent(), '0');
  await until(async () => (await admin('events?appId=claude')).find(({ installationId, ruleId }) => installationId === newId && ruleId === 'pem-private-key'),
    'The managed Chrome profile did not report the private key decision through HTTPS.');
  await until(async () => {
    const health = await admin(`browser-health?rolloutGroup=${group.id}&browserVersion=${extensionVersion}`);
    return health.composerReadiness.activeInstallations === 1 &&
      health.composerReadiness.apps.find(({ appId }) => appId === 'claude').counts.detected === 1;
  }, 'The managed Chrome profile did not report fresh Claude readiness through HTTPS.');

  const attachment = await browser.newPage();
  const attachmentFixture = await readFile(new URL('./upload-composer.html', import.meta.url), 'utf8');
  await attachment.route('https://chatgpt.com/**', (route) => route.fulfill({ contentType: 'text/html', body: attachmentFixture }));
  await attachment.goto('https://chatgpt.com/');
  await attachment.getByText(/File content monitor$/).waitFor();
  const attachmentName = join(scratch, 'private-hosted-content-sample.docx');
  const documentBody = keyBlock.split('\n').map((line) => `<w:p><w:r><w:t>${line}</w:t></w:r></w:p>`).join('');
  await writeFile(attachmentName, officeFile('docx', [['word/document.xml', textXml.word(documentBody)]]));
  const chooser = attachment.waitForEvent('filechooser');
  await attachment.getByLabel('Attach fixture files').click();
  await (await chooser).setFiles(attachmentName);
  assert.deepEqual(await attachment.evaluate(() => window.fileEvents), [['input', 1], ['change', 1]]);
  await until(async () => (await admin('events?appId=chatgpt')).some(({ ruleId, uploadMethod, decision }) =>
    ruleId === 'pem-private-key' && uploadMethod === 'picker' && decision === 'monitor'), 'The private key file observation did not appear in Control.');
  await dashboard.reload();
  await dashboard.getByRole('table', { name: 'Security events' }).getByRole('row').filter({ hasText: 'Private key' })
    .getByText('Claude', { exact: true }).waitFor();
  await dashboard.getByRole('table', { name: 'Security events' }).getByText('File content · File picker', { exact: true }).waitFor();
  await dashboard.getByRole('link', { name: 'Reports', exact: true }).click();
  const reportApps = dashboard.getByRole('table', { name: 'By AI application', exact: true });
  await reportApps.getByRole('rowheader', { name: 'Claude', exact: true }).waitFor();
  assert.equal(await reportApps.locator('tbody tr').count(), 2);
  const contentActivity = dashboard.getByRole('table', { name: 'By activity', exact: true }).getByRole('row', { name: /^File content inspection / });
  assert.deepEqual(await contentActivity.getByRole('cell').allTextContents(), ['1', '0', '0', '0', '0', '1']);
  const reportLink = dashboard.getByRole('link', { name: 'Export report (JSON)', exact: true });
  const href = await reportLink.getAttribute('href');
  const report = await dashboard.evaluate(async (path) => {
    const response = await fetch(path);
    return { status: response.status, report: await response.json() };
  }, href);
  assert.equal(report.status, 200);
  assert.equal(report.report.counts.block, 3);
  assert.equal(report.report.byRule.find(({ id }) => id === 'pem-private-key').counts.block, 1);
  assert.equal(report.report.bySource.find(({ id }) => id === 'file_content').counts.monitor, 1);
  assert.deepEqual(report.report.byApp.map(({ id }) => id), ['chatgpt', 'claude']);
  assert.doesNotMatch(JSON.stringify(report.report), /Synthetic (?:pilot|TLS Claude) draft|ZEKVAR_TEST_SECRET|installationId|eventId|BEGIN ENCRYPTED|WnJBWnJB|private-hosted-content/);

  await admin(`installations/${newId}/policy-group`, { groupId: null }, 204);
  await popup.getByRole('button', { name: 'Sync now', exact: true }).click();
  await label(popup, `Connected to Control · MONITOR v${initialVersion.version}`).waitFor();
  await chat.getByText(new RegExp(`^Zekvar · MONITOR v${initialVersion.version}`)).waitFor();
  await chat.getByPlaceholder('Ask ChatGPT', { exact: true }).fill('Synthetic baseline draft ZEKVAR_TEST_SECRET');
  await chat.getByRole('button', { name: 'Send message', exact: true }).click();
  await until(async () => (await admin('events?rolloutGroup=baseline&appId=chatgpt'))
    .some(({ installationId, decision }) => installationId === newId && decision === 'monitor'),
  'The moved browser did not report a baseline decision.');
  assert.equal(await chat.locator('#fixture-sends').textContent(), '1');
  await dashboard.goto(`${dashboardOrigin}/?rolloutGroup=baseline#events`);
  const policyEvents = dashboard.getByRole('table', { name: 'Security events', exact: true });
  await policyEvents.getByRole('link', { name: group.name, exact: true }).first().click();
  await dashboard.waitForURL((url) => url.searchParams.get('eventGroup') === group.id && url.searchParams.get('rolloutGroup') === 'baseline');
  assert.equal(await policyEvents.locator('tbody tr').count(), 4);
  assert.equal(await policyEvents.getByRole('link', { name: 'Organization baseline', exact: true }).count(), 0);
  const downloadPath = await dashboard.getByRole('link', { name: 'Export security events (JSON)', exact: true }).getAttribute('href');
  const scoped = await dashboard.evaluate(async (path) => (await fetch(path)).json(), downloadPath);
  assert.equal(scoped.filters.rolloutGroup, group.id);
  assert.equal(scoped.entries.length, 4);
  assert.ok(scoped.entries.every(({ rollout }) => rollout.kind === 'group' && rollout.groupId === group.id && rollout.groupName === group.name));
  if (artifacts) await dashboard.locator('#events').screenshot({ path: join(artifacts, '34-recorded-rollout.png') });

  await dashboard.getByRole('link', { name: 'Reports', exact: true }).click();
  await dashboard.getByLabel('Recorded rollout group', { exact: true }).selectOption(group.id);
  await dashboard.getByRole('button', { name: 'Apply report filters', exact: true }).click();
  await dashboard.waitForURL((url) => url.searchParams.get('rolloutGroup') === group.id);
  const scopedHref = await reportLink.getAttribute('href');
  const scopedReport = await dashboard.evaluate(async (path) => (await fetch(path)).json(), scopedHref);
  assert.equal(scopedReport.rolloutGroup, group.id);
  assert.deepEqual(scopedReport.counts, report.report.counts);
  await dashboard.getByRole('link', { name: 'Investigate security events', exact: true }).click();
  await dashboard.waitForURL((url) => url.searchParams.get('eventGroup') === group.id);
  assert.equal(await policyEvents.locator('tbody tr').count(), 4);
  await t.test('an owner, investigator, and auditor triage a real browser detection through the hosted dashboard', async () => {
    const reviewPath = `/events/${detected.installationId}/${detected.eventId}`;
    const investigator = await admin('access', { name: 'Hosted investigator', role: 'administrator', hours: 1 });
    const auditor = await admin('access', { name: 'Hosted auditor', role: 'auditor', hours: 1 });
    const triage = dashboard.getByRole('region', { name: 'Triage', exact: true });
    const activity = dashboard.getByRole('table', { name: 'Triage activity', exact: true });
    const save = triage.getByRole('button', { name: 'Save triage', exact: true });
    const status = triage.getByLabel('Status', { exact: true });
    const saved = () => triage.getByRole('status').getByText('Event triage saved.', { exact: true }).waitFor();
    async function signInAs(token) {
      await dashboard.getByRole('button', { name: 'Sign out', exact: true }).click();
      await dashboard.getByLabel('Control token').fill(token);
      await dashboard.getByRole('button', { name: 'Sign in', exact: true }).click();
      await dashboard.getByRole('heading', { name: 'Security overview', exact: true }).waitFor();
    }
    await dashboard.locator(`a[href^="${reviewPath}?"]`).click();
    await dashboard.waitForURL((url) => url.pathname === reviewPath);
    await dashboard.getByRole('region', { name: 'Detection details' }).getByText('ChatGPT', { exact: true }).waitFor();
    assert.equal(await status.inputValue(), 'needs_review');
    await status.selectOption('investigating');
    await triage.getByLabel('Assignee', { exact: true }).selectOption(investigator.access.id);
    await save.click();
    await saved();
    await activity.getByText('Organization admin', { exact: true }).waitFor();
    await dashboard.getByRole('link', { name: 'Back to security events', exact: true }).click();
    await dashboard.waitForURL((url) => url.searchParams.get('eventGroup') === group.id);
    await dashboard.getByLabel('Triage status', { exact: true }).selectOption('investigating');
    await dashboard.getByLabel('Triage assignee', { exact: true }).selectOption(investigator.access.id);
    await dashboard.locator('#events').getByRole('button', { name: 'Apply filters', exact: true }).click();
    await dashboard.waitForURL((url) => url.searchParams.get('triageAssignee') === investigator.access.id);
    assert.equal(await policyEvents.locator('tbody tr').count(), 1);
    const filteredExport = await dashboard.getByRole('link', { name: 'Export security events (JSON)', exact: true }).getAttribute('href');
    const report = await dashboard.evaluate(async (path) => (await fetch(path)).json(), filteredExport);
    assert.equal(report.filters.triageStatus, 'investigating');
    assert.equal(report.entries.length, 1);
    assert.equal(report.entries[0].eventId, detected.eventId);
    assert.doesNotMatch(JSON.stringify(report), /Synthetic pilot draft|ZEKVAR_TEST_SECRET/);
    for (const query of ['triageStatus=investigating&triageStatus=resolved', 'triageAssignee=someone']) {
      assert.equal(await dashboard.evaluate(async (value) => (await fetch(`/events/export?${value}`)).status, query), 400);
    }
    await signInAs(investigator.token);
    assert.match(await dashboard.getByLabel('Triage assignee', { exact: true }).locator(`option[value="${investigator.access.id}"]`).textContent(),
      /Assigned to me/);
    await dashboard.goto(dashboardOrigin + reviewPath);
    await status.selectOption('resolved');
    const resolution = triage.getByLabel('Resolution', { exact: true });
    await resolution.waitFor();
    await save.click();
    assert.equal(await resolution.evaluate((element) => element.validity.valueMissing), true);
    await resolution.selectOption('confirmed_violation');
    await admin(`events/${detected.installationId}/${detected.eventId}/triage`,
      { expectedRevision: 1, status: 'needs_review', disposition: null, assigneeId: investigator.access.id });
    await save.click();
    await triage.getByRole('alert').getByText(/Someone updated this event/).waitFor();
    assert.equal(await resolution.inputValue(), 'confirmed_violation');
    await dashboard.reload();
    assert.equal(await status.inputValue(), 'needs_review');
    await status.selectOption('resolved');
    await resolution.selectOption('false_positive');
    await save.click();
    await saved();
    await activity.getByRole('row').filter({ hasText: 'Hosted investigator' }).getByText(/Resolved · False positive/).waitFor();
    if (artifacts) await dashboard.screenshot({ path: join(artifacts, '35-event-triage.png'), fullPage: true });
    await signInAs(auditor.token);
    await dashboard.goto(dashboardOrigin + reviewPath);
    await triage.getByText('Resolved', { exact: true }).waitFor();
    assert.equal(await save.count(), 0);
    assert.equal(await status.count(), 0);
    await dashboard.getByRole('link', { name: 'Open audit log', exact: true }).click();
    await dashboard.getByRole('heading', { name: 'Audit log', exact: true }).waitFor();
    const audit = dashboard.getByRole('table', { name: 'Control activity', exact: true });
    const finalEntry = audit.getByRole('row').filter({ hasText: 'False positive' });
    await finalEntry.getByText('Hosted investigator', { exact: true }).waitFor();
    assert.equal(await finalEntry.getByRole('link', { name: 'Review event', exact: true }).getAttribute('href'), reviewPath);
    await finalEntry.getByRole('link', { name: 'Review event', exact: true }).click();
    await dashboard.waitForURL((url) => url.pathname === reviewPath);
    await activity.getByText(/Resolved · False positive/).waitFor();
    assert.equal((await call(browserOrigin + '/v1/admin' + reviewPath, { headers: { Authorization: `Bearer ${owner}` } })).status, 404);
  });
  await t.test('enforces file content blocking in managed Chrome over the hosted policy and event endpoints', async () => {
    const fileBlock = await admin('policies', { fileContentModes: { chatgpt: 'block' } });
    await popup.getByRole('button', { name: 'Sync now', exact: true }).click();
    await attachment.getByText(/File content block$/).waitFor();
    const field = attachment.getByLabel('Attach fixture files');
    const disguisedFile = join(scratch, 'synthetic-hosted-attachment.png');
    const safeFile = join(scratch, 'synthetic-safe.txt');
    await Promise.all([writeFile(disguisedFile, 'ZEKVAR_TEST_SECRET'), writeFile(safeFile, 'Synthetic safe attachment')]);
    const rejected = attachment.waitForEvent('filechooser');
    await field.click();
    await (await rejected).setFiles(disguisedFile);
    await attachment.getByRole('alert').filter({ hasText: 'sensitive content' }).waitFor();
    assert.deepEqual(await attachment.evaluate(() => window.fileEvents), [['input', 1], ['change', 1]]);
    assert.equal(await field.evaluate((input) => input.files.length), 0);
    const row = await until(async () => (await admin('events?appId=chatgpt&decision=block')).find(({ policyVersion, uploadMethod }) =>
      policyVersion === fileBlock.version && uploadMethod === 'picker'), 'The hosted browser did not report the blocked attachment.');
    assert.equal(row.ruleId, 'fixture-secret');
    const approved = attachment.waitForEvent('filechooser');
    await field.click();
    await (await approved).setFiles(safeFile);
    await until(async () => (await attachment.evaluate(() => window.fileEvents)).length === 4, 'The hosted browser did not release the clean attachment.');
    await dashboard.goto(dashboardOrigin + `/events/${row.installationId}/${row.eventId}`);
    await dashboard.getByRole('region', { name: 'Detection details' }).getByText(/Synthetic secret · File picker/).waitFor();
    const details = await admin(`events/${row.installationId}/${row.eventId}`);
    assert.doesNotMatch(JSON.stringify(details), /synthetic-hosted-attachment|ZEKVAR_TEST_SECRET|image\/png/);
  });
  await dashboard.getByRole('button', { name: 'Sign out', exact: true }).click();
  await dashboard.getByRole('heading', { name: 'Sign in to Control', exact: true }).waitFor();
  assert.equal((await browser.cookies(dashboardOrigin)).some(({ name }) => name === session.name), false);
  assert.equal(await dashboard.evaluate(async () => (await fetch('/events/export')).status), 401);
  assert.equal(await dashboard.evaluate(async () => (await fetch('/reports/export')).status), 401);
});
