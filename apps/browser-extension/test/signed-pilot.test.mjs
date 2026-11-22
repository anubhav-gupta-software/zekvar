import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { once } from 'node:events';
import { lstat, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { request } from 'node:http';
import { createServer } from 'node:https';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { promisify } from 'node:util';
import { chromium } from 'playwright';

const run = promisify(execFile);
const load = async (file) => JSON.parse(await readFile(file, 'utf8'));
const { ZEKVAR_SIGNED_PILOT_ARTIFACTS: releases, ZEKVAR_SIGNED_PILOT_API: api,
  ZEKVAR_DEMO_TOKEN: owner, ZEKVAR_SIGNED_PILOT_CHROME: executablePath = '/usr/bin/chromium',
  ZEKVAR_SIGNED_PILOT_SCREENSHOT: screenshot } = process.env;

async function until(check, message, timeout = 30_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const answer = await check();
    if (answer) return answer;
    await delay(200);
  }
  assert.fail(typeof message === 'function' ? message() : message);
}

test('a Linux-managed Chromium profile installs, updates, and removes signed Zekvar Browser', { timeout: 180_000 }, async (t) => {
  assert.equal(process.platform, 'linux', 'Run in a disposable Linux VM.');
  assert.ok(releases, 'Set ZEKVAR_SIGNED_PILOT_ARTIFACTS to the package test output.');
  assert.match(api ?? '', /^http:\/\/127\.0\.0\.1:\d+$/);
  assert.match(owner ?? '', /^[a-f0-9]{64}$/);
  const work = await mkdtemp(join(tmpdir(), 'zekvar-signed-browser-'));
  const policyFile = '/etc/chromium/policies/managed/99-zekvar-signed-fixture.json';
  let installedPolicy = false;
  let browser;
  let edge;
  t.after(async () => {
    try {
      await browser?.close();
      if (edge?.listening) await new Promise((resolve) => edge.close(resolve));
    } finally {
      if (installedPolicy) await run('sudo', ['-n', 'rm', policyFile]);
      await rm(work, { recursive: true, force: true });
    }
  });
  await assert.rejects(lstat(policyFile), { code: 'ENOENT' });

  async function release(name) {
    const root = join(releases, name);
    const metadata = await load(join(root, 'release.json'));
    const update = new URL(metadata.updateUrl);
    const packageUrl = new URL(metadata.packageUrl);
    const xml = await readFile(join(root, 'public', update.pathname));
    const crx = await readFile(join(root, 'public', packageUrl.pathname));
    return { ...metadata, update, packageUrl, xml, crx };
  }
  const first = await release('first');
  const next = await release('next');
  const wrongSigner = await release('wrong-signer');
  const { extensionId } = first;
  const control = new URL(first.controlOrigin);
  const policy = await load(join(releases, 'first/chrome-policy.json'));
  const certPath = join(work, 'site.pem');
  const keyPath = join(work, 'site.key');
  await run('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=Zekvar disposable pilot fixture',
    '-addext', `subjectAltName=DNS:${control.hostname},DNS:${first.update.hostname}`, '-out', certPath, '-keyout', keyPath]);
  const cert = await readFile(certPath);
  const pin = createHash('sha256').update(new X509Certificate(cert).publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
  let manifest = first;
  let replacement = next.crx;
  const downloads = [];
  const updateEndpoints = [];
  const enrollmentRequests = [];
  edge = createServer({ cert, key: await readFile(keyPath) }, (req, res) => {
    const path = new URL(req.url, first.updateUrl).pathname;
    if (req.headers.host === first.update.host && req.method === 'GET') {
      updateEndpoints.push({ path, hasCookie: Boolean(req.headers.cookie), hasAuthorization: Boolean(req.headers.authorization) });
      if (path === first.update.pathname) {
        res.writeHead(200, { 'Content-Type': 'application/xml', 'Cache-Control': 'no-store' }).end(manifest.xml);
        return;
      }
      if (path === first.packageUrl.pathname || path === next.packageUrl.pathname) {
        downloads.push(path);
        res.writeHead(200, { 'Content-Type': 'application/x-chrome-extension', 'Cache-Control': 'no-store' })
          .end(path === first.packageUrl.pathname ? first.crx : replacement);
        return;
      }
    }
    if (req.headers.host === control.host && (path === '/v1/enroll' || path.startsWith('/v1/browser/'))) {
      if (path === '/v1/enroll') enrollmentRequests.push(1);
      const upstream = request(new URL(req.url, api), { method: req.method, headers: req.headers }, (response) => {
        res.writeHead(response.statusCode, response.headers);
        response.pipe(res);
      });
      upstream.on('error', () => res.writeHead(502).end());
      req.pipe(upstream);
      return;
    }
    res.writeHead(404).end();
  });
  edge.listen(Number(first.update.port), '127.0.0.1');
  await once(edge, 'listening');

  async function admin(route, body, expected = 200) {
    const response = await fetch(`${api}/v1/admin/${route}`, {
      method: body === undefined ? 'GET' : 'POST', signal: AbortSignal.timeout(5000),
      headers: { Authorization: `Bearer ${owner}`, ...(body !== undefined && { 'Content-Type': 'application/json' }) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    assert.equal(response.status, expected, route);
    return expected === 204 ? undefined : response.json();
  }
  async function deployPolicy() {
    const local = join(work, 'policy.json');
    await writeFile(local, JSON.stringify(policy), { mode: 0o600 });
    await run('sudo', ['-n', 'install', '-d', '-m', '0755', dirname(policyFile)]);
    await run('sudo', ['-n', 'install', '-m', '0640', '-g', String(process.getgid()), local, policyFile]);
    installedPolicy = true;
  }
  const existingInstallations = new Set((await admin('installations')).map(({ installationId }) => installationId));
  const blockPolicy = await admin('policies', { mode: 'block' });
  const extensionSettings = policy['3rdparty'].extensions[extensionId];
  extensionSettings.EnrollmentGrant = (await admin('enrollment-grants', {})).grant;
  await deployPolicy();

  const profile = join(work, 'profile');
  async function launch() {
    browser = await chromium.launchPersistentContext(profile, {
      executablePath, headless: process.env.ZEKVAR_DEMO_HEADED !== '1',
      ignoreDefaultArgs: ['--disable-extensions', '--disable-background-networking'],
      args: ['--no-proxy-server', `--ignore-certificate-errors-spki-list=${pin}`,
        `--host-resolver-rules=MAP ${control.hostname} 127.0.0.1, MAP ${first.update.hostname} 127.0.0.1, MAP * ~NOTFOUND`],
    });
    browser.setDefaultTimeout(10_000);
  }
  await launch();
  async function openExtensions() {
    const page = await browser.newPage();
    await page.goto('chrome://extensions');
    return page;
  }
  let extensions = await openExtensions();
  const extensionInfo = (page = extensions) => page.evaluate(async (id) =>
    (await chrome.developerPrivate.getExtensionsInfo({ includeDisabled: true, includeTerminated: true })).find((item) => item.id === id), extensionId);
  const installed = await until(() => extensionInfo(),
    () => `Managed Chromium did not install the signed CRX. Update requests ${JSON.stringify(updateEndpoints)}.`, 55_000);
  assert.equal(installed.version, first.version);
  assert.equal(installed.userMayModify, false);
  const browserInstallations = async () => (await admin('installations')).filter(({ installationId }) => !existingInstallations.has(installationId));
  const before = await until(async () => (await browserInstallations()).find((row) =>
    row.appliedPolicyVersion === blockPolicy.version && row.extensionVersion === first.version),
  'The force-installed browser did not report its extension release and apply its Control policy.');

  async function enforce(useKeyboard) {
    const chat = await browser.newPage();
    const fixture = await readFile(new URL('./guest-chatgpt-composer.html', import.meta.url), 'utf8');
    await chat.route('https://chatgpt.com/**', (route) => route.fulfill({ contentType: 'text/html', body: fixture }));
    await chat.goto('https://chatgpt.com/');
    const coverage = chat.getByText(new RegExp(`^Zekvar · BLOCK v${blockPolicy.version}(?:\\D|$)`));
    await until(async () => {
      if (await coverage.waitFor({ timeout: 1500 }).then(() => true, () => false)) return true;
      await chat.reload();
    }, 'The loaded composer did not show the active Zekvar policy.', 15_000);
    await chat.getByPlaceholder('Ask ChatGPT').fill('Synthetic update draft ZEKVAR_TEST_SECRET');
    if (useKeyboard) await chat.getByPlaceholder('Ask ChatGPT').press('Enter');
    else await chat.getByRole('button', { name: 'Send message', exact: true }).click();
    await chat.getByRole('alert').filter({ hasText: 'Submission blocked' }).waitFor();
    assert.equal(await chat.locator('#fixture-sends').textContent(), '0');
    if (screenshot && useKeyboard) await chat.screenshot({ path: screenshot, fullPage: true });
    await chat.getByPlaceholder('Ask ChatGPT').fill('Clean synthetic pilot draft');
    await chat.getByRole('button', { name: 'Send message', exact: true }).click();
    await chat.locator('#fixture-sends').filter({ hasText: /^1$/ }).waitFor();
    await chat.close();
  }
  await enforce(false);
  assert.equal(enrollmentRequests.length, 1);
  delete extensionSettings.EnrollmentGrant;
  await deployPolicy();

  await extensions.locator('extensions-item').getByText('Zekvar Browser', { exact: true }).waitFor();
  async function requestUpdate() {
    const devMode = extensions.locator('extensions-toolbar #devMode');
    const updateNow = extensions.locator('extensions-toolbar #updateNow');
    if (!await updateNow.isVisible()) await devMode.click();
    await updateNow.click();
  }
  async function checkUpdate() {
    const attempted = downloads.length;
    await requestUpdate();
    await until(() => downloads.slice(attempted).includes(next.packageUrl.pathname), 'Chromium did not fetch the advertised update.');
  }
  manifest = next;
  replacement = wrongSigner.crx;
  await checkUpdate();
  await delay(1_200);
  assert.equal((await extensionInfo())?.version, first.version, 'Chromium accepted an update signed with the wrong key');
  replacement = next.crx;
  await checkUpdate();
  const upgraded = await until(async () => {
    const info = await extensionInfo();
    return info?.version === next.version && info;
  }, 'Chromium did not activate the signed update.');
  assert.equal(upgraded.id, extensionId);
  assert.equal(upgraded.userMayModify, false);
  const reportedRelease = async () => (await browserInstallations()).find((row) => row.extensionVersion === next.version);
  let released;
  for (let attempt = 0; attempt < 20 && !released; attempt++) {
    released = await reportedRelease();
    if (!released) await delay(200);
  }
  if (!released) {
    t.diagnostic('Chromium displayed the upgraded package before its worker reported the release. Relaunching the same managed profile.');
    await browser.close();
    await launch();
    extensions = await openExtensions();
    assert.equal((await extensionInfo())?.version, next.version);
    released = await until(reportedRelease, 'Control did not observe the new extension release after relaunch.');
  }
  assert.equal(released.installationId, before.installationId);
  assert.ok(Date.parse(released.extensionVersionReportedAt) > Date.parse(before.extensionVersionReportedAt));
  await enforce(true);
  assert.equal(enrollmentRequests.length, 1);
  assert.deepEqual((await browserInstallations()).map(({ installationId }) => installationId), [before.installationId]);
  const events = await until(async () => {
    const rows = (await admin('events')).filter((row) => row.installationId === before.installationId && row.decision === 'block');
    return rows.length === 2 && rows;
  }, 'Control did not receive decisions from both signed versions.');
  assert.doesNotMatch(JSON.stringify(events), /Synthetic update draft|ZEKVAR_TEST_SECRET/);
  assert.ok(updateEndpoints.every(({ hasCookie, hasAuthorization }) => !hasCookie && !hasAuthorization));

  const previousRequests = downloads.length;
  const previousChecks = updateEndpoints.length;
  manifest = first;
  await requestUpdate();
  await until(() => updateEndpoints.slice(previousChecks).some(({ path }) => path === first.update.pathname),
    'Chromium did not check the channel advertising the older version.');
  await delay(1_200);
  assert.equal(downloads.length, previousRequests, 'Chromium downloaded a lower version');
  assert.equal((await extensionInfo())?.version, next.version);
  policy.ExtensionSettings[extensionId] = { installation_mode: 'removed' };
  await deployPolicy();
  await browser.close();
  await launch();
  const page = await browser.newPage();
  await page.goto('chrome://extensions');
  await page.locator('extensions-item').getByText('Zekvar Browser', { exact: true }).waitFor({ state: 'detached' });
  assert.equal(await extensionInfo(page), undefined);
  await admin(`installations/${before.installationId}/revoke`, {}, 204);
  const deployments = await admin('installations');
  assert.ok(deployments.find(({ installationId }) => installationId === before.installationId).revokedAt);
});
