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
import { textImage } from './image-fixture.mjs';
import { pdfFixture } from './pdf-fixture.mjs';

const run = promisify(execFile);
const load = async (file) => JSON.parse(await readFile(file, 'utf8'));
const { ZEKVAR_SIGNED_PILOT_ARTIFACTS: releases, ZEKVAR_SIGNED_PILOT_API: api,
  ZEKVAR_DEMO_TOKEN: owner, ZEKVAR_SIGNED_PILOT_CHROME: executablePath = '/usr/bin/chromium',
  ZEKVAR_SIGNED_PILOT_SCREENSHOT: screenshot, ZEKVAR_SIGNED_PILOT_CLAUDE_FILES: claudeFiles,
  ZEKVAR_SIGNED_PILOT_ATTACHMENT_SCREENSHOT: attachmentScreenshot } = process.env;
const attachmentUpgrade = claudeFiles === '1';

async function until(check, message, timeout = 30_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const answer = await check();
    if (answer) return answer;
    await delay(200);
  }
  assert.fail(typeof message === 'function' ? message() : message);
}

test('a Linux-managed Chromium profile installs, updates, rolls back, and removes signed Zekvar Browser', { timeout: 240_000 }, async (t) => {
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
  const rollback = await release('rollback');
  const wrongSigner = await release('wrong-signer');
  const { extensionId } = first;
  if (attachmentUpgrade) {
    assert.equal(first.version, '0.39.0');
    assert.equal(next.version, '0.40.0');
  }
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
  let controlAvailable = true;
  let pauseEventDelivery = false;
  let withheldEvents = 0;
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
      const packages = { [first.packageUrl.pathname]: first.crx, [next.packageUrl.pathname]: replacement,
        [rollback.packageUrl.pathname]: rollback.crx };
      if (Object.hasOwn(packages, path)) {
        downloads.push(path);
        res.writeHead(200, { 'Content-Type': 'application/x-chrome-extension', 'Cache-Control': 'no-store' }).end(packages[path]);
        return;
      }
    }
    if (req.headers.host === control.host && (path === '/v1/enroll' || path.startsWith('/v1/browser/'))) {
      if (path === '/v1/enroll') enrollmentRequests.push(1);
      const sendingEvent = path === '/v1/browser/events';
      if (!controlAvailable || (pauseEventDelivery && sendingEvent)) {
        if (sendingEvent) withheldEvents++;
        res.writeHead(503).end();
        return;
      }
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
  let blockPolicy = await admin('policies', { mode: 'block', ...(attachmentUpgrade && {
    claudePromptEnabled: true, fileContentModes: { claude: 'off' }, blockedAiAppHosts: [],
  }) });
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

  async function enforce({ keyboard = false, capture = false, candidate = false } = {}) {
    const chat = await browser.newPage();
    const fixture = await readFile(new URL('./guest-chatgpt-composer.html', import.meta.url), 'utf8');
    await chat.route('https://chatgpt.com/**', (route) => route.fulfill({ contentType: 'text/html', body: fixture }));
    await chat.goto('https://chatgpt.com/');
    const coverage = chat.getByText(new RegExp(`^Zekvar · BLOCK v${blockPolicy.version}(?:\\D|$)`));
    await until(async () => {
      if (await coverage.waitFor({ timeout: 1500 }).then(() => true, () => false)) return true;
      await chat.reload();
    }, 'The loaded composer did not show the active Zekvar policy.', 15_000);
    assert.equal(await chat.locator('html').getAttribute('data-zekvar-test-release'), candidate && !attachmentUpgrade ? 'candidate' : null);
    await chat.getByPlaceholder('Ask ChatGPT').fill('Synthetic update draft ZEKVAR_TEST_SECRET');
    if (keyboard) await chat.getByPlaceholder('Ask ChatGPT').press('Enter');
    else await chat.getByRole('button', { name: 'Send message', exact: true }).click();
    await chat.getByRole('alert').filter({ hasText: 'Submission blocked' }).waitFor();
    assert.equal(await chat.locator('#fixture-sends').textContent(), '0');
    if (screenshot && capture) await chat.screenshot({ path: screenshot, fullPage: true });
    await chat.getByPlaceholder('Ask ChatGPT').fill('Clean synthetic pilot draft');
    await chat.getByRole('button', { name: 'Send message', exact: true }).click();
    await chat.locator('#fixture-sends').filter({ hasText: /^1$/ }).waitFor();
    await chat.close();
  }

  async function checkClaudeAttachment(blocked, capture = false) {
    const chat = await browser.newPage();
    const fixture = await readFile(new URL('./upload-composer.html', import.meta.url), 'utf8');
    try {
      await chat.route('https://claude.ai/**', (route) => route.fulfill({ contentType: 'text/html', body: fixture }));
      await chat.goto('https://claude.ai/new');
      const status = chat.getByText(new RegExp(`^Zekvar · BLOCK v${blockPolicy.version}(?:\\D|$)`));
      await status.waitFor({ timeout: 40_000 });
      assert.equal((await status.textContent()).includes('File content block'), blocked);
      const image = { bytes: await textImage(chat, 'image/jpeg', ['Synthetic Claude attachment', 'ZEKVAR_TEST_SECRET']),
        width: 960, height: 260 };
      const bytes = pdfFixture([{ lines: ['Public heading'], image }]);
      const file = join(work, 'synthetic-signed-claude.pdf');
      await writeFile(file, bytes);
      const field = chat.getByLabel('Attach fixture files');
      const chooser = chat.waitForEvent('filechooser');
      await field.click();
      await (await chooser).setFiles(file);
      if (blocked) {
        const notice = chat.getByRole('alert').filter({ hasText: 'sensitive content' });
        await notice.waitFor();
        assert.deepEqual(await chat.evaluate(() => window.fileEvents), []);
        assert.equal(await field.evaluate((input) => input.files.length), 0);
        if (capture && attachmentScreenshot) await chat.screenshot({ path: attachmentScreenshot, fullPage: true });
      } else await until(async () => (await chat.evaluate(() => window.fileEvents)).some(([kind]) => kind === 'change'),
        'The legacy fixture did not receive the file.');
    } finally {
      await chat.close();
    }
  }

  async function checkClaudeHostBlock() {
    const tab = await browser.newPage();
    try {
      await assert.rejects(tab.goto('https://claude.ai/new'), /ERR_BLOCKED_BY_CLIENT/);
    } finally {
      await tab.close();
    }
  }
  await enforce();
  assert.equal(enrollmentRequests.length, 1);
  delete extensionSettings.EnrollmentGrant;
  await deployPolicy();
  if (attachmentUpgrade) {
    blockPolicy = await admin('policies', { fileContentModes: { claude: 'block' } });
    await checkClaudeAttachment(false);
    assert.notEqual((await browserInstallations())[0].appliedPolicyVersion, blockPolicy.version);
  }
  const attachmentPolicyVersion = blockPolicy.version;

  async function requestUpdate() {
    const devMode = extensions.locator('extensions-toolbar #devMode');
    const updateNow = extensions.locator('extensions-toolbar #updateNow');
    if (!await updateNow.isVisible()) await devMode.click();
    await updateNow.click();
  }
  async function checkUpdate(release) {
    const attempted = downloads.length;
    await requestUpdate();
    await until(() => downloads.slice(attempted).includes(release.packageUrl.pathname), 'Chromium did not fetch the advertised update.');
  }
  manifest = next;
  replacement = wrongSigner.crx;
  await checkUpdate(next);
  await delay(1_200);
  assert.equal((await extensionInfo())?.version, first.version, 'Chromium accepted an update signed with the wrong key');
  replacement = next.crx;
  await checkUpdate(next);
  async function activeRelease(version) {
    return until(async () => {
      const info = await extensionInfo();
      return info?.version === version && info;
    }, 'Chromium did not activate the signed update.');
  }
  const upgraded = await activeRelease(next.version);
  assert.equal(upgraded.id, extensionId);
  assert.equal(upgraded.userMayModify, false);
  const reportedRelease = async (version) => (await browserInstallations()).find((row) => row.extensionVersion === version);
  async function restart(version) {
    await browser.close();
    await launch();
    extensions = await openExtensions();
    assert.equal((await extensionInfo())?.version, version);
  }
  if (!attachmentUpgrade) await restart(next.version);
  await enforce({ keyboard: true, candidate: true });
  if (attachmentUpgrade) await checkClaudeAttachment(true, true);
  const released = await until(() => reportedRelease(next.version), 'Control did not observe the new signed extension release.');
  assert.equal(released.installationId, before.installationId);
  assert.ok(Date.parse(released.extensionVersionReportedAt) > Date.parse(before.extensionVersionReportedAt));
  assert.equal(enrollmentRequests.length, 1);
  assert.deepEqual((await browserInstallations()).map(({ installationId }) => installationId), [before.installationId]);
  if (attachmentUpgrade) await until(async () => (await reportedRelease(next.version))?.appliedPolicyVersion === blockPolicy.version,
    'The signed candidate did not acknowledge Claude attachment protection.');
  const installationEvents = async () => (await admin('events')).filter(({ installationId }) => installationId === before.installationId);
  const onlineDecisions = attachmentUpgrade ? 3 : 2;
  const events = await until(async () => {
    const rows = (await installationEvents()).filter((row) => row.decision === 'block');
    return rows.length === onlineDecisions && rows;
  }, 'Control did not receive decisions from both signed versions.');
  assert.doesNotMatch(JSON.stringify(events), /Synthetic update draft|ZEKVAR_TEST_SECRET|synthetic-signed-claude|JVBERi/);

  const previousRequests = downloads.length;
  const previousChecks = updateEndpoints.length;
  manifest = first;
  await requestUpdate();
  await until(() => updateEndpoints.slice(previousChecks).some(({ path }) => path === first.update.pathname),
    'Chromium did not check the channel advertising the older version.');
  await delay(1_200);
  assert.equal(downloads.length, previousRequests, 'Chromium downloaded a lower version');
  assert.equal((await extensionInfo())?.version, next.version);

  pauseEventDelivery = true;
  await enforce({ candidate: true });
  if (attachmentUpgrade) {
    await checkClaudeAttachment(true);
    blockPolicy = await admin('policies', { blockedAiAppHosts: ['claude.ai'] });
    await until(async () => (await reportedRelease(next.version))?.appliedPolicyVersion === blockPolicy.version,
      'The signed candidate did not apply the Claude host block before rollback.', 50_000);
    await checkClaudeHostBlock();
  }
  await until(() => withheldEvents > 0, 'The candidate did not attempt to deliver the blocked decision.');
  controlAvailable = false;
  assert.equal((await installationEvents()).length, onlineDecisions);

  assert.equal(rollback.sourceVersion, first.version);
  manifest = rollback;
  const rollbackStarted = Date.now();
  await checkUpdate(rollback);
  const restored = await activeRelease(rollback.version);
  assert.equal(restored.id, extensionId);
  assert.equal(restored.userMayModify, false);
  await restart(rollback.version);
  await enforce({ keyboard: true, capture: true });
  if (attachmentUpgrade) await checkClaudeHostBlock();
  assert.equal((await installationEvents()).length, onlineDecisions);
  const reopened = Date.now();
  controlAvailable = true;
  pauseEventDelivery = false;
  const restoredReport = await until(() => reportedRelease(rollback.version), 'Control did not observe the rollback release.', 50_000);
  assert.equal(restoredReport.installationId, before.installationId);
  if (attachmentUpgrade) {
    await until(async () => {
      const row = await reportedRelease(rollback.version);
      return row && row.appliedPolicyVersion !== blockPolicy.version;
    }, 'Control kept the rolled-back release current despite its unavailable Claude file checks.');
  } else assert.equal(restoredReport.appliedPolicyVersion, blockPolicy.version);
  assert.equal(enrollmentRequests.length, 1);
  assert.deepEqual((await browserInstallations()).map(({ installationId }) => installationId), [before.installationId]);
  const recovered = await until(async () => {
    const rows = await installationEvents();
    return rows.length === (attachmentUpgrade ? 6 : 4) && rows;
  }, 'Control did not receive all decisions queued during the outage.');
  const replayed = Date.now();
  assert.ok(recovered.every(({ decision }) => decision === 'block'));
  assert.equal(new Set(recovered.map(({ eventId }) => eventId)).size, recovered.length);
  assert.doesNotMatch(JSON.stringify(recovered), /Synthetic update draft|ZEKVAR_TEST_SECRET|synthetic-signed-claude|JVBERi/);
  if (attachmentUpgrade) {
    const claude = recovered.filter(({ appId }) => appId === 'claude');
    assert.deepEqual(claude.map(({ policyVersion, uploadMethod, ruleId }) => [policyVersion, uploadMethod, ruleId]),
      Array.from({ length: 2 }, () => [attachmentPolicyVersion, 'picker', 'fixture-secret']));
    const containment = await admin('policies', { fileContentModes: { claude: 'off' } });
    await until(async () => (await reportedRelease(rollback.version))?.appliedPolicyVersion === containment.version,
      'The rolled-back browser did not acknowledge the policy once the unavailable attachment check was removed.', 50_000);
    await checkClaudeHostBlock();
  }
  assert.ok(updateEndpoints.every(({ hasCookie, hasAuthorization }) => !hasCookie && !hasAuthorization));
  t.diagnostic(`Rollback and restart took ${reopened - rollbackStarted} ms. Control reconnected and received the queued decisions in ${replayed - reopened} ms.`);

  policy.ExtensionSettings[extensionId] = { installation_mode: 'removed' };
  await deployPolicy();
  await browser.close();
  await launch();
  const page = await openExtensions();
  await until(async () => !await extensionInfo(page), 'Chromium did not remove the policy-installed extension.');
  await admin(`installations/${before.installationId}/revoke`, {}, 204);
  const deployments = await admin('installations');
  assert.ok(deployments.find(({ installationId }) => installationId === before.installationId).revokedAt);
});
