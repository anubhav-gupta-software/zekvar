import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const api = process.env.ZEKVAR_DEMO_API;
const web = process.env.ZEKVAR_DEMO_WEB;
const owner = process.env.ZEKVAR_DEMO_TOKEN;
const otherTenant = process.env.ZEKVAR_DEMO_OTHER_TOKEN;
const artifacts = process.env.ZEKVAR_DEMO_ARTIFACTS;
assert.match(api ?? '', /^http:\/\/127\.0\.0\.1:\d+$/);
assert.match(web ?? '', /^http:\/\/localhost:\d+$/);
assert.match(owner ?? '', /^[a-f0-9]{64}$/);
assert.match(otherTenant ?? '', /^[a-f0-9]{64}$/);
const fixture = await readFile(new URL('./upload-composer.html', import.meta.url), 'utf8');
const marker = 'ZEKVAR_TEST_SECRET';

async function admin(path, body, { token = owner, expect = 200 } = {}) {
  const response = await fetch(`${api}/v1/admin/${path}`, { method: body ? 'POST' : 'GET',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: body && JSON.stringify(body), signal: AbortSignal.timeout(5_000) });
  assert.equal(response.status, expect, path);
  const text = await response.text();
  return text ? JSON.parse(text) : undefined;
}

async function until(check, message) {
  for (let attempt = 0; attempt < 160; attempt++) {
    const result = await check();
    if (result) return result;
    await delay(125);
  }
  assert.fail(message);
}

test('disables ChatGPT attachments and the whole adapter for a rollout group, fails closed, and restores protection', { timeout: 120_000 }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'zekvar-adapter-controls-'));
  let browser;
  let olderRelease = false;
  const posts = [];
  const proxy = createServer(async (request, response) => {
    try {
      if (request.url !== '/v1/enroll' && !request.url?.startsWith('/v1/browser/')) return response.writeHead(404).end();
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      if (request.url === '/v1/browser/events') posts.push(JSON.parse(body));
      // An older Browser release does not negotiate adapter controls.
      const headers = Object.fromEntries(Object.entries(request.headers).filter(([name]) =>
        (name === 'content-type' || name === 'authorization' || name.startsWith('x-zekvar-')) &&
        !(olderRelease && name === 'x-zekvar-adapter-controls')));
      const upstream = await fetch(api + request.url, { method: request.method, headers,
        body: body.length ? body : undefined, signal: AbortSignal.timeout(5_000) });
      response.writeHead(upstream.status, { 'Content-Type': 'application/json' }).end(await upstream.text());
    } catch {
      response.writeHead(502).end();
    }
  });
  await new Promise((resolve, reject) => {
    proxy.once('error', reject);
    proxy.listen(0, '127.0.0.1', resolve);
  });
  t.after(async () => {
    await browser?.close();
    await new Promise((resolve) => {
      proxy.close(resolve);
      proxy.closeAllConnections();
    });
    await rm(root, { recursive: true, force: true });
  });
  const dist = join(root, 'extension');
  execFileSync(process.execPath, ['build.mjs'], { cwd: fileURLToPath(new URL('..', import.meta.url)),
    env: { ...process.env, ZEKVAR_CONTROL_PORT: String(proxy.address().port), ZEKVAR_EXTENSION_OUTDIR: dist } });
  const sensitive = join(root, 'synthetic-adapter-secret.txt');
  await writeFile(sensitive, `Synthetic attachment ${marker}`);

  const baseline = await admin('policies', { mode: 'block', fileContentModes: { chatgpt: 'block' } });
  const group = await admin('policy-groups', { name: 'Adapter kill switch canary' });
  const groupPath = `policy-groups/${group.id}/policies`;
  const { grant } = await admin('enrollment-grants', {});
  browser = await chromium.launchPersistentContext(join(root, 'profile'), {
    channel: 'chromium', headless: process.env.ZEKVAR_DEMO_HEADED !== '1', viewport: { width: 1440, height: 960 },
    args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`,
      '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1'],
  });
  browser.setDefaultTimeout(8_000);
  const worker = browser.serviceWorkers()[0] ?? await browser.waitForEvent('serviceworker');
  const popup = await browser.newPage();
  await popup.goto(new URL('popup.html', worker.url()).href);
  await popup.getByLabel('Enrollment grant').fill(grant);
  await popup.getByRole('button', { name: 'Enroll this browser', exact: true }).click();
  await popup.getByText(`Connected to Control · BLOCK v${baseline.version}`, { exact: true }).waitFor();
  const [{ installationId }] = await admin('installations');
  await admin(`installations/${installationId}/policy-group`, { groupId: group.id }, { expect: 204 });
  const sync = () => popup.getByRole('button', { name: 'Sync now', exact: true }).click();
  const installation = async () => (await admin('installations')).find((row) => row.installationId === installationId);
  async function acknowledged(version) {
    for (let attempt = 0; attempt < 6; attempt++) {
      await sync();
      for (let poll = 0; poll < 16; poll++) {
        if ((await installation())?.appliedPolicyVersion === version) return;
        await delay(125);
      }
    }
    assert.fail(`Browser did not acknowledge version ${version}.`);
  }
  const readiness = async () => (await admin(`reports/composer-readiness?rolloutGroup=${group.id}`)).apps
    .find(({ appId }) => appId === 'chatgpt');
  const current = async () => (await admin(groupPath))[0] ?? (await admin('policies'))[0];

  const chat = await browser.newPage();
  await chat.route('https://chatgpt.com/**', (route) => route.fulfill({ contentType: 'text/html', body: fixture }));
  await chat.goto('https://chatgpt.com/');
  await chat.evaluate(() => {
    window.sends = 0;
    document.querySelector('[data-testid="send-button"]').addEventListener('click', () => { window.sends++; });
  });
  const status = (pattern) => chat.getByText(pattern).waitFor();
  const fileEvents = () => chat.evaluate(() => window.fileEvents);
  const sends = () => chat.evaluate(() => window.sends);
  async function pick() {
    await chat.evaluate(() => { window.fileEvents = []; });
    await chat.getByLabel('Attach fixture files').setInputFiles([]);
    const chooser = chat.waitForEvent('filechooser');
    await chat.getByLabel('Attach fixture files').click();
    await (await chooser).setFiles([sensitive]);
  }
  async function send() {
    const field = chat.getByLabel('Fixture text', { exact: true });
    await field.fill(`Draft ${marker}`);
    await chat.getByRole('button', { name: 'Fixture send', exact: true }).click();
  }
  async function expectProtected(version) {
    await status(new RegExp(`BLOCK v${version}.*File content block$`));
    await pick();
    await chat.getByRole('alert').filter({ hasText: 'sensitive content was detected' }).waitFor();
    assert.deepEqual(await fileEvents(), []);
    const before = await sends();
    await send();
    await chat.getByRole('alert').filter({ hasText: 'Submission blocked' }).waitFor();
    assert.equal(await sends(), before);
  }
  async function navigation() {
    const page = await browser.newPage();
    try {
      const error = await page.goto('https://chatgpt.com/').then(() => undefined, (reason) => String(reason));
      return /ERR_BLOCKED_BY_CLIENT/.test(error ?? '') ? 'blocked' : /ERR_NAME_NOT_RESOLVED/.test(error ?? '') ? 'open' : error;
    } finally {
      await page.close();
    }
  }

  const inherited = await current();
  await acknowledged(inherited.version);
  await expectProtected(inherited.version);
  assert.equal(await navigation(), 'open');
  const protectedEvents = posts.length;
  assert.ok(protectedEvents >= 2, 'The protected file and prompt decisions did not reach Control.');

  await t.test('attachments only, fail open: files reach the site and the prompt stays protected', async () => {
    const published = await admin(groupPath, { adapterControls: { chatgpt: { scope: 'attachments', fallback: 'open' } } });
    await acknowledged(published.version);
    await status(/Attachments disabled by administrator$/);
    await pick();
    await until(async () => (await fileEvents()).length === 2, 'The site did not receive the selected file.');
    assert.deepEqual(await fileEvents(), [['input', 1], ['change', 1]]);
    const before = await sends();
    await send();
    await chat.getByRole('alert').filter({ hasText: 'Submission blocked' }).waitFor();
    assert.equal(await sends(), before);
    await delay(300);
    assert.ok(posts.slice(protectedEvents).every(({ uploadMethod }) => uploadMethod === undefined), 'A file decision was reported.');
    const chatgpt = await readiness();
    assert.equal(chatgpt.attachmentsDisabled, 1);
    assert.equal(chatgpt.counts.detected, 1);
  });

  await t.test('the whole adapter, fail open: Browser leaves ChatGPT untouched and reports Disabled by administrator', async () => {
    const published = await admin(groupPath, { adapterControls: { chatgpt: { scope: 'adapter', fallback: 'open' } } });
    await acknowledged(published.version);
    await status('Zekvar · ChatGPT protection disabled by your administrator');
    const reported = posts.length;
    const before = await sends();
    await send();
    await until(async () => await sends() === before + 1, 'The disabled adapter still held the prompt.');
    await pick();
    await until(async () => (await fileEvents()).length === 2, 'The disabled adapter still held the file.');
    await until(async () => (await installation()).chatGptCoverage === 'disabled', 'Control did not record the disabled coverage state.');
    const chatgpt = await readiness();
    assert.deepEqual([chatgpt.counts.disabled_by_admin, chatgpt.counts.unsupported, chatgpt.counts.detected], [1, 0, 0]);
    await delay(300);
    assert.equal(posts.length, reported, 'A disabled adapter reported a decision.');
  });

  const dashboard = await browser.newPage();
  dashboard.on('dialog', (dialog) => dialog.accept());
  async function signIn(token) {
    await browser.clearCookies();
    await dashboard.goto(web);
    await dashboard.getByLabel('Control token', { exact: true }).fill(token);
    await dashboard.getByRole('button', { name: 'Sign in', exact: true }).click();
    await dashboard.getByRole('heading', { name: 'Security overview', exact: true }).waitFor();
  }

  await t.test('an auditor sees the disabled state but cannot change an adapter control', async () => {
    const auditor = await admin('access', { name: 'Adapter auditor', role: 'auditor', hours: 1 });
    await admin(groupPath, { adapterControls: {} }, { token: auditor.token, expect: 403 });
    await signIn(auditor.token);
    await dashboard.goto(`${web}/adapters?group=${group.id}`);
    const row = dashboard.getByRole('row', { name: /^ChatGPT/ });
    await row.getByText('Whole adapter disabled · Fail open', { exact: true }).waitFor();
    assert.equal(await dashboard.getByRole('button', { name: 'Publish ChatGPT adapter control' }).count(), 0);
  });

  await t.test('fail closed from the dashboard blocks ChatGPT hosts, including on an older Browser release', async () => {
    await signIn(owner);
    await dashboard.goto(`${web}/adapters?group=${group.id}`);
    await dashboard.getByRole('row', { name: /^ChatGPT/ }).getByText('1', { exact: true }).first().waitFor();
    for (const width of [1440, 390]) {
      await dashboard.setViewportSize({ width, height: width === 390 ? 844 : 960 });
      assert.ok(await dashboard.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth),
        `The adapter controls page scrolls sideways at ${width}px.`);
      if (artifacts) {
        await mkdir(artifacts, { recursive: true });
        await dashboard.screenshot({ path: join(artifacts, `43-adapter-controls-${width}.png`), fullPage: true });
      }
    }
    await dashboard.setViewportSize({ width: 1440, height: 960 });
    await dashboard.getByLabel('ChatGPT interception', { exact: true }).selectOption('adapter');
    await dashboard.getByLabel('ChatGPT when disabled', { exact: true }).selectOption('closed');
    await dashboard.getByRole('button', { name: 'Publish ChatGPT adapter control', exact: true }).click();
    await dashboard.getByText(/ChatGPT adapter disabled in version \d+\./).waitFor();
    const closed = await current();
    assert.deepEqual(closed.adapterControls, { chatgpt: { scope: 'adapter', fallback: 'closed' } });
    await acknowledged(closed.version);
    assert.equal(await navigation(), 'blocked');

    olderRelease = true;
    const older = await admin(groupPath, { adapterControls: { chatgpt: { scope: 'attachments', fallback: 'closed' } } });
    await sync();
    await popup.getByText(`Connected to Control · BLOCK v${older.version}`, { exact: true }).waitFor();
    await delay(500);
    assert.notEqual((await installation()).appliedPolicyVersion, older.version, 'An older release acknowledged a control it cannot apply.');
    assert.equal(await navigation(), 'blocked');
    const openOlder = await admin(groupPath, { adapterControls: { chatgpt: { scope: 'attachments', fallback: 'open' } } });
    await sync();
    await status(new RegExp(`BLOCK v${openOlder.version}.*File content block$`));
    await pick();
    await chat.getByRole('alert').filter({ hasText: 'sensitive content was detected' }).waitFor();
    assert.deepEqual(await fileEvents(), [], 'An older release must keep protecting attachments it cannot disable.');
    assert.notEqual((await installation()).appliedPolicyVersion, openOlder.version);
    assert.equal((await readiness()).counts.policy_pending, 1);
    olderRelease = false;
  });

  await t.test('re-enabling restores protection without touching the baseline or another tenant', async () => {
    const restored = await admin(groupPath, { adapterControls: {} });
    await acknowledged(restored.version);
    await expectProtected(restored.version);
    assert.equal(await navigation(), 'open');
    assert.equal(posts.filter(({ policyVersion }) => policyVersion === restored.version).length >= 2, true);
    assert.deepEqual((await admin('policies'))[0].adapterControls, {});
    assert.deepEqual((await admin('policies', undefined, { token: otherTenant }))[0].adapterControls, {});
    await until(async () => (await readiness()).counts.detected === 1, 'ChatGPT did not return to Detected.');
  });
});
