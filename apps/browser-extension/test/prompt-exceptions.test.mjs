import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
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
const chatFixture = await readFile(new URL('./guest-chatgpt-composer.html', import.meta.url), 'utf8');
const geminiFixture = await readFile(new URL('./gemini-composer.html', import.meta.url), 'utf8');
const marker = 'ZEKVAR_TEST_SECRET';
const fakePat = 'ghp_' + '0'.repeat(36);
const reason = 'Synthetic support case EX-123';

async function until(check, message) {
  for (let attempt = 0; attempt < 80; attempt++) {
    if (await check()) return;
    await delay(100);
  }
  assert.fail(message);
}

test('prompt exception applies only on its app and detector and expires in the existing Chrome tab', { timeout: 90_000 }, async (t) => {
  const scratch = await mkdtemp(join(tmpdir(), 'zekvar-prompt-exceptions-'));
  const dist = join(scratch, 'extension');
  const profile = join(scratch, 'profile');
  let browser;
  let offline = false;
  let loseAcknowledgment = false;
  const events = [];
  const policies = [];
  const proxy = createServer(async (request, response) => {
    try {
      if (!request.url?.startsWith('/v1/browser/') && request.url !== '/v1/enroll') return response.writeHead(404).end();
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      const event = request.url === '/v1/browser/events' ? JSON.parse(body.toString()) : undefined;
      if (event) events.push(event);
      if (offline) return response.writeHead(503).end();
      const upstream = await fetch(api + request.url, {
        method: request.method,
        headers: {
          ...(request.headers.authorization ? { Authorization: request.headers.authorization } : {}),
          ...(request.headers['x-zekvar-assignment-aware'] ? { 'X-Zekvar-Assignment-Aware': '1' } : {}),
          ...(body.length ? { 'Content-Type': 'application/json' } : {}),
        },
        body: body.length ? body : undefined, signal: AbortSignal.timeout(5000),
      });
      const payload = await upstream.text();
      if (request.url === '/v1/browser/policy' && upstream.ok) policies.push(JSON.parse(payload));
      if (event?.decision === 'exception_applied' && upstream.ok && loseAcknowledgment) {
        loseAcknowledgment = false;
        return response.writeHead(503).end();
      }
      response.writeHead(upstream.status, { 'Content-Type': 'application/json' }).end(payload);
    } catch {
      response.writeHead(502).end();
    }
  });
  proxy.listen(0, '127.0.0.1');
  await once(proxy, 'listening');
  t.after(async () => {
    await browser?.close();
    await new Promise((done) => { proxy.close(done); proxy.closeAllConnections(); });
    await rm(scratch, { recursive: true, force: true });
  });
  execFileSync(process.execPath, ['build.mjs'], {
    cwd: fileURLToPath(new URL('..', import.meta.url)),
    env: { ...process.env, ZEKVAR_CONTROL_PORT: String(proxy.address().port), ZEKVAR_EXTENSION_OUTDIR: dist },
  });

  async function admin(path, body) {
    const response = await fetch(api + '/v1/admin/' + path, {
      method: body ? 'POST' : 'GET',
      headers: { Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body && JSON.stringify(body), signal: AbortSignal.timeout(5000),
    });
    assert.equal(response.status, 200, `Control request failed for ${path}`);
    return response.json();
  }

  async function launch() {
    browser = await chromium.launchPersistentContext(profile, {
      channel: 'chromium', headless: process.env.ZEKVAR_DEMO_HEADED !== '1',
      args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`],
    });
    browser.setDefaultTimeout(8000);
    const worker = browser.serviceWorkers()[0] ?? await browser.waitForEvent('serviceworker');
    const popup = await browser.newPage();
    await popup.goto(new URL('popup.html', worker.url()).href);
    return { popup, worker };
  }
  const sync = (popup) => popup.getByRole('button', { name: 'Sync now', exact: true }).click();
  async function composer(app) {
    const page = await browser.newPage();
    const url = app === 'chatgpt' ? 'https://chatgpt.com/uc/00000000-1234-4321-8765-0123456789ab' : 'https://gemini.google.com/app';
    await page.route(`${new URL(url).origin}/**`, (route) => route.fulfill({
      contentType: 'text/html', body: app === 'chatgpt' ? chatFixture : geminiFixture,
    }));
    await page.goto(url);
    const input = app === 'chatgpt' ? page.getByPlaceholder('Ask ChatGPT', { exact: true }) :
      page.getByRole('textbox', { name: 'Enter a prompt for Gemini', exact: true });
    const send = app === 'chatgpt' ? page.getByRole('button', { name: 'Send message', exact: true }) :
      page.locator('input-area-v2').getByRole('button', { name: 'Send message', exact: true });
    const count = () => page.locator('#fixture-sends').textContent();
    const submit = async (text, method = 'click') => {
      await input.fill(text);
      if (method === 'enter') await input.press('Enter');
      else await send.click();
    };
    const notice = (message) => page.getByRole('alert').filter({ hasText: message }).waitFor();
    return { page, submit, count, notice };
  }

  let { popup, worker } = await launch();
  const dashboard = await browser.newPage();
  await dashboard.goto(web);
  await dashboard.getByLabel('Control token', { exact: true }).fill(token);
  await dashboard.getByRole('button', { name: 'Sign in', exact: true }).click();
  await dashboard.getByRole('heading', { name: 'Security overview', exact: true }).waitFor();
  const { grant } = await admin('enrollment-grants', {});
  await popup.getByLabel('Enrollment grant').fill(grant);
  await popup.getByRole('button', { name: 'Enroll this browser', exact: true }).click();
  await popup.getByText('Connected to Control · MONITOR v1', { exact: true }).waitFor();
  const [chat, gemini] = await Promise.all([composer('chatgpt'), composer('gemini')]);

  await dashboard.getByRole('link', { name: 'Policy preview', exact: true }).click();
  await dashboard.getByLabel('Draft test marker', { exact: true }).selectOption('block');
  await dashboard.getByLabel('Draft GitHub classic PAT', { exact: true }).selectOption('block');
  await dashboard.getByRole('button', { name: 'Add prompt exception', exact: true }).click();
  const runPreview = dashboard.getByRole('button', { name: 'Run preview', exact: true });
  await runPreview.click();
  await dashboard.getByRole('alert').filter({ hasText: 'Choose one exception per app and detector' }).waitFor();
  await dashboard.getByLabel('Reason', { exact: true }).fill(reason);
  const expiry = new Date(Date.now() + 20_000);
  await dashboard.getByLabel('Expires (UTC)', { exact: true }).fill(expiry.toISOString().slice(0, -1));
  await runPreview.click();
  const result = (name) => dashboard.getByRole('row', { name: new RegExp(`^${name} `) }).getByRole('cell').nth(1);
  await result('Synthetic test marker').getByText('Exception applied', { exact: true }).waitFor();
  await result('Both detectors match').getByText('Block', { exact: true }).waitFor();
  await dashboard.getByLabel('Prompt sample destination', { exact: true }).selectOption('gemini');
  await runPreview.click();
  await result('Synthetic test marker').getByText('Block', { exact: true }).waitFor();
  await dashboard.getByLabel('Prompt sample destination', { exact: true }).selectOption('chatgpt');
  await runPreview.click();
  if (artifacts) await dashboard.getByRole('table', { name: 'Preview results' }).screenshot({ path: join(artifacts, '26-prompt-exception-preview.png') });
  dashboard.once('dialog', (dialog) => dialog.accept());
  await dashboard.getByRole('button', { name: 'Publish previewed policy', exact: true }).click();
  await dashboard.getByText('Previewed policy published as version 2.', { exact: true }).waitFor();
  await sync(popup);
  for (const site of [chat, gemini]) await site.page.getByText(/^Zekvar · BLOCK v2/).waitFor();
  assert.deepEqual(policies.at(-1).promptExceptionLease.grants, [
    { appId: 'chatgpt', ruleId: 'fixture-secret', expiresAtMs: expiry.getTime() },
  ]);
  assert.doesNotMatch(JSON.stringify(policies), /EX-123/);
  await chat.submit(marker);
  await chat.notice('Temporary policy exception applied');
  assert.equal(await chat.count(), '1');
  await until(async () => (await admin('events?decision=exception_applied')).length === 1, 'Control did not record the allowed send.');
  await chat.submit(`${marker} ${fakePat}`, 'enter');
  await chat.notice('GitHub classic personal access token');
  assert.equal(await chat.count(), '1');
  await gemini.submit(marker, 'enter');
  await gemini.notice('Submission blocked');
  assert.equal(await gemini.count(), '0');

  loseAcknowledgment = true;
  await chat.submit(marker, 'enter');
  await chat.notice('Temporary policy exception applied');
  assert.equal(await chat.count(), '2');
  await until(() => !loseAcknowledgment, 'The proxy did not interrupt the acknowledgment.');
  await sync(popup);
  const allowed = () => admin('events?decision=exception_applied');
  await until(() => events.filter((event) => event.decision === 'exception_applied').length >= 3, 'Chrome did not retry the exception event.');
  assert.equal((await allowed()).length, 2);
  assert.deepEqual(events.filter((event) => event.decision === 'exception_applied').slice(-2)[0],
    events.filter((event) => event.decision === 'exception_applied').at(-1));
  assert.doesNotMatch(JSON.stringify(events), /ZEKVAR_TEST_SECRET|ghp_0+|EX-123/);
  assert.ok(Date.now() < expiry.getTime(), 'The controlled attempts must run before expiry.');

  offline = true;
  await delay(Math.max(0, expiry.getTime() - Date.now() + 100));
  await chat.submit(marker);
  await chat.notice('Submission blocked');
  assert.equal(await chat.count(), '2');
  assert.equal((await allowed()).length, 2);
  offline = false;
  const extended = await admin('policies', { promptExceptions: [
    { appId: 'chatgpt', ruleId: 'fixture-secret', expiresAt: new Date(Date.now() + 120_000).toISOString(), reason },
  ] });
  await sync(popup);
  await chat.page.getByText(new RegExp(`^Zekvar · BLOCK v${extended.version}`)).waitFor();
  await chat.submit(marker);
  await chat.notice('Temporary policy exception applied');
  assert.equal(await chat.count(), '3');
  await until(async () => (await allowed()).length === 3, 'Control did not record the renewed exception use.');
  assert.equal(await worker.evaluate(() => chrome.storage.local.get('controlState')
    .then(({ controlState }) => JSON.stringify(controlState).includes('promptExceptionLease'))), false);

  offline = true;
  await browser.close();
  ({ popup, worker } = await launch());
  const reopened = await composer('chatgpt');
  await reopened.page.getByText(/Offline policy/).waitFor();
  await reopened.submit(marker, 'enter');
  await reopened.notice('Submission blocked');
  assert.equal(await reopened.count(), '0');
  offline = false;
  const removed = await admin('policies', { promptExceptions: [] });
  await sync(popup);
  await reopened.page.getByText(new RegExp(`^Zekvar · BLOCK v${removed.version}`)).waitFor();
  await reopened.submit(marker);
  await reopened.notice('Submission blocked');
  assert.equal(await reopened.count(), '0');
  const { entries } = await admin('events/export?decision=exception_applied');
  assert.equal(entries.length, 3);
  assert.ok(entries.every(({ appId, ruleId }) => appId === 'chatgpt' && ruleId === 'fixture-secret'));
});
