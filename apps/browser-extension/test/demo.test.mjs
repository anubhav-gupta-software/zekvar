import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const api = process.env.ZEKVAR_DEMO_API;
const web = process.env.ZEKVAR_DEMO_WEB;
const token = process.env.ZEKVAR_DEMO_TOKEN;
const artifacts = process.env.ZEKVAR_DEMO_ARTIFACTS;
assert.match(api ?? '', /^http:\/\/127\.0\.0\.1:\d+$/);
assert.match(web ?? '', /^http:\/\/localhost:\d+$/);
assert.match(token ?? '', /^[a-f0-9]{64}$/);
const marker = 'ZEKVAR_TEST_SECRET';
const fixture = await readFile(new URL('./guest-chatgpt-composer.html', import.meta.url), 'utf8');

async function events() {
  const response = await fetch(`${api}/v1/admin/events?appId=chatgpt`, {
    headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(5000),
  });
  assert.equal(response.status, 200);
  return response.json();
}

async function waitForEvents(count) {
  for (let attempt = 0; attempt < 50; attempt++) {
    const rows = await events();
    if (rows.length === count) return rows;
    assert.ok(rows.length < count, 'Control stored an unexpected duplicate event');
    await delay(100);
  }
  assert.fail(`Expected ${count} ChatGPT events in Control.`);
}

async function screenshot(page, file) {
  if (artifacts) await page.screenshot({ path: join(artifacts, file), fullPage: true });
}

test('fresh Chrome profile completes the Control-to-browser demo', { timeout: 90_000 }, async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'zekvar-demo-profile-'));
  const dist = join(dir, 'extension');
  const attempts = [];
  let offline = false;
  let loseAcknowledgment = false;
  let browser;
  const proxy = createServer(async (request, reply) => {
    try {
      if (!request.url?.startsWith('/v1/browser/') && request.url !== '/v1/enroll') return reply.writeHead(404).end();
      if (offline) return reply.writeHead(503).end();
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      const isEvent = request.url === '/v1/browser/events';
      if (isEvent) attempts.push(JSON.parse(body.toString()));
      const response = await fetch(`${api}${request.url}`, {
        method: request.method, signal: AbortSignal.timeout(5000),
        headers: {
          ...(request.headers.authorization ? { Authorization: request.headers.authorization } : {}),
          ...(body.length ? { 'Content-Type': 'application/json' } : {}),
        },
        body: body.length ? body : undefined,
      });
      if (isEvent && response.ok && loseAcknowledgment) {
        loseAcknowledgment = false;
        return reply.writeHead(503).end();
      }
      reply.writeHead(response.status, { 'Content-Type': 'application/json' }).end(await response.text());
    } catch {
      reply.writeHead(502).end();
    }
  });
  t.after(async () => {
    try {
      await browser?.close();
    } finally {
      await new Promise((resolve) => proxy.close(resolve));
      await rm(dir, { recursive: true, force: true });
    }
  });
  await new Promise((resolve, reject) => {
    proxy.once('error', reject);
    proxy.listen(0, '127.0.0.1', resolve);
  });
  execFileSync(process.execPath, ['build.mjs'], {
    cwd: fileURLToPath(new URL('..', import.meta.url)),
    env: { ...process.env, ZEKVAR_CONTROL_PORT: String(proxy.address().port), ZEKVAR_EXTENSION_OUTDIR: dist },
  });
  browser = await chromium.launchPersistentContext(join(dir, 'profile'), {
    channel: 'chromium', headless: process.env.ZEKVAR_DEMO_HEADED !== '1', viewport: { width: 1440, height: 1000 },
    args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`],
  });
  browser.setDefaultTimeout(7000);
  const worker = browser.serviceWorkers()[0] ?? await browser.waitForEvent('serviceworker');
  const popup = await browser.newPage();
  await popup.goto(new URL('popup.html', worker.url()).href);
  const dashboard = await browser.newPage();
  const rows = dashboard.getByRole('table', { name: 'Security events' }).locator('tbody tr');
  const health = dashboard.getByRole('table', { name: 'Browser health' });
  await dashboard.goto(web);

  await t.test('enrolls through the dashboard and extension popup', async () => {
    await dashboard.getByLabel('Admin token').fill(token);
    await dashboard.getByRole('button', { name: 'Sign in' }).click();
    await dashboard.getByRole('heading', { name: 'Security overview' }).waitFor();
    await dashboard.getByRole('button', { name: 'Create enrollment grant' }).click();
    const grant = dashboard.getByLabel('Enrollment grant', { exact: true });
    await grant.waitFor();
    await popup.getByLabel('Enrollment grant').fill(await grant.inputValue());
    await popup.getByRole('button', { name: 'Enroll this browser' }).click();
    await popup.getByText('Connected to Control · MONITOR v1', { exact: true }).waitFor();
    await dashboard.reload();
    await health.getByText('v1', { exact: true }).waitFor();
    assert.equal(await grant.count(), 0);
  });

  async function publishBlock(version) {
    await dashboard.getByLabel('Policy mode').selectOption('block');
    await dashboard.getByRole('button', { name: 'Publish policy' }).click();
    await dashboard.getByText(`Version ${version} published in block mode.`, { exact: true }).waitFor();
    await popup.getByRole('button', { name: 'Sync now' }).click();
    await popup.getByText(`Connected to Control · BLOCK v${version}`, { exact: true }).waitFor();
  }

  const chat = await browser.newPage();
  await chat.route('https://chatgpt.com/**', (route) => route.fulfill({ contentType: 'text/html', body: fixture }));
  await chat.goto('https://chatgpt.com/uc/00000000-1234-4321-8765-0123456789ab');
  const prompt = chat.getByPlaceholder('Ask ChatGPT', { exact: true });
  const send = chat.getByRole('button', { name: 'Send message' });
  const submissions = chat.locator('#fixture-sends');
  const blocked = chat.getByRole('alert').filter({ hasText: 'Submission blocked' });

  await t.test('publishes Block, verifies Chrome applied it, and shows Send and Enter decisions in Control', async () => {
    await publishBlock(2);
    await prompt.fill('Synthetic clean draft');
    await chat.getByText('Zekvar · BLOCK v2', { exact: true }).waitFor();
    await send.click();
    assert.equal(await submissions.textContent(), '1');
    await prompt.fill(marker);
    await send.click();
    await blocked.waitFor();
    await prompt.press('Enter');
    assert.equal(await submissions.textContent(), '1');
    await screenshot(chat, '01-fixture-block.png');
    await prompt.fill('Synthetic edited retry');
    await prompt.press('Enter');
    assert.equal(await submissions.textContent(), '2');

    const stored = await waitForEvents(2);
    assert.ok(stored.every((event) => event.policyVersion === 2 && event.decision === 'block'));
    assert.doesNotMatch(JSON.stringify(stored), /ZEKVAR_TEST_SECRET|Synthetic (?:clean|edited)/);
    await dashboard.reload();
    await health.getByText('v2', { exact: true }).waitFor();
    await health.getByText('Detected', { exact: true }).waitFor();
    await dashboard.getByLabel('Application', { exact: true }).selectOption('chatgpt');
    await dashboard.getByRole('button', { name: 'Apply filters' }).click();
    await dashboard.waitForURL((url) => url.searchParams.get('app') === 'chatgpt');
    assert.equal(await rows.filter({ hasText: 'Block' }).count(), 2);
    await screenshot(dashboard, '02-control-block-events.png');
  });

  await t.test('restores Monitor and delivers a queued event exactly once after a lost acknowledgment', async () => {
    await dashboard.getByRole('button', { name: 'Restore version 1', exact: true }).click();
    await dashboard.getByText('Version 1 restored as version 3.', { exact: true }).waitFor();
    await popup.getByRole('button', { name: 'Sync now' }).click();
    await popup.getByText('Connected to Control · MONITOR v3', { exact: true }).waitFor();
    offline = true;
    await popup.getByRole('button', { name: 'Sync now' }).click();
    await popup.getByText('Control offline · MONITOR v3', { exact: true }).waitFor();
    await prompt.fill(marker);
    await chat.getByText('Zekvar · MONITOR v3 · Offline policy', { exact: true }).waitFor();
    await prompt.press('Enter');
    assert.equal(await submissions.textContent(), '3');
    await popup.getByText('1 queued', { exact: true }).waitFor();
    assert.equal((await events()).length, 2);
    await screenshot(popup, '03-offline-event-queued.png');

    offline = false;
    loseAcknowledgment = true;
    await popup.getByRole('button', { name: 'Sync now' }).click();
    await popup.getByText('Control offline · MONITOR v3', { exact: true }).waitFor();
    const first = (await waitForEvents(3)).find(({ decision }) => decision === 'monitor');
    assert.ok(first?.eventId && first.policyVersion === 3);
    await popup.getByRole('button', { name: 'Sync now' }).click();
    await popup.getByText('Connected to Control · MONITOR v3', { exact: true }).waitFor();
    assert.equal(attempts.filter(({ eventId }) => eventId === first.eventId).length, 2);
    assert.equal((await events()).filter(({ eventId }) => eventId === first.eventId).length, 1);
    for (const event of attempts) {
      assert.deepEqual(Object.keys(event).sort(), ['appId', 'decision', 'detectorCategory', 'eventId', 'policyVersion', 'ruleId', 'timestamp']);
      assert.doesNotMatch(JSON.stringify(event), /ZEKVAR_TEST_SECRET|Synthetic (?:clean|edited)/);
    }
    await dashboard.reload();
    await rows.filter({ hasText: 'Monitor' }).first().waitFor();
    assert.equal(await rows.count(), 3);
    await screenshot(dashboard, '04-control-after-reconnect.png');
  });

  await t.test('live public ChatGPT in the same fresh profile', { skip: process.env.ZEKVAR_DEMO_LIVE !== '1' }, async (live) => {
    await publishBlock(4);
    const page = await browser.newPage();
    let markerSent = false;
    page.on('request', (request) => { if (request.postData()?.includes(marker)) markerSent = true; });
    const reply = await page.goto('https://chatgpt.com/', { waitUntil: 'domcontentloaded', timeout: 12_000 }).catch(() => undefined);
    if (!reply?.ok()) return live.skip(reply ? `Live ChatGPT returned HTTP ${reply.status()}.` : 'Live ChatGPT was unreachable.');
    const input = page.locator('textarea[placeholder="Ask ChatGPT"]:visible, #prompt-textarea:visible, [data-testid="prompt-textarea"]:visible').first();
    const found = await input.waitFor({ timeout: 5000 }).then(() => true, () => false);
    if (!found) return live.skip('The live page did not expose a tested text editor.');
    await input.fill(marker);
    const active = await page.getByText('Zekvar · BLOCK v4', { exact: true }).waitFor({ timeout: 5000 }).then(() => true, () => false);
    if (!active) return live.skip('The extension did not detect a supported live Send control.');
    const sendButton = page.locator('button[data-testid="send-button"]:visible').or(
      page.getByRole('button', { name: /^(Send prompt|Send message|Send)$/i }));
    const available = await sendButton.waitFor({ timeout: 5000 }).then(() => true, () => false);
    if (!available) return live.skip('The live Send control was absent or ambiguous.');
    await sendButton.click();
    await page.getByRole('alert').filter({ hasText: 'Submission blocked' }).waitFor();
    await input.press('Enter');
    const stored = await waitForEvents(5);
    assert.equal(stored.filter(({ policyVersion, decision }) => policyVersion === 4 && decision === 'block').length, 2);
    assert.equal(markerSent, false, 'The test marker appeared in an outgoing browser request.');
    await screenshot(page, '05-live-chatgpt-block.png');
    await input.fill('Reply with OK. This is an automated synthetic compatibility check.');
    await input.press('Enter');
    await page.getByText('Reply with OK. This is an automated synthetic compatibility check.', { exact: true }).last().waitFor();
    assert.equal(markerSent, false, 'The test marker appeared in an outgoing browser request.');
    await dashboard.reload();
    await rows.filter({ hasText: 'Block' }).nth(3).waitFor();
    assert.equal(await rows.count(), 5);
    await screenshot(dashboard, '06-control-with-live-events.png');
  });
});
