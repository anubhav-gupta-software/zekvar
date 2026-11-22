import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { domainFixtureArgs, startDomainFixture } from './domain-fixture.mjs';

const api = process.env.ZEKVAR_DEMO_API;
const web = process.env.ZEKVAR_DEMO_WEB;
const token = process.env.ZEKVAR_DEMO_TOKEN;
const artifacts = process.env.ZEKVAR_DEMO_ARTIFACTS;
assert.match(api ?? '', /^http:\/\/127\.0\.0\.1:\d+$/);
assert.match(web ?? '', /^http:\/\/localhost:\d+$/);
assert.match(token ?? '', /^[a-f0-9]{64}$/);
const marker = 'ZEKVAR_TEST_SECRET';
const fixture = await readFile(new URL('./guest-chatgpt-composer.html', import.meta.url), 'utf8');

async function adminGet(path) {
  const response = await fetch(`${api}/v1/admin/${path}`, {
    headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(5000),
  });
  assert.equal(response.status, 200);
  return response.json();
}

const events = () => adminGet('events?appId=chatgpt');
const inventory = () => adminGet('ai-apps');

async function waitUntil(check, message) {
  for (let attempt = 0; attempt < 50; attempt++) {
    if (await check()) return;
    await delay(100);
  }
  assert.fail(message);
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
  const domains = await startDomainFixture();
  const dist = join(dir, 'extension');
  const attempts = [];
  const observationAttempts = [];
  let offline = false;
  let loseAcknowledgment = false;
  let loseObservationAcknowledgment = false;
  let browser;
  const proxy = createServer(async (request, reply) => {
    try {
      if (!request.url?.startsWith('/v1/browser/') && request.url !== '/v1/enroll') return reply.writeHead(404).end();
      if (offline) return reply.writeHead(503).end();
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      const isEvent = request.url === '/v1/browser/events';
      const isObservation = request.url === '/v1/browser/ai-app-observations';
      if (isEvent) attempts.push(JSON.parse(body.toString()));
      if (isObservation) observationAttempts.push(JSON.parse(body.toString()));
      const response = await fetch(`${api}${request.url}`, {
        method: request.method, signal: AbortSignal.timeout(5000),
        headers: {
          ...(request.headers.authorization ? { Authorization: request.headers.authorization } : {}),
          ...(request.headers['x-zekvar-assignment-aware'] ? { 'X-Zekvar-Assignment-Aware': request.headers['x-zekvar-assignment-aware'] } : {}),
          ...(body.length ? { 'Content-Type': 'application/json' } : {}),
        },
        body: body.length ? body : undefined,
      });
      if (isEvent && response.ok && loseAcknowledgment) {
        loseAcknowledgment = false;
        return reply.writeHead(503).end();
      }
      if (isObservation && response.ok && loseObservationAcknowledgment) {
        loseObservationAcknowledgment = false;
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
      await Promise.all([domains.close(), new Promise((resolve) => proxy.close(resolve))]);
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
    args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`, ...domainFixtureArgs],
  });
  browser.setDefaultTimeout(7000);
  const worker = browser.serviceWorkers()[0] ?? await browser.waitForEvent('serviceworker');
  const buildManifest = JSON.parse(await readFile(join(dist, 'manifest.json'), 'utf8'));
  assert.equal(new URL(worker.url()).pathname, '/' + buildManifest.background.service_worker);
  const popup = await browser.newPage();
  await popup.goto(new URL('popup.html', worker.url()).href);
  const dashboard = await browser.newPage();
  const rows = dashboard.getByRole('table', { name: 'Security events' }).locator('tbody tr');
  const health = dashboard.getByRole('table', { name: 'Browser health' });
  await dashboard.goto(web);

  await t.test('enrolls through the dashboard and extension popup', async () => {
    await dashboard.getByLabel('Control token').fill(token);
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
    await dashboard.getByLabel('Test marker', { exact: true }).selectOption('block');
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

    await dashboard.getByRole('link', { name: 'Reports', exact: true }).click();
    const summary = dashboard.getByRole('region', { name: 'Summary of policy events', exact: true });
    await summary.getByText('Blocks', { exact: true }).waitFor();
    assert.deepEqual(await summary.locator('strong').allTextContents(), ['2', '0', '2']);
    const download = await dashboard.getByRole('link', { name: 'Export report (JSON)', exact: true }).getAttribute('href');
    const response = await dashboard.request.get(new URL(download, dashboard.url()).href);
    assert.equal(response.status(), 200);
    const aggregate = await response.json();
    assert.equal(aggregate.counts.block, 2);
    assert.deepEqual(aggregate.byApp.map(({ id }) => id), ['chatgpt']);
    assert.doesNotMatch(JSON.stringify(aggregate), /ZEKVAR_TEST_SECRET|installationId|eventId/);
    await screenshot(dashboard, '02a-control-ai-enforcement-report.png');
    await dashboard.getByRole('link', { name: 'Investigate security events', exact: true }).click();
    await rows.filter({ hasText: 'Block' }).first().waitFor();
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
    const clean = 'Reply with OK. This is an automated synthetic compatibility check.';
    const sanitized = `${clean} Example: [REDACTED]`;
    await input.fill(`${clean} Example: ${marker}`);
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
    await page.getByRole('button', { name: 'Redact detected values', exact: true }).click();
    await page.getByRole('alert').filter({ hasText: 'Detected values redacted.' }).waitFor();
    assert.equal(await input.evaluate((editor) => editor instanceof HTMLTextAreaElement ? editor.value : editor.innerText), sanitized);
    await screenshot(page, '18-live-chatgpt-redacted-draft.png');
    await input.press('Enter');
    await page.getByText(sanitized, { exact: true }).last().waitFor();
    assert.equal(markerSent, false, 'The test marker appeared in an outgoing browser request.');
    await dashboard.reload();
    await rows.filter({ hasText: 'Block' }).nth(3).waitFor();
    assert.equal(await rows.count(), 5);
    await screenshot(dashboard, '06-control-with-live-events.png');
  });

  const fakePat = 'ghp_' + '0'.repeat(36);
  let monitorVersion;
  const previousEvents = await events();
  let expectedCount = previousEvents.length;
  const policyHistory = dashboard.getByRole('table', { name: 'Policy history' });
  async function configureGitHub(mode, markerMode) {
    const current = policyHistory.locator('tbody tr').first().locator('td').first();
    const version = Number((await current.innerText()).slice(1)) + 1;
    await dashboard.getByLabel('Test marker', { exact: true }).selectOption(markerMode);
    await dashboard.getByLabel('GitHub classic PAT', { exact: true }).selectOption(mode);
    await dashboard.getByRole('button', { name: 'Publish policy' }).click();
    await dashboard.getByText(`Version ${version} published in ${markerMode} mode.`, { exact: true }).waitFor();
    await popup.getByRole('button', { name: 'Sync now' }).click();
    await popup.getByText(`Connected to Control · ${markerMode.toUpperCase()} v${version}`, { exact: true }).waitFor();
    await prompt.fill('Draft for policy synchronization');
    await chat.getByText(`Zekvar · ${markerMode.toUpperCase()} v${version} · GitHub PAT ${mode}`, { exact: true }).waitFor();
    return version;
  }

  await t.test('GitHub classic PAT starts off and Monitor logs only complete, delimited candidates', async () => {
    const sentBefore = Number(await submissions.textContent());
    assert.equal(await dashboard.getByLabel('GitHub classic PAT', { exact: true }).inputValue(), 'off');
    await prompt.fill(fakePat);
    await prompt.press('Enter');
    assert.equal(await submissions.textContent(), String(sentBefore + 1));
    assert.equal((await events()).length, expectedCount);

    monitorVersion = await configureGitHub('monitor', 'block');
    for (const negative of [fakePat.slice(0, -1), fakePat + '0', `prefix_${fakePat}`, fakePat + '_suffix', 'gho_' + '0'.repeat(36)]) {
      await prompt.fill(negative);
      await prompt.press('Enter');
    }
    await prompt.fill(`export EXAMPLE_TOKEN="${fakePat}"`);
    await prompt.press('Enter');
    assert.equal(await submissions.textContent(), String(sentBefore + 7));
    const stored = await waitForEvents(++expectedCount);
    const [match] = stored.filter(({ ruleId }) => ruleId === 'github-classic-pat');
    assert.equal(match.policyVersion, monitorVersion);
    assert.equal(match.decision, 'monitor');
    assert.equal(match.detectorCategory, 'credential');
    assert.ok(!JSON.stringify(stored).includes(fakePat));
  });

  await t.test('GitHub warning can be overridden once even when the test marker mode is Block', async () => {
    const version = await configureGitHub('warn', 'block');
    const count = Number(await submissions.textContent());
    await prompt.fill(fakePat);
    await send.click();
    await chat.getByRole('alert').filter({ hasText: 'GitHub classic personal access token' }).waitFor();
    assert.equal(await submissions.textContent(), String(count));
    await chat.getByRole('button', { name: 'Continue anyway' }).click();
    assert.equal(await submissions.textContent(), String(count + 1));
    expectedCount += 2;
    const stored = await waitForEvents(expectedCount);
    assert.deepEqual(stored.filter(({ policyVersion }) => policyVersion === version).map(({ decision }) => decision).sort(),
      ['warn', 'warn_override']);
  });

  await t.test('Block wins for mixed matches and rollback restores the detector mode', async () => {
    const version = await configureGitHub('block', 'monitor');
    const count = Number(await submissions.textContent());
    await prompt.fill(`${marker} ${fakePat}`);
    await send.click();
    await blocked.waitFor();
    assert.equal(await submissions.textContent(), String(count));
    const stored = await waitForEvents(++expectedCount);
    assert.deepEqual(stored.filter(({ policyVersion }) => policyVersion === version).map(({ ruleId, decision }) => [ruleId, decision]),
      [['github-classic-pat', 'block']]);
    await dashboard.reload();
    await rows.filter({ hasText: 'GitHub classic PAT' }).first().waitFor();
    await screenshot(dashboard, '10-control-credential-events.png');
    await dashboard.getByRole('button', { name: `Restore version ${monitorVersion}`, exact: true }).click();
    await dashboard.getByText(`Version ${monitorVersion} restored as version ${version + 1}.`, { exact: true }).waitFor();
    assert.equal(await dashboard.getByLabel('GitHub classic PAT', { exact: true }).inputValue(), 'monitor');
    assert.match(await policyHistory.locator('tbody tr').first().innerText(), /Monitor/);
    await popup.getByRole('button', { name: 'Sync now' }).click();
    await prompt.fill(fakePat);
    await chat.getByText(`Zekvar · BLOCK v${version + 1} · GitHub PAT monitor`, { exact: true }).waitFor();
    await prompt.press('Enter');
    assert.equal(await submissions.textContent(), String(count + 1));
    const restored = await waitForEvents(++expectedCount);
    assert.deepEqual(restored.filter(({ policyVersion }) => policyVersion === version + 1).map(({ ruleId, decision }) => [ruleId, decision]),
      [['github-classic-pat', 'monitor']]);
    assert.ok(!JSON.stringify(attempts).includes(fakePat) && !JSON.stringify(restored).includes(fakePat));
  });

  let discoveryOffVersion;
  let discoveryOnVersion;
  const discoveryMode = dashboard.getByLabel('App discovery', { exact: true });
  const apps = dashboard.getByRole('table', { name: 'App inventory' });
  const appPage = await browser.newPage();
  const privateDetail = 'SYNTHETIC_PRIVATE_PAGE_DETAIL';
  const appFixture = `<html><title>${privateDetail}</title><p>${privateDetail}</p></html>`;
  await appPage.route('https://**/*', (route) => route.fulfill({
    contentType: 'text/html',
    body: new URL(route.request().url()).hostname === 'claude.ai.example.test'
      ? '<iframe src="https://gemini.google.com/embed"></iframe>' : appFixture,
  }));
  const openApp = (host) => appPage.goto(`https://${host}/fixture/${privateDetail}?conversation=${privateDetail}#${privateDetail}`);
  const sync = () => popup.getByRole('button', { name: 'Sync now' }).click();
  const policyVersion = async () => Number((await policyHistory.locator('tbody tr').first().locator('td').first().innerText()).slice(1));

  await t.test('enabling discovery records only top-level visits on the three catalog origins', async () => {
    assert.equal(await discoveryMode.inputValue(), 'off');
    discoveryOffVersion = await policyVersion();
    await openApp('claude.ai');
    discoveryOnVersion = discoveryOffVersion + 1;
    const markerMode = await dashboard.getByLabel('Test marker', { exact: true }).inputValue();
    await discoveryMode.selectOption('on');
    await dashboard.getByRole('button', { name: 'Publish policy' }).click();
    await dashboard.getByText(`Version ${discoveryOnVersion} published in ${markerMode} mode.`, { exact: true }).waitFor();
    await sync();
    await popup.getByText(`Connected to Control · ${markerMode.toUpperCase()} v${discoveryOnVersion}`, { exact: true }).waitFor();
    assert.ok((await inventory()).every(({ browsersSeen }) => browsersSeen === 0));

    await openApp('claude.ai.example.test');
    await appPage.frameLocator('iframe').getByText(privateDetail).waitFor();
    await openApp('claude.ai');
    await waitUntil(async () => (await inventory())[1].browsersSeen === 1, 'Claude was not recorded.');
    assert.deepEqual(observationAttempts.map(({ appId }) => appId), ['claude']);
    await openApp('chatgpt.com');
    await openApp('gemini.google.com');
    await waitUntil(async () => (await inventory()).every(({ browsersSeen }) => browsersSeen === 1),
      'Expected a browser for each catalog app.');
    assert.equal(observationAttempts.length, 3);
    for (const observation of observationAttempts) {
      assert.deepEqual(Object.keys(observation).sort(), ['appId', 'observedAt', 'policyVersion']);
      assert.equal(observation.policyVersion, discoveryOnVersion);
    }
    assert.ok(!JSON.stringify(observationAttempts).includes(privateDetail));
    await dashboard.getByRole('button', { name: 'Refresh app inventory' }).click();
    await apps.getByRole('row', { name: /Gemini/ }).getByText('1', { exact: true }).waitFor();
    await dashboard.getByLabel('Claude classification', { exact: true }).selectOption('unapproved');
    await dashboard.getByRole('button', { name: 'Save Claude classification' }).click();
    await dashboard.getByText('Claude classification saved.', { exact: true }).waitFor();
    await dashboard.getByLabel('ChatGPT classification', { exact: true }).selectOption('approved');
    await dashboard.getByRole('button', { name: 'Save ChatGPT classification' }).click();
    await dashboard.getByText('ChatGPT classification saved.', { exact: true }).waitFor();
    assert.deepEqual((await inventory()).map(({ status }) => status), ['approved', 'unapproved', 'unreviewed']);
    await screenshot(dashboard, '11-ai-app-inventory.png');
  });

  await t.test('discovery retries a lost acknowledgment and rollback stops subsequent reporting', async () => {
    loseObservationAcknowledgment = true;
    const initialAttempts = observationAttempts.length;
    await openApp('claude.ai');
    await waitUntil(async () => !loseObservationAcknowledgment, 'The proxy did not drop the observation acknowledgment.');
    const committed = (await inventory())[1];
    await sync();
    await waitUntil(async () => observationAttempts.length === initialAttempts + 2, 'The observation was not retried.');
    assert.deepEqual(observationAttempts.slice(-2), Array(2).fill(observationAttempts.at(-1)));
    assert.deepEqual((await inventory())[1], committed);

    await dashboard.getByRole('button', { name: `Restore version ${discoveryOffVersion}`, exact: true }).click();
    await dashboard.getByText(`Version ${discoveryOffVersion} restored as version ${discoveryOnVersion + 1}.`, { exact: true }).waitFor();
    assert.equal(await discoveryMode.inputValue(), 'off');
    await sync();
    await popup.getByText(new RegExp(`Connected to Control · [A-Z]+ v${discoveryOnVersion + 1}$`)).waitFor();
    await openApp('claude.ai');
    await sync();
    assert.equal(observationAttempts.length, initialAttempts + 2);
    assert.deepEqual((await inventory())[1], committed);
  });

  await t.test('live public Gemini blocks click and Enter and sends a reviewed redacted draft', {
    skip: process.env.ZEKVAR_DEMO_LIVE !== '1',
  }, async (live) => {
    const [policy] = await adminGet('policies');
    assert.equal(policy.mode, 'block');
    const page = await browser.newPage();
    try {
      const requests = [];
      page.on('request', (request) => {
        const payload = request.postData();
        if (payload?.includes(marker) && request.url().startsWith('https://gemini.google.com/')) requests.push('marker');
      });
      const response = await page.goto('https://gemini.google.com/app', { waitUntil: 'domcontentloaded', timeout: 15_000 })
        .catch(() => undefined);
      if (!response?.ok()) return live.skip(response ? `Live Gemini returned HTTP ${response.status()}.` : 'Live Gemini was unreachable.');
      const editor = page.getByRole('textbox', { name: 'Enter a prompt for Gemini', exact: true });
      if (!await editor.waitFor({ timeout: 8000 }).then(() => true, () => false)) {
        return live.skip('Signed-out Gemini did not expose its English text composer.');
      }
      const clean = 'Reply with OK. Zekvar synthetic compatibility check. Example: [REDACTED]';
      await editor.fill(clean.replace('[REDACTED]', marker));
      const send = page.locator('input-area-v2').getByRole('button', { name: 'Send message', exact: true });
      await send.waitFor();
      await page.getByText(new RegExp(`^Zekvar · BLOCK v${policy.version}(?: · GitHub PAT [a-z]+)?$`)).waitFor();
      await send.click();
      await page.getByRole('alert').filter({ hasText: 'Submission blocked' }).waitFor();
      await editor.press('Enter');
      await waitUntil(async () => (await adminGet('events?appId=gemini')).filter((entry) =>
        entry.policyVersion === policy.version && entry.decision === 'block').length === 2, 'Control should record both Gemini blocks.');
      assert.deepEqual(requests, []);
      await page.getByRole('button', { name: 'Redact detected values', exact: true }).click();
      await page.getByRole('alert').filter({ hasText: 'Detected values redacted.' }).waitFor();
      assert.equal(await editor.innerText(), clean);
      await screenshot(page, '19-live-gemini-redacted-draft.png');
      await send.click();
      await page.getByText(clean, { exact: true }).last().waitFor();
      await editor.waitFor();
      assert.doesNotMatch(await editor.innerText(), /REDACTED/);
      assert.deepEqual(requests, []);
      assert.equal((await adminGet('events?appId=gemini')).length, 2);

      await dashboard.reload();
      await health.getByRole('columnheader', { name: 'Gemini composer' }).waitFor();
      assert.equal(await health.getByRole('row').nth(1).getByRole('cell').nth(6).getByText('Detected', { exact: true }).count(), 1);
      await dashboard.getByLabel('Application', { exact: true }).selectOption('gemini');
      await dashboard.getByRole('button', { name: 'Apply filters' }).click();
      await rows.getByText('Gemini', { exact: true }).nth(1).waitFor();
      assert.equal(await rows.count(), 2);
      const link = dashboard.getByRole('link', { name: 'Export security events (JSON)' });
      const report = await dashboard.request.get(new URL(await link.getAttribute('href'), web).href);
      assert.ok(report.ok());
      const download = await report.json();
      assert.equal(download.filters.appId, 'gemini');
      assert.deepEqual(download.entries, await adminGet('events?appId=gemini'));
    } finally { await page.close(); }
  });

  const testCard = '4242-4242-4242-4242';
  const cardRule = 'payment-card-number';
  const cardEvents = async () => (await adminGet('events')).filter(({ ruleId }) => ruleId === cardRule);
  await t.test('publishes the payment detector, retries delivery, and handles Off, Monitor, Warn, and Block in Chrome', async () => {
    await dashboard.reload();
    const mode = dashboard.getByLabel('Payment card number', { exact: true });
    assert.equal(await mode.inputValue(), 'off');
    let sends = Number(await submissions.textContent());
    await prompt.fill(testCard);
    await prompt.press('Enter');
    assert.equal(await submissions.textContent(), String(++sends));
    assert.deepEqual(await cardEvents(), []);
    const publish = async (value) => {
      const version = await policyVersion() + 1;
      await mode.selectOption(value);
      await dashboard.getByRole('button', { name: 'Publish policy' }).click();
      await dashboard.getByText(`Version ${version} published in block mode.`, { exact: true }).waitFor();
      await sync();
      await popup.getByText(`Connected to Control · BLOCK v${version}`, { exact: true }).waitFor();
      await prompt.fill(testCard);
      await chat.getByText(new RegExp(`^Zekvar · BLOCK v${version}.* · Payment card ${value}$`)).waitFor();
      return version;
    };
    const monitor = await publish('monitor');
    loseAcknowledgment = true;
    await send.click();
    assert.equal(await submissions.textContent(), String(++sends));
    await waitUntil(() => !loseAcknowledgment, 'The proxy did not drop the payment event acknowledgment.');
    await sync();
    await waitUntil(() => attempts.filter(({ ruleId }) => ruleId === cardRule).length === 2, 'The browser did not replay the payment event.');
    assert.equal(new Set(attempts.filter(({ ruleId }) => ruleId === cardRule).map(({ eventId }) => eventId)).size, 1);
    assert.deepEqual((await cardEvents()).map(({ policyVersion, decision }) => [policyVersion, decision]), [[monitor, 'monitor']]);

    const warn = await publish('warn');
    await prompt.press('Enter');
    await chat.getByRole('alert').filter({ hasText: 'possible payment card number' }).waitFor();
    assert.equal(await submissions.textContent(), String(sends));
    await chat.getByRole('button', { name: 'Continue anyway' }).click();
    assert.equal(await submissions.textContent(), String(++sends));
    await waitUntil(async () => (await cardEvents()).filter(({ policyVersion }) => policyVersion === warn).length === 2,
      'Expected warning and override metadata.');

    const block = await publish('block');
    await worker.evaluate(async () => {
      const { controlState } = await chrome.storage.local.get('controlState');
      delete controlState.policy.paymentCardMode;
      await chrome.storage.local.set({ controlState });
    });
    await sync();
    const cachedMode = () => worker.evaluate(async () => (await chrome.storage.local.get('controlState')).controlState.policy.paymentCardMode);
    await waitUntil(async () => await cachedMode() === 'block', 'The browser did not add the detector to a legacy cache at the same version.');
    const [versionWithoutDetector] = await adminGet('policies');
    delete versionWithoutDetector.paymentCardMode;
    await worker.evaluate((older) => {
      const fetchPolicy = globalThis.fetch;
      globalThis.fetch = (url, options) => {
        if (String(url).endsWith('/v1/browser/policy')) {
          globalThis.fetch = fetchPolicy;
          return Promise.resolve(Response.json(older));
        }
        return fetchPolicy(url, options);
      };
    }, versionWithoutDetector);
    await sync();
    await popup.waitForFunction(() => !document.querySelector('#sync').disabled);
    assert.equal(await cachedMode(), 'block');
    await prompt.fill('Invalid checksum 4242-4242-4242-4243');
    await prompt.press('Enter');
    assert.equal(await submissions.textContent(), String(++sends));
    await prompt.fill(`Marker ${marker}; card ${testCard}; token ${fakePat}.`);
    await send.click();
    await chat.getByRole('alert').filter({ hasText: 'Submission blocked. This prompt contains a possible payment card number.' }).waitFor();
    await chat.getByRole('button', { name: 'Redact detected values' }).click();
    assert.equal(await prompt.inputValue(), 'Marker [REDACTED]; card [REDACTED]; token [REDACTED].');
    assert.equal(await submissions.textContent(), String(sends));
    await prompt.press('Enter');
    assert.equal(await submissions.textContent(), String(++sends));
    await waitUntil(async () => (await cardEvents()).length === 4, 'Expected one payment card block.');
    assert.deepEqual((await cardEvents()).filter(({ policyVersion }) => policyVersion === block).map(({ decision }) => decision), ['block']);
    assert.doesNotMatch(JSON.stringify([...await cardEvents(), ...attempts]), /4242(?:[- ]?4242){3}|REDACTED/);
    await dashboard.reload();
    await dashboard.getByLabel('Application', { exact: true }).selectOption('chatgpt');
    await dashboard.getByRole('button', { name: 'Apply filters' }).click();
    await rows.getByText('Payment card number', { exact: true }).nth(3).waitFor();
  });

  for (const site of [
    { appId: 'chatgpt', name: 'ChatGPT', url: 'https://chatgpt.com/',
      editor: 'textarea[placeholder="Ask ChatGPT"]:visible, #prompt-textarea:visible, [data-testid="prompt-textarea"]:visible', method: 'enter' },
    { appId: 'gemini', name: 'Gemini', url: 'https://gemini.google.com/app',
      editor: 'input-area-v2 [role="textbox"][aria-label="Enter a prompt for Gemini"]:visible', method: 'click' },
  ]) {
    await t.test(`live signed-out ${site.name} keeps the sandbox card out of the sent prompt`, {
      skip: process.env.ZEKVAR_DEMO_LIVE !== '1',
    }, async (live) => {
      const page = await browser.newPage();
      const safe = 'Reply with OK. Zekvar payment detector check. Example: [REDACTED]';
      let leaked = false;
      page.on('request', (request) => {
        const body = request.postData();
        if (body?.includes(testCard) || body?.includes(testCard.replaceAll('-', ''))) leaked = true;
      });
      try {
        const response = await page.goto(site.url, { waitUntil: 'domcontentloaded', timeout: 12_000 }).catch(() => undefined);
        if (!response?.ok()) return live.skip(response ? `Live ${site.name} returned HTTP ${response.status()}.` : `Live ${site.name} was unreachable.`);
        const editor = page.locator(site.editor).first();
        if (!await editor.waitFor({ timeout: 6000 }).then(() => true, () => false)) {
          return live.skip(`Signed-out ${site.name} did not expose a tested text composer.`);
        }
        await editor.fill(safe.replace('[REDACTED]', testCard));
        await page.getByText(/Zekvar · BLOCK v\d+.*Payment card block$/).waitFor();
        const sendLive = page.locator('button[data-testid="send-button"]:visible')
          .or(page.getByRole('button', { name: /^(Send prompt|Send message|Send)$/i }));
        await sendLive.waitFor();
        await waitUntil(() => sendLive.isEnabled(), `Live ${site.name} never enabled Send for the filled draft.`);
        if (site.method === 'click') await sendLive.click();
        else await editor.press('Enter');
        try {
          await page.getByRole('alert').filter({ hasText: 'Submission blocked. This prompt contains a possible payment card number.' }).waitFor();
        } catch (error) {
          await screenshot(page, `20-${site.appId}-payment-block-failure.png`);
          assert.equal(leaked, false, 'The sandbox card appeared in an outgoing browser request.');
          throw error;
        }
        const version = await policyVersion();
        await waitUntil(async () => (await cardEvents()).some(({ appId, policyVersion, decision }) =>
          appId === site.appId && policyVersion === version && decision === 'block'), 'The payment decision did not reach Control.');
        await page.getByRole('button', { name: 'Redact detected values', exact: true }).click();
        await page.getByRole('alert').filter({ hasText: 'Detected values redacted.' }).waitFor();
        assert.equal(await editor.evaluate((element) => element instanceof HTMLTextAreaElement ? element.value : element.innerText), safe);
        await screenshot(page, `20-${site.appId}-payment-redaction.png`);
        if (site.method === 'click') await sendLive.click();
        else await editor.press('Enter');
        await page.getByText(safe, { exact: true }).last().waitFor();
        assert.equal(leaked, false);
      } finally { await page.close(); }
    });
  }

  await t.test('holds matching native file drops on live signed-out ChatGPT and Gemini and reports their methods', {
    skip: process.env.ZEKVAR_DEMO_LIVE !== '1',
  }, async (live) => {
    await dashboard.reload();
    const version = await policyVersion() + 1;
    await dashboard.getByLabel('ChatGPT file uploads', { exact: true }).selectOption('block');
    await dashboard.getByLabel('Gemini file uploads', { exact: true }).selectOption('block');
    await dashboard.getByLabel('ChatGPT file types', { exact: true }).fill('.TXT');
    await dashboard.getByLabel('Gemini file types', { exact: true }).fill('text/*');
    await dashboard.getByRole('button', { name: 'Publish policy' }).click();
    await dashboard.getByText(`Version ${version} published in block mode.`, { exact: true }).waitFor();
    await sync();
    const name = 'synthetic-private-live-upload.txt';
    const content = 'Zekvar synthetic file drop test content';
    const fixtureFile = join(dir, name);
    await writeFile(fixtureFile, content);
    let geminiVerified = false;
    for (const [app, url, editorSelector] of [
      ['chatgpt', 'https://chatgpt.com/', 'textarea[placeholder="Ask ChatGPT"]:visible, #prompt-textarea:visible'],
      ['gemini', 'https://gemini.google.com/app', 'input-area-v2 [role="textbox"][aria-label="Enter a prompt for Gemini"]:visible'],
    ]) {
      await live.test(app, async (site) => {
        const page = await browser.newPage();
        try {
          let fileSent = false;
          page.on('request', (request) => {
            const body = request.postData();
            if (body?.includes(name) || body?.includes(content)) fileSent = true;
          });
          const response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 12_000 }).catch(() => undefined);
          if (!response?.ok()) return site.skip(`The public ${app} route was unavailable.`);
          const editor = page.locator(editorSelector).first();
          if (!await editor.waitFor({ timeout: 6000 }).then(() => true, () => false)) return site.skip('The tested editor was unavailable.');
          await page.getByText(/File uploads block \(selected types\)/).first().waitFor();
          const cdp = await browser.newCDPSession(page);
          try {
            const box = await editor.boundingBox();
            const data = { items: [], files: [fixtureFile], dragOperationsMask: 1 };
            for (const type of ['dragEnter', 'dragOver', 'drop']) {
              await cdp.send('Input.dispatchDragEvent', { type, x: box.x + box.width / 2, y: box.y + box.height / 2, data });
            }
          } finally { await cdp.detach(); }
          await page.getByRole('alert').filter({ hasText: 'File upload blocked by your organization' }).waitFor();
          await waitUntil(async () => (await adminGet(`events?appId=${app}`)).some(({ policyVersion, ruleId, uploadMethod, decision }) =>
            policyVersion === version && ruleId === 'ai-file-upload' && uploadMethod === 'drop' && decision === 'block'),
          'Control did not receive the block.');
          assert.equal(fileSent, false);
          if (app === 'gemini') geminiVerified = true;
          await screenshot(page, `21-${app}-file-drop-blocked.png`);
        } finally { await page.close(); }
      });
    }
    if (!geminiVerified) return;
    await dashboard.reload();
    await dashboard.getByLabel('Application', { exact: true }).selectOption('gemini');
    await dashboard.getByRole('button', { name: 'Apply filters' }).click();
    await rows.getByText('Drag and drop', { exact: true }).first().waitFor();
    const exportLink = dashboard.getByRole('link', { name: 'Export security events (JSON)' });
    const report = await dashboard.request.get(new URL(await exportLink.getAttribute('href'), web).href);
    assert.ok(report.ok());
    const { entries } = await report.json();
    assert.deepEqual(entries.filter(({ policyVersion }) => policyVersion === version).map(({ uploadMethod }) => uploadMethod), ['drop']);
    assert.ok(!JSON.stringify(entries).includes(name) && !JSON.stringify(entries).includes(content));
  });

  const allowedDomains = dashboard.getByLabel('Allowed domains', { exact: true });
  const blockedDomains = dashboard.getByLabel('Blocked domains', { exact: true });
  const allowedPaths = dashboard.getByLabel('Allowed paths', { exact: true });
  const blockedPaths = dashboard.getByLabel('Blocked paths', { exact: true });
  const publishDomains = () => dashboard.getByRole('button', { name: 'Publish navigation rules', exact: true }).click();
  const currentInstallation = async () => (await adminGet('installations'))[0];
  const longestPath = '/' + 'z.-_~9'.repeat(10) + 'abc';
  let beforeDomains;
  let withDomains;
  await t.test('publishes explicit domain rules and Chrome applies the most specific navigation rule', async () => {
    beforeDomains = await policyVersion();
    withDomains = beforeDomains + 1;
    await domains.visit(browser, 'apps.test', false);
    await allowedDomains.fill('WORK.APPS.TEST.\nwork.apps.test');
    await blockedDomains.fill('https://apps.test/');
    await publishDomains();
    await dashboard.getByRole('alert').filter({ hasText: 'Enter up to 50 hostnames' }).waitFor();
    assert.equal(await policyVersion(), beforeDomains);
    assert.equal(await blockedDomains.inputValue(), 'https://apps.test/');
    await blockedDomains.fill(' APPS.TEST \n restricted.work.apps.test ');
    await allowedPaths.fill(' APPS.TEST./public/ \nwork.apps.test/admin/guides');
    await blockedPaths.fill('apps.test/public');
    await publishDomains();
    await dashboard.getByRole('alert').filter({ hasText: 'Enter distinct hostname/path prefixes' }).waitFor();
    assert.equal(await policyVersion(), beforeDomains);
    await blockedPaths.fill(`work.apps.test/admin\nwork.apps.test${longestPath}`);
    await publishDomains();
    await dashboard.getByText(`Navigation rules published as version ${withDomains}.`, { exact: true }).waitFor();
    assert.equal(await allowedDomains.inputValue(), 'work.apps.test');
    assert.equal(await blockedDomains.inputValue(), 'apps.test\nrestricted.work.apps.test');
    assert.equal(await allowedPaths.inputValue(), 'apps.test/public\nwork.apps.test/admin/guides');
    await sync();
    await popup.getByText('Active domain rules: 3', { exact: true }).waitFor();
    assert.equal((await currentInstallation()).appliedPolicyVersion, withDomains);
    for (const host of ['apps.test', 'apps.test.', 'other.apps.test', 'restricted.work.apps.test', 'redirect.test']) {
      await domains.visit(browser, host, true);
    }
    for (const host of ['work.apps.test', 'work.apps.test.', 'notapps.test', 'apps.test.other.test']) {
      await domains.visit(browser, host, false);
    }
    await dashboard.getByText('1 allow · 2 block domains', { exact: true }).first().click();
  });

  await t.test('Chrome applies path prefixes with label, segment, case and redirect boundaries', async () => {
    await popup.getByText('Active path rules: 4', { exact: true }).waitFor();
    for (const [host, path, blocked] of [
      ['apps.test', '/public', false],
      ['apps.test.', '/public/team/#intro', false],
      ['apps.test', '/publicity', true],
      ['apps.test', '/Public', true],
      ['apps.test', '/public/team%2fnotes', true],
      ['work.apps.test', '/admin', true],
      ['work.apps.test', '/admin/users', true],
      ['work.apps.test', '/admin%2fusers', true],
      ['work.apps.test', '/admin;section', true],
      ['work.apps.test', '/Admin', false],
      ['work.apps.test', '/administrator', false],
      ['work.apps.test', '/admin/guides', false],
      ['work.apps.test', '/admin/guides-v2', true],
      ['restricted.work.apps.test', '/admin/guides', true],
      ['work.apps.test', longestPath, true],
      ['redirect.test', '/public', false],
      ['redirect.test', '/private', true],
    ]) await domains.visit(browser, host, blocked, path);
    assert.ok(!JSON.stringify([...observationAttempts, ...attempts]).includes('private-navigation'));
    await dashboard.getByText('2 allow · 2 block paths', { exact: true }).first().click();
    await screenshot(dashboard, '12-control-domain-rules.png');
  });

  await t.test('retains enforcement offline and acknowledges rollback only after replacing Chrome rules', async () => {
    offline = true;
    try {
      await sync();
      await popup.getByText(new RegExp(`Control offline · [A-Z]+ v${withDomains}$`)).waitFor();
      await domains.visit(browser, 'apps.test', true);
      await domains.visit(browser, 'work.apps.test', true, '/admin');
      await domains.visit(browser, 'work.apps.test', false);
    } finally { offline = false; }

    await dashboard.getByRole('button', { name: `Restore version ${beforeDomains}`, exact: true }).click();
    const restored = withDomains + 1;
    await dashboard.getByText(`Version ${beforeDomains} restored as version ${restored}.`, { exact: true }).waitFor();
    await worker.evaluate(() => {
      const api = chrome.declarativeNetRequest;
      globalThis.restoreDomainUpdate = () => { api.updateDynamicRules = globalThis.originalDomainUpdate; };
      globalThis.originalDomainUpdate = api.updateDynamicRules;
      api.updateDynamicRules = async () => { throw new Error('Synthetic browser rule update failure'); };
    });
    try {
      await sync();
      await popup.getByText(new RegExp(`Policy update pending · [A-Z]+ v${withDomains}$`)).waitFor();
      assert.equal((await currentInstallation()).appliedPolicyVersion, withDomains);
      await domains.visit(browser, 'apps.test', true);
      await domains.visit(browser, 'work.apps.test', true, '/admin');
    } finally {
      await worker.evaluate(() => globalThis.restoreDomainUpdate());
    }
    await sync();
    await popup.getByText(new RegExp(`Connected to Control · [A-Z]+ v${restored}$`)).waitFor();
    assert.equal((await currentInstallation()).appliedPolicyVersion, restored);
    await domains.visit(browser, 'apps.test', false);
    await domains.visit(browser, 'work.apps.test', false, '/admin');
  });

  await t.test('revoking enrollment removes active domain rules', async () => {
    await blockedDomains.fill('apps.test');
    await blockedPaths.fill('work.other.test/private');
    await publishDomains();
    await dashboard.getByText(`Navigation rules published as version ${withDomains + 2}.`, { exact: true }).waitFor();
    await sync();
    await popup.getByText('Active domain rules: 1', { exact: true }).waitFor();
    await domains.visit(browser, 'apps.test', true);
    await domains.visit(browser, 'work.other.test', true, '/private');
    const { installationId } = await currentInstallation();
    dashboard.once('dialog', (dialog) => dialog.accept());
    await dashboard.getByRole('button', { name: `Revoke installation ${installationId}`, exact: true }).click();
    await health.getByText('Revoked', { exact: true }).waitFor();
    await sync();
    await popup.getByText(/Control access revoked/).waitFor();
    await domains.visit(browser, 'apps.test', false);
    await domains.visit(browser, 'work.other.test', false, '/private');
  });
});
