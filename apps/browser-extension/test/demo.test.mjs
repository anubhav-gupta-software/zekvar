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
  const discoveryMode = dashboard.getByLabel('AI app discovery', { exact: true });
  const apps = dashboard.getByRole('table', { name: 'AI apps' });
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
    await dashboard.getByRole('button', { name: 'Refresh AI apps' }).click();
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

  const allowedDomains = dashboard.getByLabel('Allowed domains', { exact: true });
  const blockedDomains = dashboard.getByLabel('Blocked domains', { exact: true });
  const publishDomains = () => dashboard.getByRole('button', { name: 'Publish domain rules', exact: true }).click();
  const currentInstallation = async () => (await adminGet('installations'))[0];
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
    await publishDomains();
    await dashboard.getByText(`Domain rules published as version ${withDomains}.`, { exact: true }).waitFor();
    assert.equal(await allowedDomains.inputValue(), 'work.apps.test');
    assert.equal(await blockedDomains.inputValue(), 'apps.test\nrestricted.work.apps.test');
    await sync();
    await popup.getByText('Active domain rules: 3', { exact: true }).waitFor();
    assert.equal((await currentInstallation()).appliedPolicyVersion, withDomains);
    for (const host of ['apps.test', 'apps.test.', 'other.apps.test', 'restricted.work.apps.test', 'redirect.test']) {
      await domains.visit(browser, host, true);
    }
    for (const host of ['work.apps.test', 'work.apps.test.', 'notapps.test', 'apps.test.other.test']) {
      await domains.visit(browser, host, false);
    }
    assert.ok(!JSON.stringify([...observationAttempts, ...attempts]).includes('private-navigation-'));
    await dashboard.getByText('1 allow · 2 block', { exact: true }).first().click();
    await screenshot(dashboard, '12-control-domain-rules.png');
  });

  await t.test('retains enforcement offline and acknowledges rollback only after replacing Chrome rules', async () => {
    offline = true;
    try {
      await sync();
      await popup.getByText(new RegExp(`Control offline · [A-Z]+ v${withDomains}$`)).waitFor();
      await domains.visit(browser, 'apps.test', true);
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
    } finally {
      await worker.evaluate(() => globalThis.restoreDomainUpdate());
    }
    await sync();
    await popup.getByText(new RegExp(`Connected to Control · [A-Z]+ v${restored}$`)).waitFor();
    assert.equal((await currentInstallation()).appliedPolicyVersion, restored);
    await domains.visit(browser, 'apps.test', false);
  });

  await t.test('revoking enrollment removes active domain rules', async () => {
    await blockedDomains.fill('apps.test');
    await publishDomains();
    await dashboard.getByText(`Domain rules published as version ${withDomains + 2}.`, { exact: true }).waitFor();
    await sync();
    await popup.getByText('Active domain rules: 1', { exact: true }).waitFor();
    await domains.visit(browser, 'apps.test', true);
    const { installationId } = await currentInstallation();
    dashboard.once('dialog', (dialog) => dialog.accept());
    await dashboard.getByRole('button', { name: `Revoke installation ${installationId}`, exact: true }).click();
    await health.getByText('Revoked', { exact: true }).waitFor();
    await sync();
    await popup.getByText(/Control access revoked/).waitFor();
    await domains.visit(browser, 'apps.test', false);
  });
});
