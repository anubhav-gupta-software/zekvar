import { readBrowserState, writeBrowserState } from './browser-state.mjs';
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
import { fixtureUrl } from '../fixture/server.mjs';

const origin = process.env.ZEKVAR_EXTENSION_TEST_API;
const admin = process.env.ZEKVAR_EXTENSION_TEST_ADMIN_TOKEN;
assert.match(origin ?? '', /^http:\/\/127\.0\.0\.1:\d+$/, 'Set ZEKVAR_EXTENSION_TEST_API to a loopback API origin.');
assert.match(admin ?? '', /^[a-f0-9]{64}$/, 'Set ZEKVAR_EXTENSION_TEST_ADMIN_TOKEN for a disposable organization.');
const fixture = await readFile(new URL('../fixture/index.html', import.meta.url), 'utf8');
const chatGptFixture = await readFile(new URL('./chatgpt-composer.html', import.meta.url), 'utf8');
const guestComposerFixture = await readFile(new URL('./guest-chatgpt-composer.html', import.meta.url), 'utf8');
const geminiComposerFixture = await readFile(new URL('./gemini-composer.html', import.meta.url), 'utf8');
const uploadFixture = await readFile(new URL('./upload-composer.html', import.meta.url), 'utf8');
const { version: extensionVersion } = JSON.parse(await readFile(new URL('../manifest.json', import.meta.url), 'utf8'));
const marker = 'ZEKVAR_TEST_SECRET';

async function adminCall(path, body) {
  const response = await fetch(`${origin}/v1/admin/${path}`, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { Authorization: `Bearer ${admin}`, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(5000),
  });
  assert.ok(response.ok, `Control admin call ${path} returned ${response.status}`);
  return response.status === 204 ? undefined : response.json();
}

// Poll the real condition. The deadline only bounds a genuine failure; a loaded machine must not turn a slow
// round trip (Chrome worker, proxy, Control) into a false failure.
async function until(check, explanation, deadlineMs = 30_000) {
  const end = Date.now() + deadlineMs;
  while (Date.now() < end) {
    if (await check()) return;
    await delay(100);
  }
  assert.fail(explanation);
}

// The extension worker bounds each Control request to 3.5 s and reports offline when one is slow, so a loaded
// machine can legitimately skip one delivery pass. Syncing again is what an operator does; repeat until the condition holds.
async function syncUntil(popup, check, explanation) {
  for (let pass = 0; pass < 5; pass++) {
    await popup.getByRole('button', { name: 'Sync now' }).click();
    try {
      await until(check, explanation, 10_000);
      return;
    } catch (error) {
      if (pass === 4) throw error;
    }
  }
}

test('Chrome enrolls, applies Control policy, and recovers queued events across restart', { timeout: 60_000 }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'zekvar-browser-control-'));
  const buildPath = join(root, 'extension');
  const profile = join(root, 'profile');
  let browser;
  let popup;
  let page;
  let worker;
  let offline = false;
  let stalePolicy;
  let staleResponses = 0;
  let loseNextAcknowledgment = false;
  const posts = [];

  const proxy = createServer(async (request, response) => {
    try {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      if (request.url === '/v1/browser/events') posts.push(JSON.parse(body.toString()));
      if (offline) return response.writeHead(503).end();
      if (stalePolicy && request.url === '/v1/browser/policy') {
        staleResponses++;
        return response.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify(stalePolicy));
      }
      if (!request.url?.startsWith('/v1/browser/') && request.url !== '/v1/enroll') return response.writeHead(404).end();
      const upstream = await fetch(`${origin}${request.url}`, {
        method: request.method,
        headers: {
          ...(request.headers.authorization ? { Authorization: request.headers.authorization } : {}),
          ...(request.headers['x-zekvar-assignment-aware'] ? { 'X-Zekvar-Assignment-Aware': request.headers['x-zekvar-assignment-aware'] } : {}),
          ...(request.headers['x-zekvar-composer-coverage'] ? { 'X-Zekvar-Composer-Coverage': request.headers['x-zekvar-composer-coverage'] } : {}),
          ...(request.headers['x-zekvar-private-key'] ? { 'X-Zekvar-Private-Key': request.headers['x-zekvar-private-key'] } : {}),
          ...(request.headers['x-zekvar-file-inspection'] ? { 'X-Zekvar-File-Inspection': request.headers['x-zekvar-file-inspection'] } : {}),
          ...(request.headers['x-zekvar-file-content-block'] ? { 'X-Zekvar-File-Content-Block': request.headers['x-zekvar-file-content-block'] } : {}),
          ...(body.length ? { 'Content-Type': 'application/json' } : {}),
        },
        body: body.length ? body : undefined,
      });
      const text = await upstream.text();
      if (loseNextAcknowledgment && request.url === '/v1/browser/events' && upstream.ok) {
        loseNextAcknowledgment = false;
        return response.writeHead(503).end();
      }
      response.writeHead(upstream.status, { 'Content-Type': 'application/json' }).end(text);
    } catch {
      response.writeHead(502).end();
    }
  });
  t.after(async () => {
    try {
      await browser?.close();
    } finally {
      await new Promise((resolve) => proxy.close(resolve));
      await rm(root, { recursive: true, force: true });
    }
  });
  await new Promise((resolve, reject) => {
    proxy.once('error', reject);
    proxy.listen(0, '127.0.0.1', resolve);
  });
  execFileSync(process.execPath, ['build.mjs'], {
    cwd: fileURLToPath(new URL('..', import.meta.url)),
    env: { ...process.env, ZEKVAR_CONTROL_PORT: String(proxy.address().port), ZEKVAR_EXTENSION_OUTDIR: buildPath },
  });

  async function openChrome() {
    browser = await chromium.launchPersistentContext(profile, {
      channel: 'chromium', headless: process.env.ZEKVAR_DEMO_HEADED !== '1',
      args: [`--disable-extensions-except=${buildPath}`, `--load-extension=${buildPath}`],
    });
    browser.setDefaultTimeout(5000);
    await browser.route(fixtureUrl, (route) => route.fulfill({ contentType: 'text/html', body: fixture }));
    worker = browser.serviceWorkers()[0] ?? await browser.waitForEvent('serviceworker');
    const id = new URL(worker.url()).hostname;
    popup = await browser.newPage();
    await popup.goto(`chrome-extension://${id}/popup.html`);
    page = await browser.newPage();
    await page.goto(fixtureUrl);
    await page.locator('form[data-zekvar-ready="true"]').waitFor();
  }

  async function enroll(grant) {
    await popup.getByLabel('Enrollment grant').fill(grant);
    await popup.getByRole('button', { name: 'Enroll this browser' }).click();
  }

  async function blockPrompt(count) {
    await page.getByLabel('Prompt', { exact: true }).fill(marker);
    await page.getByRole('button', { name: 'Send prompt' }).click();
    await page.getByText(/Submission blocked/).waitFor();
    assert.equal(await page.locator('#submission-count').textContent(), String(count));
  }

  await openChrome();
  const initial = (await adminCall('policies'))[0];
  const used = await adminCall('enrollment-grants', {});
  let installationId;
  let policy;
  let chatGpt;
  let chatGptInstallation;

  await t.test('rejects an unavailable grant and redeems a fresh grant', async () => {
    const consumed = await fetch(`${origin}/v1/enroll`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ grant: used.grant }),
    });
    assert.ok(consumed.ok);
    for (const unavailable of [process.env.ZEKVAR_EXTENSION_TEST_EXPIRED_GRANT, used.grant].filter(Boolean)) {
      await enroll(unavailable);
      await popup.getByText(/invalid, expired, or already used/).waitFor();
    }
    const fresh = await adminCall('enrollment-grants', {});
    await enroll(fresh.grant);
    await popup.getByText(/Connected to Control/).waitFor();
    installationId = (await adminCall('installations'))[0].installationId;
    assert.equal(await popup.getByRole('button', { name: 'Enroll this browser' }).count(), 0);
  });

  await t.test('applies the published policy and keeps the higher version when an old response arrives', async () => {
    policy = await adminCall('policies', { mode: 'block' });
    await page.getByRole('button', { name: 'Sync policy' }).click();
    await page.getByText(`Control policy: BLOCK · v${policy.version}`, { exact: true }).waitFor();
    assert.equal(await page.getByLabel('Policy mode', { exact: true }).isDisabled(), true);
    stalePolicy = initial;
    await popup.getByRole('button', { name: 'Sync now' }).click();
    await until(async () => staleResponses > 0 && await popup.getByRole('button', { name: 'Sync now' }).isEnabled(),
      'Chrome did not finish processing the older policy response.');
    stalePolicy = undefined;
    assert.equal(await popup.getByText(`Connected to Control · BLOCK v${policy.version}`, { exact: true }).isVisible(), true);
    assert.equal((await adminCall('installations')).find((row) => row.installationId === installationId).appliedPolicyVersion, policy.version);
    await page.getByLabel('Prompt', { exact: true }).fill('A clean fixture prompt');
    await page.getByRole('button', { name: 'Send prompt' }).click();
    assert.equal(await page.locator('#submission-count').textContent(), '1');
  });

  await t.test('retains a cached policy and event queue when the API goes away and Chrome restarts', async () => {
    loseNextAcknowledgment = true;
    await blockPrompt(1);
    await popup.getByText(/Control offline/).waitFor();
    await popup.getByText('1 queued', { exact: true }).waitFor();
    assert.equal((await adminCall('events')).filter((row) => row.installationId === installationId).length, 1);

    offline = true;
    await browser.close();
    await openChrome();
    await popup.getByText(`Control offline · BLOCK v${policy.version}`, { exact: true }).waitFor();
    await popup.getByText('1 queued', { exact: true }).waitFor();
    await blockPrompt(0);
    await popup.getByText('2 queued', { exact: true }).waitFor();
  });

  await t.test('reconnects with stable IDs and sends metadata only', async () => {
    offline = false;
    await popup.getByRole('button', { name: 'Sync now' }).click();
    await popup.getByText(/Connected to Control/).waitFor();
    const rows = (await adminCall('events')).filter((row) => row.installationId === installationId);
    assert.equal(rows.length, 2);
    assert.equal(new Set(posts.map(({ eventId }) => eventId)).size, 2);
    assert.ok(posts.filter(({ eventId }) => eventId === posts[0].eventId).length >= 2);
    for (const event of posts) {
      assert.deepEqual(Object.keys(event).sort(), ['appId', 'decision', 'detectorCategory', 'eventId', 'policyVersion', 'ruleId', 'timestamp']);
      assert.equal(event.policyVersion, policy.version);
      assert.equal(event.decision, 'block');
      assert.ok(!JSON.stringify(event).includes(marker));
    }
  });

  await t.test('detects revocation, discards pending delivery and asks for a fresh grant', async () => {
    offline = true;
    await popup.getByRole('button', { name: 'Sync now' }).click();
    await popup.getByText(/Control offline/).waitFor();
    await blockPrompt(0);
    await popup.getByText('1 queued', { exact: true }).waitFor();
    await adminCall(`installations/${installationId}/revoke`, {});
    offline = false;
    await popup.getByRole('button', { name: 'Sync now' }).click();
    await popup.getByText(/Control access revoked/).waitFor();
    await popup.getByText('0 queued · 1 discarded', { exact: true }).waitFor();
    await popup.getByRole('button', { name: 'Enroll this browser' }).waitFor();
    assert.equal((await adminCall('events')).filter((row) => row.installationId === installationId).length, 2);
  });

  await t.test('re-enrolls and reports a warning and its override as separate decisions', async () => {
    const warning = await adminCall('policies', { mode: 'warn' });
    const grant = await adminCall('enrollment-grants', {});
    await enroll(grant.grant);
    await page.getByText(`Control policy: WARN · v${warning.version}`, { exact: true }).waitFor();
    const newId = (await adminCall('installations'))[0].installationId;
    chatGptInstallation = newId;
    assert.notEqual(newId, installationId);
    await page.getByLabel('Prompt', { exact: true }).fill(marker);
    await page.getByRole('button', { name: 'Send prompt' }).click();
    assert.equal(await page.locator('#submission-count').textContent(), '0');
    await page.getByRole('button', { name: 'Continue anyway' }).click();
    assert.equal(await page.locator('#submission-count').textContent(), '1');
    await until(async () => {
      const rows = (await adminCall('events')).filter((row) => row.installationId === newId);
      return rows.length === 2 && rows.every((row) => row.policyVersion === warning.version) &&
        rows.map((row) => row.decision).sort().join(',') === 'warn,warn_override';
    }, 'Control did not record the warning and override.');
  });

  await t.test('guards click and Enter on the supported ChatGPT-shaped composer and sends edited text', async () => {
    const block = await adminCall('policies', { mode: 'block' });
    await browser.route('https://chatgpt.com/**', (route) => route.fulfill({ contentType: 'text/html', body: chatGptFixture }));
    chatGpt = await browser.newPage();
    await chatGpt.goto('https://chatgpt.com/');
    await chatGpt.getByText(`Zekvar · BLOCK v${block.version}`, { exact: true }).waitFor();
    const input = chatGpt.getByRole('textbox', { name: 'Message' });
    const clickSend = chatGpt.getByRole('button', { name: 'Fixture send' });
    const submissions = chatGpt.locator('#fixture-sends');

    await input.fill('Clean test prompt');
    await clickSend.click();
    assert.equal(await submissions.textContent(), '1');
    await input.fill(`${marker} sample`);
    await clickSend.click();
    await chatGpt.getByRole('alert').filter({ hasText: 'Submission blocked' }).waitFor();
    await input.press('Enter');
    assert.equal(await submissions.textContent(), '1');
    await input.fill('Edited test prompt');
    await input.press('Enter');
    assert.equal(await submissions.textContent(), '2');

    await until(async () => (await adminCall('events?appId=chatgpt')).length === 2, 'Expected two ChatGPT block events.');
    const rows = await adminCall('events?appId=chatgpt');
    assert.ok(rows.every((row) => row.appId === 'chatgpt' && row.decision === 'block' && row.policyVersion === block.version));
    assert.ok((await adminCall('events?appId=local-prompt-fixture')).every((row) => row.appId === 'local-prompt-fixture'));
    assert.ok(posts.filter(({ appId }) => appId === 'chatgpt').every((event) =>
      JSON.stringify(Object.keys(event).sort()) === JSON.stringify(['appId', 'decision', 'detectorCategory', 'eventId', 'policyVersion', 'ruleId', 'timestamp']) &&
      !JSON.stringify(event).includes(marker)));
  });

  await t.test('reports an unsupported composer and recovers when it returns', async () => {
    const coverage = async () => (await adminCall('installations')).find((row) => row.installationId === chatGptInstallation);
    await until(async () => (await coverage()).chatGptCoverage === 'ready', 'The recognized composer status was not reported.');
    await chatGpt.locator('#prompt-textarea').evaluate((element) => { element.id = 'renamed-composer'; });
    await chatGpt.getByText('Zekvar · Unsupported composer (editable field missing)', { exact: true }).waitFor();
    await until(async () => (await coverage()).chatGptCoverage === 'unsupported', 'The coverage loss was not reported.');
    assert.ok(Number.isFinite(Date.parse((await coverage()).chatGptCheckedAt)));
    await chatGpt.locator('#renamed-composer').evaluate((element) => { element.id = 'prompt-textarea'; });
    await until(async () => (await coverage()).chatGptCoverage === 'ready', 'Recovery was not reported.');
    await chatGpt.goto('https://chatgpt.com/unrelated');
    await chatGpt.getByText('Zekvar · Unsupported ChatGPT page', { exact: true }).waitFor();
  });

  await t.test('keeps a cached composer check from certifying a new policy or a fresh reconnection', async () => {
    const verified = async () => (await adminCall('browser-health')).installations
      .find(({ installationId }) => installationId === chatGptInstallation).composerReadiness.chatgpt.state;
    for (const changesPolicy of [false, true]) {
      await chatGpt.goto('https://chatgpt.com/');
      await until(async () => await verified() === 'detected', 'Control did not confirm the recognized composer.');
      offline = true;
      await chatGpt.locator('#prompt-textarea').evaluate((element) => { element.id = 'renamed-composer'; });
      await chatGpt.getByText('Zekvar · Unsupported composer (editable field missing)', { exact: true }).waitFor();
      await until(async () => (await readBrowserState(worker))?.coveragePending?.coverage === 'unsupported', 'The offline composer check did not reach the extension worker.');
      await chatGpt.close();
      if (changesPolicy) {
        await adminCall('policies', { mode: 'block' });
        assert.equal(await verified(), 'policy_pending');
      } else {
        const state = await readBrowserState(worker);
        state.coveragePending.observedAt -= 61_000;
        await writeBrowserState(worker, state);
      }
      offline = false;
      await popup.getByRole('button', { name: 'Sync now' }).click();
      await popup.getByText(/Connected to Control/).waitFor();
      await until(async () => {
        const state = await readBrowserState(worker);
        return state?.status === 'connected' && state.coveragePending === undefined;
      }, 'The extension did not finish reconciling the offline composer check.');
      if (changesPolicy) await until(async () => await verified() === 'unobserved',
        'Control did not acknowledge the policy without carrying forward the outdated composer check.');
      assert.equal(await verified(), changesPolicy ? 'unobserved' : 'detected');
      chatGpt = await browser.newPage();
    }
    await chatGpt.goto('https://chatgpt.com/');
    await until(async () => await verified() === 'detected', 'A fresh composer check did not restore readiness.');
  });

  await t.test('allows one ChatGPT warning override for the unchanged draft', async () => {
    const warnPolicy = await adminCall('policies', { mode: 'warn' });
    await chatGpt.goto('https://chatgpt.com/c/fixture-conversation');
    await chatGpt.getByText(`Zekvar · WARN v${warnPolicy.version}`, { exact: true }).waitFor();
    const input = chatGpt.getByRole('textbox', { name: 'Message' });
    const proceed = chatGpt.getByRole('button', { name: 'Continue anyway' });
    await input.fill(marker);
    await input.press('Enter');
    await proceed.waitFor();
    await input.fill(`${marker} edited`);
    assert.equal(await proceed.isVisible(), false);
    await input.press('Enter');
    await proceed.click();
    assert.equal(await chatGpt.locator('#fixture-sends').textContent(), '1');
    await until(async () => {
      const rows = (await adminCall('events?appId=chatgpt')).filter((row) => row.policyVersion === warnPolicy.version);
      return rows.map((row) => row.decision).sort().join(',') === 'warn,warn,warn_override';
    }, 'Expected two warnings and one override for ChatGPT.');
  });

  await t.test('guards an explicitly paired editor and Send control without a form', async () => {
    const policy = await adminCall('policies', { mode: 'block' });
    const alternative = chatGptFixture.replace('<form data-fixture-composer', '<div data-fixture-composer')
      .replace('</form>', '</div>').replace('id="prompt-textarea"', 'id="fixture-editor" data-testid="prompt-textarea"')
      .replace("querySelector('#prompt-textarea')", "querySelector('[data-testid=prompt-textarea]')")
      .replace('type="submit" data-testid="send-button"', 'type="button" id="composer-submit-button" aria-label="Send prompt"');
    await browser.route('https://chatgpt.com/c/fixture-alt?case=*', (route) =>
      route.fulfill({ contentType: 'text/html', body: alternative }));
    await chatGpt.goto('https://chatgpt.com/c/fixture-alt?case=private-option');
    await chatGpt.getByText(`Zekvar · BLOCK v${policy.version}`, { exact: true }).waitFor();
    const input = chatGpt.getByRole('textbox', { name: 'Message' });
    const sendButton = chatGpt.getByRole('button', { name: 'Send prompt' });
    await input.fill('Clean test');
    await sendButton.click();
    assert.equal(await chatGpt.locator('#fixture-sends').textContent(), '1');
    await input.fill(marker);
    await sendButton.click();
    await chatGpt.getByRole('alert').filter({ hasText: 'Submission blocked' }).waitFor();
    await input.press('Enter');
    assert.equal(await chatGpt.locator('#fixture-sends').textContent(), '1');
    await until(async () => (await adminCall('events?appId=chatgpt')).filter((row) => row.policyVersion === policy.version).length === 2,
      'Expected two block events from the paired controls.');

    await browser.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: 'https://chatgpt.com' });
    await chatGpt.getByRole('button', { name: 'Copy composer diagnostics' }).click();
    await chatGpt.getByRole('button', { name: 'Diagnostics copied' }).waitFor();
    const diagnostics = await chatGpt.evaluate(() => navigator.clipboard.readText());
    assert.doesNotMatch(diagnostics, /ZEKVAR_TEST_SECRET|fixture-alt|private-option/);
    assert.deepEqual(JSON.parse(diagnostics), {
      version: extensionVersion, route: 'conversation', markedEditors: 1, visibleMarkedEditors: 1,
      hasEditorForm: false, visibleTextareas: 0, visibleEditableRoots: 1,
      hasComposerSubmitId: true, hasSendTestId: false, hasLabeledSend: true, hasPairedSend: true,
    });
  });

  await t.test('protects guest conversations after in-tab navigation and direct load', async () => {
    const [policy] = await adminCall('policies');
    const baseline = (await adminCall('events?appId=chatgpt')).length;
    const guest = '/uc/00000000-1234-4321-8765-0123456789ab';
    const input = chatGpt.getByRole('textbox', { name: 'Message' });
    const badge = chatGpt.getByText(`Zekvar · BLOCK v${policy.version}`, { exact: true });
    const submissions = chatGpt.locator('#fixture-sends');
    await chatGpt.goto('https://chatgpt.com/');
    await badge.waitFor();
    await chatGpt.evaluate((path) => history.pushState({}, '', path), guest);
    await input.fill(marker);
    await input.press('Enter');
    await chatGpt.getByRole('alert').filter({ hasText: 'Submission blocked' }).waitFor();
    assert.equal(await submissions.textContent(), '0');

    await chatGpt.goto(`https://chatgpt.com${guest}`);
    await badge.waitFor();
    await input.fill(marker);
    await chatGpt.getByRole('button', { name: 'Fixture send' }).click();
    await chatGpt.getByRole('alert').filter({ hasText: 'Submission blocked' }).waitFor();
    assert.equal(await submissions.textContent(), '0');
    await input.fill('Clean reply');
    await input.press('Enter');
    assert.equal(await submissions.textContent(), '1');
    await until(async () => (await adminCall('events?appId=chatgpt')).length === baseline + 2,
      'Both guest-route blocks should reach Control.');

    await chatGpt.getByRole('button', { name: 'Copy composer diagnostics' }).click();
    await chatGpt.getByRole('button', { name: 'Diagnostics copied' }).waitFor();
    const diagnostics = await chatGpt.evaluate(() => navigator.clipboard.readText());
    assert.equal(JSON.parse(diagnostics).route, 'guest-conversation');
    assert.ok(!diagnostics.includes(guest));
  });

  await t.test('pairs a labeled guest textarea without IDs and ignores an unrelated form', async () => {
    const [policy] = await adminCall('policies');
    const baseline = (await adminCall('events?appId=chatgpt')).length;
    const url = 'https://chatgpt.com/?layout=guest-textarea';
    await browser.route(url, (route) => route.fulfill({ contentType: 'text/html', body: guestComposerFixture }));
    await chatGpt.goto(url);
    await chatGpt.getByText(/Waiting for Send control/).waitFor();
    const input = chatGpt.getByPlaceholder('Ask ChatGPT', { exact: true });
    const send = chatGpt.getByRole('button', { name: 'Send message', exact: true });
    await input.fill(marker);
    await chatGpt.getByText(`Zekvar · BLOCK v${policy.version}`, { exact: true }).waitFor();
    await send.click();
    await chatGpt.getByRole('alert').filter({ hasText: 'Submission blocked' }).waitFor();
    await input.press('Enter');
    assert.equal(await chatGpt.locator('#fixture-sends').textContent(), '0');

    await chatGpt.getByRole('textbox', { name: 'Account field' }).fill(marker);
    await chatGpt.getByRole('button', { name: 'Submit form' }).click();
    assert.equal(await chatGpt.locator('#unrelated-sends').textContent(), '1');
    await input.fill('Clean draft');
    await input.press('Enter');
    assert.equal(await chatGpt.locator('#fixture-sends').textContent(), '1');
    await until(async () => (await adminCall('events?appId=chatgpt')).length === baseline + 2,
      'Only the two matching prompt attempts should reach Control.');
  });

  await t.test('redacts a blocked multiline editor draft as one recoverable edit and requires a separate send', async () => {
    const policy = await adminCall('policies', { mode: 'block', githubPatMode: 'monitor' });
    await popup.getByRole('button', { name: 'Sync now' }).click();
    await chatGpt.goto('https://chatgpt.com/c/redaction-fixture');
    await chatGpt.getByText(`Zekvar · BLOCK v${policy.version} · GitHub PAT monitor`, { exact: true }).waitFor();
    const input = chatGpt.getByRole('textbox', { name: 'Message' });
    const send = chatGpt.getByRole('button', { name: 'Fixture send' });
    const redaction = chatGpt.getByRole('button', { name: 'Redact detected values', exact: true });
    const review = chatGpt.getByRole('alert').filter({ hasText: 'Detected values redacted.' });
    const submissions = chatGpt.locator('#fixture-sends');
    const pat = 'ghp_' + 'r'.repeat(36);
    const secondPat = 'ghp_' + 'k'.repeat(36);
    const embeddedPat = 'prefix_' + pat + '_suffix';
    const original = `Review this synthetic draft: ${marker}\nCredentials: "${pat}" and ${secondPat}. Preserve ${embeddedPat}.`;
    const expected = `Review this synthetic draft: [REDACTED]\nCredentials: "[REDACTED]" and [REDACTED]. Preserve ${embeddedPat}.`;
    await input.fill(original);
    await send.click();
    await redaction.waitFor();
    assert.equal(await chatGpt.getByRole('button', { name: 'Continue anyway' }).count(), 0);
    await redaction.evaluate((button) => button.click());
    assert.equal(await input.innerText(), original);
    await redaction.click();
    await review.waitFor();
    assert.equal(await input.innerText(), expected);
    assert.equal(await submissions.textContent(), '0');
    await input.press('ControlOrMeta+z');
    assert.equal(await input.innerText(), original);
    await input.press('Enter');
    await redaction.click();
    await review.waitFor();
    await input.press('Enter');
    assert.equal(await submissions.textContent(), '1');
    assert.equal(await submissions.getAttribute('data-last-draft'), expected);

    await input.evaluate((editor, value) => {
      const emphasis = document.createElement('strong');
      emphasis.textContent = value;
      editor.replaceChildren(emphasis);
    }, marker);
    await send.click();
    await chatGpt.getByRole('alert').filter({ hasText: 'Submission blocked' }).waitFor();
    assert.equal(await redaction.count(), 0);
    assert.equal(await input.locator('strong').textContent(), marker);
    assert.equal(await submissions.textContent(), '1');
    await until(async () => (await adminCall('events?appId=chatgpt')).filter((entry) => entry.policyVersion === policy.version).length === 3,
      'Control should record the blocked attempts only.');
    assert.doesNotMatch(JSON.stringify(posts), new RegExp(`${marker}|${pat}|${secondPat}|REDACTED`));
  });

  await t.test('redacts a warned guest textarea draft and invalidates stale draft and policy actions', async () => {
    const policy = await adminCall('policies', { mode: 'warn', githubPatMode: 'off' });
    await popup.getByRole('button', { name: 'Sync now' }).click();
    await chatGpt.goto('https://chatgpt.com/?layout=guest-textarea');
    const input = chatGpt.getByPlaceholder('Ask ChatGPT', { exact: true });
    const submit = chatGpt.getByRole('button', { name: 'Send message', exact: true });
    const redact = chatGpt.getByRole('button', { name: 'Redact detected values', exact: true });
    const proceed = chatGpt.getByRole('button', { name: 'Continue anyway', exact: true });
    const submissions = chatGpt.locator('#fixture-sends');
    const disabledPat = 'ghp_' + 'x'.repeat(36);
    const edited = `Keep this draft.\n${marker} and ${disabledPat}`;
    await input.fill(marker);
    await chatGpt.getByText(`Zekvar · WARN v${policy.version}`, { exact: true }).waitFor();
    await submit.click();
    await proceed.waitFor();
    await input.evaluate((field, value) => { field.value = value; }, edited);
    await redact.click();
    assert.equal(await input.inputValue(), edited);
    assert.equal(await submissions.textContent(), '0');

    await submit.click();
    await redact.waitFor();
    const tightened = await adminCall('policies', { mode: 'warn', githubPatMode: 'block' });
    await popup.getByRole('button', { name: 'Sync now' }).click();
    await chatGpt.getByText(`Zekvar · WARN v${tightened.version} · GitHub PAT block`, { exact: true }).waitFor();
    assert.equal(await redact.count(), 0);
    assert.equal(await input.inputValue(), edited);
    await submit.click();
    await redact.waitFor();
    assert.equal(await proceed.count(), 0);
    await redact.click();
    await chatGpt.getByRole('alert').filter({ hasText: 'Detected values redacted.' }).waitFor();
    const expected = 'Keep this draft.\n[REDACTED] and [REDACTED]';
    assert.equal(await input.inputValue(), expected);
    assert.equal(await submissions.textContent(), '0');
    await submit.click();
    assert.equal(await submissions.textContent(), '1');
    assert.equal(await submissions.getAttribute('data-last-draft'), expected);

    const markerOnly = await adminCall('policies', { mode: 'warn', githubPatMode: 'off' });
    await popup.getByRole('button', { name: 'Sync now' }).click();
    await input.fill(edited);
    await chatGpt.getByText(`Zekvar · WARN v${markerOnly.version}`, { exact: true }).waitFor();
    await input.press('Enter');
    await proceed.waitFor();
    await redact.click();
    await chatGpt.getByRole('alert').filter({ hasText: 'Detected values redacted.' }).waitFor();
    assert.equal(await input.inputValue(), `Keep this draft.\n[REDACTED] and ${disabledPat}`);
    assert.equal(await submissions.textContent(), '1');
    await input.press('Enter');
    assert.equal(await submissions.textContent(), '2');
    await until(async () => {
      const rows = (await adminCall('events?appId=chatgpt')).filter((entry) => entry.policyVersion >= policy.version);
      return rows.length === 4 && rows.filter((entry) => entry.decision === 'warn').length === 3 &&
        rows.some((entry) => entry.policyVersion === tightened.version && entry.decision === 'block');
    }, 'Control should record the warnings and block without warning overrides.');
    assert.doesNotMatch(JSON.stringify(posts), new RegExp(`${marker}|${disabledPat}|REDACTED`));
  });

  await t.test('protects Gemini sends, isolates coverage, and clears an ambiguous composer', async () => {
    const block = await adminCall('policies', { mode: 'block', githubPatMode: 'monitor' });
    await popup.getByRole('button', { name: 'Sync now' }).click();
    const gemini = await browser.newPage();
    try {
      await gemini.route('https://gemini.google.com/**', (route) => route.fulfill({ contentType: 'text/html', body: geminiComposerFixture }));
      await gemini.goto('https://gemini.google.com/app');
      const coverage = async () => (await adminCall('installations'))[0];
      const input = gemini.getByRole('textbox', { name: 'Enter a prompt for Gemini', exact: true });
      const send = gemini.locator('input-area-v2').getByRole('button', { name: 'Send message' });
      const submissions = gemini.locator('#fixture-sends');
      const protectedText = 'Fixture private prompt ' + marker;
      const label = `Zekvar · BLOCK v${block.version} · GitHub PAT monitor`;
      await gemini.getByText(`${label} · Waiting for Send control`, { exact: true }).waitFor();
      assert.equal((await coverage()).geminiCoverage, null);
      await input.fill(protectedText);
      await gemini.getByText(label, { exact: true }).waitFor();
      await until(async () => (await coverage()).geminiCoverage === 'ready', 'Gemini did not report ready coverage.');
      const originalChatGptCoverage = (await coverage()).chatGptCoverage;
      await send.click();
      await gemini.getByRole('alert').filter({ hasText: 'Submission blocked' }).waitFor();
      await input.press('Enter');
      assert.equal(await submissions.textContent(), '0');
      await gemini.locator('#unrelated-send').click();
      assert.equal(await gemini.locator('#unrelated-sends').textContent(), '1');
      await gemini.getByRole('button', { name: 'Redact detected values' }).click();
      await gemini.getByText('Detected values redacted. Review the updated draft before sending.', { exact: true }).waitFor();
      assert.equal(await submissions.textContent(), '0');
      await input.press('Enter');
      assert.equal(await submissions.getAttribute('data-last-draft'), 'Fixture private prompt [REDACTED]');
      assert.equal(await submissions.textContent(), '1');
      const rows = () => adminCall('events?appId=gemini');
      await until(async () => (await rows()).length === 2, 'Both Gemini block events should reach Control.');
      assert.ok((await rows()).every(({ appId, policyVersion, decision }) =>
        appId === 'gemini' && policyVersion === block.version && decision === 'block'));

      await input.fill(protectedText);
      await send.evaluate((button) => {
        const duplicate = button.cloneNode(true);
        duplicate.id = 'duplicate-send';
        button.after(duplicate);
      });
      await gemini.getByText('Zekvar · Unsupported composer (multiple Send controls)', { exact: true }).waitFor();
      await until(async () => (await coverage()).geminiCoverage === 'unsupported', 'Gemini did not report ambiguous pairing.');
      assert.equal((await coverage()).chatGptCoverage, originalChatGptCoverage);
      await gemini.locator('#duplicate-send').evaluate((button) => button.remove());
      await until(async () => (await coverage()).geminiCoverage === 'ready', 'Gemini did not report recovery.');

      const warn = await adminCall('policies', { mode: 'warn' });
      await popup.getByRole('button', { name: 'Sync now' }).click();
      await gemini.evaluate(() => history.pushState({}, '', '/app/0123456789abcdef'));
      await gemini.getByText(`Zekvar · WARN v${warn.version} · GitHub PAT monitor`, { exact: true }).waitFor();
      await send.click();
      await gemini.getByRole('button', { name: 'Continue anyway' }).click();
      assert.equal(await submissions.textContent(), '2');
      await until(async () => (await rows()).filter(({ policyVersion }) => policyVersion === warn.version).length === 2,
        'Gemini should record the warning and its override once.');
      assert.deepEqual((await rows()).filter(({ policyVersion }) => policyVersion === warn.version).map(({ decision }) => decision).sort(),
        ['warn', 'warn_override']);

      const monitor = await adminCall('policies', { mode: 'monitor' });
      await popup.getByRole('button', { name: 'Sync now' }).click();
      await input.fill(protectedText);
      await gemini.getByText(`Zekvar · MONITOR v${monitor.version} · GitHub PAT monitor`, { exact: true }).waitFor();
      await send.click();
      assert.equal(await submissions.textContent(), '3');
      await until(async () => (await rows()).some(({ policyVersion, decision }) => policyVersion === monitor.version && decision === 'monitor'),
        'Gemini did not report the monitored attempt.');
      await gemini.evaluate(() => history.pushState({}, '', '/privacy'));
      await gemini.getByText('Zekvar · Unsupported Gemini page', { exact: true }).waitFor();
      assert.doesNotMatch(JSON.stringify(posts), /Fixture private prompt|ZEKVAR_TEST_SECRET|\[REDACTED\]/);
    } finally { await gemini.close(); }
  });

  await t.test('applies per-app controls to native picker, drop, and clipboard file events', async () => {
    const [original] = await adminCall('policies');
    assert.deepEqual(original.uploadModes, { chatgpt: 'off', gemini: 'off' });
    const localFiles = [join(root, 'fixture-private-name.txt'), join(root, 'fixture-second.txt')];
    await Promise.all(localFiles.map((file) => writeFile(file, 'Synthetic private attachment contents.')));
    const chat = await browser.newPage();
    const gemini = await browser.newPage();
    const rows = async () => (await adminCall('events')).filter(({ ruleId }) => ruleId === 'ai-file-upload');
    const observed = (page) => page.evaluate(() => window.fileEvents);
    const input = (page) => page.getByLabel('Attach fixture files');
    const pasteTarget = (page) => page.getByLabel('Fixture text', { exact: true });
    const pick = async (page, files = localFiles) => {
      const chooser = page.waitForEvent('filechooser');
      await input(page).click();
      await (await chooser).setFiles(files);
    };
    const drag = async (page, target = page.locator('#drop-zone'), files = localFiles) => {
      const cdp = await browser.newCDPSession(page);
      try {
        const box = await target.boundingBox();
        const data = { items: [], files, dragOperationsMask: 1 };
        for (const type of ['dragEnter', 'dragOver', 'drop']) {
          await cdp.send('Input.dispatchDragEvent', { type, x: box.x + 10, y: box.y + 10, data });
        }
      } finally { await cdp.detach(); }
    };
    const pasteFile = async (page) => {
      await page.bringToFront();
      await page.evaluate(async () => {
        const canvas = document.createElement('canvas');
        canvas.width = canvas.height = 2;
        const data = await new Promise((done) => canvas.toBlob(done, 'image/png'));
        await navigator.clipboard.write([new ClipboardItem({ 'image/png': data })]);
      });
      await pasteTarget(page).press('ControlOrMeta+v');
    };
    try {
      const destinations = [[chat, 'https://chatgpt.com/'], [gemini, 'https://gemini.google.com/app']];
      for (const [page, url] of destinations) {
        await page.route(`${new URL(url).origin}/**`, (route) => route.fulfill({ contentType: 'text/html', body: uploadFixture }));
        await browser.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: new URL(url).origin });
        await page.goto(url);
      }
      await pick(chat);
      assert.deepEqual(await observed(chat), [['input', 2], ['change', 2]]);
      await input(chat).setInputFiles([]);
      assert.deepEqual(await rows(), []);

      const policy = await adminCall('policies', { uploadModes: { chatgpt: 'monitor', gemini: 'block' } });
      await popup.getByRole('button', { name: 'Sync now' }).click();
      await chat.getByText(new RegExp(` v${policy.version}.*File uploads monitor$`)).waitFor();
      await gemini.getByText(new RegExp(` v${policy.version}.*File uploads block$`)).waitFor();
      await pick(chat);
      await drag(chat);
      await pasteFile(chat);
      assert.deepEqual((await observed(chat)).slice(2), [['input', 2], ['change', 2], ['drop', 2], ['paste', 1]]);
      await input(chat).setInputFiles([]);
      await drag(chat, input(chat));
      assert.deepEqual((await observed(chat)).slice(6), [['drop', 2], ['input', 2], ['change', 2]]);
      await pick(gemini);
      await gemini.getByRole('alert').filter({ hasText: 'File upload blocked' }).waitFor();
      assert.equal(await input(gemini).evaluate((field) => field.files.length), 0);
      await drag(gemini);
      await pasteFile(gemini);
      assert.deepEqual(await observed(gemini), []);

      await gemini.evaluate(() => navigator.clipboard.writeText('Plain text still works'));
      await pasteTarget(gemini).press('ControlOrMeta+v');
      assert.equal(await pasteTarget(gemini).inputValue(), 'Plain text still works');
      await until(async () => (await rows()).length === 7, 'Control did not record one decision per file attempt.');
      const triples = (await rows()).map(({ appId, decision, uploadMethod }) => [appId, decision, uploadMethod].join('/')).sort();
      assert.deepEqual(triples, ['chatgpt/monitor/drop', 'chatgpt/monitor/drop', 'chatgpt/monitor/paste', 'chatgpt/monitor/picker',
        'gemini/block/drop', 'gemini/block/paste', 'gemini/block/picker']);

      await gemini.evaluate(() => history.pushState({}, '', '/privacy'));
      await gemini.getByText('Zekvar · Unsupported Gemini page', { exact: true }).waitFor();
      await pick(gemini);
      assert.deepEqual(await observed(gemini), [['input', 2], ['change', 2]]);
      assert.equal((await rows()).length, 7);
      await gemini.goto('https://gemini.google.com/app');
      await gemini.getByText(new RegExp(` v${policy.version}.*File uploads block$`)).waitFor();

      offline = true;
      try {
        await popup.getByRole('button', { name: 'Sync now' }).click();
        await gemini.getByText(/File uploads block · Offline policy$/).waitFor();
        await pick(gemini);
        assert.deepEqual(await observed(gemini), []);
        assert.equal((await rows()).length, 7);
      } finally { offline = false; }
      loseNextAcknowledgment = true;
      await syncUntil(popup, () => !loseNextAcknowledgment, 'The proxy did not drop the queued upload acknowledgment.');
      const lostEventId = posts.at(-1).eventId;
      await syncUntil(popup, () => posts.filter(({ eventId }) => eventId === lostEventId).length >= 2, 'The browser did not retry the upload metadata.');
      assert.equal((await rows()).length, 8);
      assert.doesNotMatch(JSON.stringify([...posts, ...await rows()]), /fixture-private-name|fixture-second|Synthetic private attachment|Plain text still works/);

      const pdf = join(root, 'private-mixed-case.PdF');
      const report = join(root, 'private-allowed.pdf.txt');
      const archive = join(root, 'private-archive.TAR.GZ');
      await Promise.all([pdf, report, archive].map((file) => writeFile(file, 'Synthetic scoped file contents')));
      const scoped = await adminCall('policies', { uploadTypes: { gemini: ['.pdf', 'image/png'], chatgpt: ['.tar.gz', 'image/*'] } });
      await popup.getByRole('button', { name: 'Sync now' }).click();
      await gemini.getByText(new RegExp(` v${scoped.version}.*File uploads block \\(selected types\\)$`)).waitFor();
      await chat.getByText(new RegExp(` v${scoped.version}.*File uploads monitor \\(selected types\\)$`)).waitFor();
      const scopedRows = async () => (await rows()).filter(({ policyVersion }) => policyVersion === scoped.version);
      const priorChatActions = (await observed(chat)).length;
      await pick(chat, [report]);
      await pick(chat, [archive]);
      await input(chat).setInputFiles([]);
      await drag(chat, input(chat), [archive]);
      await pasteFile(chat);
      assert.deepEqual((await observed(chat)).slice(priorChatActions),
        [['input', 1], ['change', 1], ['input', 1], ['change', 1], ['drop', 1], ['input', 1], ['change', 1], ['paste', 1]]);

      await pick(gemini, [report, pdf]);
      await gemini.getByRole('alert').filter({ hasText: 'File upload blocked' }).waitFor();
      assert.equal(await input(gemini).evaluate((field) => field.files.length), 0);
      await drag(gemini, input(gemini), [pdf]);
      await pasteFile(gemini);
      assert.deepEqual(await observed(gemini), []);
      await pick(gemini, [report]);
      assert.deepEqual(await observed(gemini), [['input', 1], ['change', 1]]);
      assert.equal(await gemini.getByRole('alert').filter({ hasText: 'File upload blocked' }).count(), 0);
      await drag(gemini, undefined, [report]);
      assert.deepEqual((await observed(gemini)).at(-1), ['drop', 1]);
      await until(async () => (await scopedRows()).length >= 6, 'Control did not receive the six matching upload attempts.');
      const matching = (await scopedRows()).map(({ appId, decision, uploadMethod }) => `${appId}/${decision}/${uploadMethod}`).sort();
      assert.deepEqual(matching, ['chatgpt/monitor/drop', 'chatgpt/monitor/paste', 'chatgpt/monitor/picker',
        'gemini/block/drop', 'gemini/block/paste', 'gemini/block/picker']);
      const installation = (await adminCall('installations'))[0];
      assert.equal(installation.appliedPolicyVersion, scoped.version);

      offline = true;
      try {
        await popup.getByRole('button', { name: 'Sync now' }).click();
        await gemini.getByText(/File uploads block \(selected types\) · Offline policy$/).waitFor();
        await pick(gemini, [pdf]);
        await gemini.getByRole('alert').filter({ hasText: 'File upload blocked' }).waitFor();
        assert.equal((await scopedRows()).length, 6);
      } finally { offline = false; }
      loseNextAcknowledgment = true;
      await syncUntil(popup, () => !loseNextAcknowledgment, 'The proxy did not drop the scoped attempt acknowledgment.');
      const lostScopedId = posts.at(-1).eventId;
      await syncUntil(popup, () => posts.filter(({ eventId }) => eventId === lostScopedId).length >= 2, 'The scoped event was not retried.');
      assert.equal((await scopedRows()).length, 7);
      assert.doesNotMatch(JSON.stringify([...posts, ...await scopedRows()]),
        /private-mixed-case|private-allowed|private-archive|Synthetic scoped file|image\/png|application\/pdf|\.tar\.gz/);

      const scanChat = await browser.newPage();
      const scanGemini = await browser.newPage();
      try {
        for (const [target, url] of [[scanChat, 'https://chatgpt.com/'], [scanGemini, 'https://gemini.google.com/app']]) {
          await target.route(`${new URL(url).origin}/**`, (route) => route.fulfill({ contentType: 'text/html', body: uploadFixture }));
          await target.goto(url);
        }
        const likelyKey = ['-----BEGIN PRIVATE KEY-----', 'c3lk'.repeat(16), '-----END PRIVATE KEY-----'].join('\n');
        const disguised = join(root, 'synthetic-inspected-image.png');
        const raw = join(root, 'synthetic-inspected-notes.txt');
        const binary = join(root, 'synthetic-invalid-text.txt');
        const blockedFile = join(root, 'synthetic-inspected-archive.bin');
        const card = '4242-4242-4242-4242';
        await Promise.all([writeFile(disguised, likelyKey), writeFile(raw, `${marker}\n${card}`),
          writeFile(binary, Buffer.concat([Buffer.from([0xff]), Buffer.from(marker)])), writeFile(blockedFile, likelyKey)]);
        const scan = await adminCall('policies', { privateKeyMode: 'block', paymentCardMode: 'warn', fileInspection: { chatgpt: true, gemini: true },
          uploadModes: { chatgpt: 'off', gemini: 'block' }, uploadTypes: { gemini: ['.bin'] } });
        await popup.getByRole('button', { name: 'Sync now' }).click();
        for (const target of [scanChat, scanGemini]) await target.getByText(/File content monitor$/).waitFor();
        await pick(scanChat, [raw, disguised]);
        assert.deepEqual(await observed(scanChat), [['input', 2], ['change', 2]]);
        await input(scanChat).setInputFiles([]);
        await drag(scanChat, input(scanChat), [disguised]);
        await pick(scanGemini, [blockedFile]);
        await scanGemini.getByRole('alert').filter({ hasText: 'File upload blocked' }).waitFor();
        assert.deepEqual(await observed(scanGemini), []);
        await pick(scanGemini, [raw]);
        await pick(scanGemini, [binary]);
        await pasteFile(scanChat);
        assert.deepEqual((await observed(scanChat)).slice(2), [['drop', 1], ['input', 1], ['change', 1], ['paste', 1]]);
        assert.deepEqual(await observed(scanGemini), [['input', 1], ['change', 1], ['input', 1], ['change', 1]]);
        const scanned = async () => (await adminCall('events')).filter(({ policyVersion }) => policyVersion === scan.version);
        await until(async () => (await scanned()).length >= 4, 'Control did not receive the independent file policies and inspections.');
        const aggregates = (await scanned()).map(({ appId, decision, ruleId, uploadMethod }) => `${appId}/${decision}/${ruleId}/${uploadMethod}`).sort();
        assert.deepEqual(aggregates, ['chatgpt/monitor/pem-private-key/drop', 'chatgpt/monitor/pem-private-key/picker',
          'gemini/block/ai-file-upload/picker', 'gemini/monitor/payment-card-number/picker']);
        assert.doesNotMatch(JSON.stringify([...posts, ...await scanned()]), /synthetic-inspected|synthetic-invalid|c3lkc3lk|4242-4242|ZEKVAR_TEST_SECRET/);
      } finally { await Promise.all([scanChat.close(), scanGemini.close()]); }

      const restored = await adminCall(`policies/${original.version}/restore`, {});
      await popup.getByRole('button', { name: 'Sync now' }).click();
      await gemini.getByText(new RegExp(`^Zekvar · [A-Z]+ v${restored.version}(?: · GitHub PAT [a-z]+)?$`)).waitFor();
      await pick(gemini);
      assert.deepEqual((await observed(gemini)).slice(3), [['input', 2], ['change', 2]]);
      assert.equal(await gemini.getByRole('alert').filter({ hasText: 'File upload blocked' }).count(), 0);
      assert.equal((await rows()).length, 16);
      const resumed = await adminCall('policies', { uploadModes: { gemini: 'block' } });
      await popup.getByRole('button', { name: 'Sync now' }).click();
      await gemini.getByText(new RegExp(` v${resumed.version}.*File uploads block$`)).waitFor();
      await input(gemini).setInputFiles([]);
      await pick(gemini);
      await gemini.getByRole('alert').filter({ hasText: 'File upload blocked' }).waitFor();
      await until(async () => (await rows()).length === 17, 'Control did not record the resumed block.');
      const [{ installationId }] = await adminCall('installations');
      await adminCall(`installations/${installationId}/revoke`, {});
      await popup.getByRole('button', { name: 'Sync now' }).click();
      await gemini.getByText('Zekvar · Gemini policy unavailable', { exact: true }).waitFor();
      assert.equal(await gemini.getByRole('alert').filter({ hasText: 'File upload blocked' }).count(), 0);
      await pick(gemini);
      assert.deepEqual((await observed(gemini)).slice(3), [['input', 2], ['change', 2], ['input', 2], ['change', 2]]);
      assert.equal((await rows()).length, 17);
    } finally { await Promise.all([chat.close(), gemini.close()]); }
  });
});
