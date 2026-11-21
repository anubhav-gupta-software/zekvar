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
import { fixtureUrl } from '../fixture/server.mjs';

const origin = process.env.ZEKVAR_EXTENSION_TEST_API;
const admin = process.env.ZEKVAR_EXTENSION_TEST_ADMIN_TOKEN;
assert.match(origin ?? '', /^http:\/\/127\.0\.0\.1:\d+$/, 'Set ZEKVAR_EXTENSION_TEST_API to a loopback API origin.');
assert.match(admin ?? '', /^[a-f0-9]{64}$/, 'Set ZEKVAR_EXTENSION_TEST_ADMIN_TOKEN for a disposable organization.');
const fixture = await readFile(new URL('../fixture/index.html', import.meta.url), 'utf8');
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

async function until(check, explanation) {
  for (let attempt = 0; attempt < 50; attempt++) {
    if (await check()) return;
    await delay(100);
  }
  assert.fail(explanation);
}

test('Chrome enrolls, applies Control policy, and recovers queued events across restart', { timeout: 60_000 }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'zekvar-browser-control-'));
  const buildPath = join(root, 'extension');
  const profile = join(root, 'profile');
  let browser;
  let popup;
  let page;
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
      channel: 'chromium',
      args: [`--disable-extensions-except=${buildPath}`, `--load-extension=${buildPath}`],
    });
    browser.setDefaultTimeout(5000);
    await browser.route(fixtureUrl, (route) => route.fulfill({ contentType: 'text/html', body: fixture }));
    const worker = browser.serviceWorkers()[0] ?? await browser.waitForEvent('serviceworker');
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
});
