import { readBrowserState } from './browser-state.mjs';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const api = process.env.ZEKVAR_DEMO_API;
const owner = process.env.ZEKVAR_DEMO_TOKEN;
const artifacts = process.env.ZEKVAR_DEMO_ARTIFACTS;
assert.match(api ?? '', /^http:\/\/127\.0\.0\.1:\d+$/);
assert.match(owner ?? '', /^[a-f0-9]{64}$/);

async function admin(path, body, expect = 200) {
  const response = await fetch(`${api}/v1/admin/${path}`, { method: body ? 'POST' : 'GET',
    headers: { Authorization: `Bearer ${owner}`, 'Content-Type': 'application/json' },
    body: body && JSON.stringify(body), signal: AbortSignal.timeout(5_000) });
  assert.equal(response.status, expect, path);
  const text = await response.text();
  return text ? JSON.parse(text) : undefined;
}

async function until(check, message, timeout = 20_000) {
  const deadline = Date.now() + timeout;
  do {
    const result = await check();
    if (result) return result;
    await delay(250);
  } while (Date.now() < deadline);
  assert.fail(message);
}

test('two managed Chrome profiles redeem one enrollment key into a rollout group and a third is refused at the limit', { timeout: 150_000 }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'zekvar-enrollment-keys-'));
  const contexts = new Set();
  const redemptions = [];
  let dropNextRedemption = false;
  // Forwards browser traffic to Control. It can drop one redemption response after Control commits it, like a lost connection.
  const proxy = createServer(async (request, response) => {
    try {
      if (!request.url?.startsWith('/v1/enroll') && !request.url?.startsWith('/v1/browser/')) return response.writeHead(404).end();
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      const headers = Object.fromEntries(Object.entries(request.headers).filter(([name]) =>
        name === 'content-type' || name === 'authorization' || name.startsWith('x-zekvar-')));
      const upstream = await fetch(api + request.url, { method: request.method, headers, body: body.length ? body : undefined,
        signal: AbortSignal.timeout(5_000) });
      const text = await upstream.text();
      if (request.url === '/v1/enroll/key') {
        redemptions.push({ ...JSON.parse(body), status: upstream.status, installationId: upstream.ok ? JSON.parse(text).installationId : undefined });
        if (dropNextRedemption && upstream.ok) {
          dropNextRedemption = false;
          return response.writeHead(502).end();
        }
      }
      response.writeHead(upstream.status, { 'Content-Type': 'application/json' }).end(text);
    } catch {
      response.writeHead(502).end();
    }
  });
  await new Promise((resolve, reject) => {
    proxy.once('error', reject);
    proxy.listen(0, '127.0.0.1', resolve);
  });
  t.after(async () => {
    await Promise.allSettled([...contexts].map((context) => context.close()));
    await new Promise((resolve) => {
      proxy.close(resolve);
      proxy.closeAllConnections();
    });
    await rm(root, { recursive: true, force: true });
  });
  const dist = join(root, 'extension');
  execFileSync(process.execPath, ['build.mjs'], { cwd: fileURLToPath(new URL('..', import.meta.url)),
    env: { ...process.env, ZEKVAR_CONTROL_PORT: String(proxy.address().port), ZEKVAR_EXTENSION_OUTDIR: dist } });

  const group = await admin('policy-groups', { name: `Device manager scope ${randomUUID().slice(0, 8)}` });
  const groupPolicy = await admin(`policy-groups/${group.id}/policies`, { mode: 'block' });
  const baseline = (await admin('policies'))[0];
  assert.notEqual(groupPolicy.version, baseline?.version);
  const issued = await admin('enrollment-keys', { requestId: randomUUID(), label: 'Connected key', groupId: group.id, days: 1, maxRedemptions: 2 });

  async function openProfile(name) {
    const browser = await chromium.launchPersistentContext(join(root, name), {
      channel: 'chromium', headless: process.env.ZEKVAR_DEMO_HEADED !== '1', viewport: { width: 1280, height: 900 },
      args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`,
        '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1'],
    });
    contexts.add(browser);
    browser.setDefaultTimeout(8_000);
    const worker = browser.serviceWorkers()[0] ?? await browser.waitForEvent('serviceworker');
    return { name, browser, worker, id: new URL(worker.url()).hostname };
  }

  // Chrome's policy test page writes the same 3rdparty managed storage a device manager would push.
  async function pushKey(profile, key) {
    const page = await profile.browser.newPage();
    try {
      await page.goto('chrome://policy/test');
      const row = page.locator('policy-test-row').first();
      await row.locator('select.namespace').selectOption(profile.id);
      await row.locator('input.name').fill('EnrollmentKey');
      await row.locator('input.value').fill(key);
      await row.locator('select.preset').selectOption({ label: 'Local machine' });
      await page.getByRole('button', { name: 'Apply policies', exact: true }).click();
      await until(() => profile.worker.evaluate(async (expected) =>
        (await chrome.storage.managed.get('EnrollmentKey')).EnrollmentKey === expected, key),
      'Chrome did not expose the enrollment key to the extension.');
    } finally {
      await page.close();
    }
  }

  async function popup(profile) {
    const page = await profile.browser.newPage();
    await page.goto(new URL('popup.html', profile.worker.url()).href);
    return page;
  }

  const installations = async () => (await admin(`installations/fleet?enrollmentKey=${issued.key.id}`)).entries;
  const [first, second, third] = await Promise.all(['first', 'second', 'third'].map(openProfile));

  await t.test('a profile whose redemption response is lost retries with its stored nonce and keeps one seat', async () => {
    dropNextRedemption = true;
    await pushKey(first, issued.token);
    const page = await popup(first);
    await until(() => redemptions.length >= 1, 'The first profile did not redeem the key.');
    await page.reload();
    await page.getByText('Enrolled by Chrome policy.', { exact: true }).waitFor();
    const firstAttempts = redemptions.filter(({ nonce }) => nonce === redemptions[0].nonce);
    assert.ok(firstAttempts.length >= 2);
    assert.equal(new Set(firstAttempts.map(({ installationId }) => installationId)).size, 1);
    assert.equal((await admin('enrollment-keys')).find(({ id }) => id === issued.key.id).redeemed, 1);
    const state = await readBrowserState(first.worker);
    assert.equal(state.enrollmentNonce, redemptions[0].nonce);
    assert.equal(state.enrollment.installationId, firstAttempts[0].installationId);
    assert.ok(!JSON.stringify(state).includes(issued.token.slice(4)), 'The browser stored the shared enrollment key.');
    await page.close();
  });

  await t.test('a second profile redeems the same key for its own credential in the same rollout group', async () => {
    await pushKey(second, issued.token);
    const page = await popup(second);
    await page.getByText('Enrolled by Chrome policy.', { exact: true }).waitFor();
    await page.getByText(`Connected to Control · BLOCK v${groupPolicy.version}`, { exact: true }).waitFor();
    const [stateA, stateB] = await Promise.all([readBrowserState(first.worker), readBrowserState(second.worker)]);
    assert.notEqual(stateA.enrollment.installationId, stateB.enrollment.installationId);
    assert.notEqual(stateA.enrollment.token, stateB.enrollment.token);
    assert.notEqual(stateA.enrollmentNonce, stateB.enrollmentNonce);
    const browsers = await until(async () => {
      const rows = await installations();
      const applied = await admin('installations');
      return rows.length === 2 && rows.every(({ groupId }) => groupId === group.id) &&
        rows.every((row) => applied.find(({ installationId }) => installationId === row.installationId)?.appliedPolicyVersion === groupPolicy.version) && rows;
    }, 'Both key enrollments should apply the rollout group policy.');
    assert.deepEqual(new Set(browsers.map(({ installationId }) => installationId)),
      new Set([stateA.enrollment.installationId, stateB.enrollment.installationId]));
    if (artifacts) await page.screenshot({ path: join(artifacts, '44-enrollment-key-profile.png') });
    await page.close();
  });

  await t.test('a third profile is refused once the key is exhausted and does not retry the same key', async () => {
    await pushKey(third, issued.token);
    const page = await popup(third);
    await page.getByText('The Chrome policy enrollment key has no enrollments left. Ask your admin to rotate the key.', { exact: true }).waitFor();
    const attempts = redemptions.length;
    await page.reload();
    await page.getByText(/no enrollments left/).waitFor();
    await delay(1_000);
    assert.equal(redemptions.length, attempts);
    assert.equal((await installations()).length, 2);
    const key = (await admin('enrollment-keys')).find(({ id }) => id === issued.key.id);
    assert.deepEqual([key.status, key.redeemed, key.activeInstallations, key.rejected], ['exhausted', 2, 2, 1]);
    assert.equal((await readBrowserState(third.worker)).enrollment, undefined);

    // Rotating to a new key lets the waiting profile enroll without touching the first two.
    const rotated = await admin(`enrollment-keys/${issued.key.id}/rotate`, { requestId: randomUUID(), days: 1, overlapHours: 1 });
    await pushKey(third, rotated.token);
    await page.reload();
    await page.getByText('Enrolled by Chrome policy.', { exact: true }).waitFor();
    await page.getByText(`Connected to Control · BLOCK v${groupPolicy.version}`, { exact: true }).waitFor();
    assert.equal((await admin(`installations/fleet?enrollmentKey=${rotated.key.id}`)).entries.length, 1);
    await page.close();
  });
});
