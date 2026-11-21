import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { domainFixtureArgs, startDomainFixture } from './domain-fixture.mjs';

const api = process.env.ZEKVAR_DEMO_API;
const web = process.env.ZEKVAR_DEMO_WEB;
const owner = process.env.ZEKVAR_DEMO_TOKEN;
assert.match(api ?? '', /^http:\/\/127\.0\.0\.1:\d+$/);
assert.match(web ?? '', /^http:\/\/localhost:\d+$/);
assert.match(owner ?? '', /^[a-f0-9]{64}$/);

async function admin(path, body, expected = 200) {
  const response = await fetch(`${api}/v1/admin/${path}`, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { Authorization: `Bearer ${owner}`, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(5000),
  });
  assert.equal(response.status, expected, path);
  if (response.status !== 204) return response.json();
}

test('two managed Chrome profiles apply a reviewed navigation rule only after approval', { timeout: 75_000 }, async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'zekvar-review-pilot-'));
  const domains = await startDomainFixture();
  const dist = join(directory, 'extension');
  const profiles = [];
  t.after(async () => {
    await Promise.allSettled(profiles.map((profile) => profile.close()));
    await domains.close();
    await rm(directory, { recursive: true, force: true });
  });
  execFileSync(process.execPath, ['build.mjs'], {
    cwd: fileURLToPath(new URL('..', import.meta.url)),
    env: { ...process.env, ZEKVAR_CONTROL_PORT: new URL(api).port, ZEKVAR_EXTENSION_OUTDIR: dist },
  });
  const [original] = await admin('policies');
  assert.equal(original.mode, 'monitor');
  await admin('policy-reviews/setting', { required: true }, 204);

  async function managedProfile(name) {
    const browser = await chromium.launchPersistentContext(join(directory, name), {
      channel: 'chromium', headless: process.env.ZEKVAR_DEMO_HEADED !== '1',
      args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`, ...domainFixtureArgs],
    });
    profiles.push(browser);
    browser.setDefaultTimeout(10000);
    const worker = browser.serviceWorkers()[0] ?? await browser.waitForEvent('serviceworker');
    const extension = new URL(worker.url());
    const { grant } = await admin('enrollment-grants', {});
    const management = await browser.newPage();
    try {
      await management.goto('chrome://policy/test');
      const row = management.locator('policy-test-row').first();
      await row.locator('select.namespace').selectOption(extension.hostname);
      await row.locator('input.name').fill('EnrollmentGrant');
      await row.locator('input.value').fill(grant);
      await row.locator('select.preset').selectOption({ label: 'Local machine' });
      await management.getByRole('button', { name: 'Apply policies', exact: true }).click();
      let applied = false;
      for (let attempt = 0; attempt < 50 && !applied; attempt++) {
        applied = await worker.evaluate(async (expected) =>
          (await chrome.storage.managed.get('EnrollmentGrant')).EnrollmentGrant === expected, grant);
        if (!applied) await delay(100);
      }
      assert.ok(applied, 'Chrome did not expose the enrollment policy to the extension.');
    } finally {
      await management.close();
    }
    const popup = await browser.newPage();
    await popup.goto(new URL('popup.html', extension).href);
    await popup.getByText('Enrolled by Chrome policy.', { exact: true }).waitFor();
    const { token } = await admin('access', { name, role: 'administrator', hours: 1 });
    const dashboard = await browser.newPage();
    await dashboard.goto(web);
    await dashboard.getByLabel('Control token').fill(token);
    await dashboard.getByRole('button', { name: 'Sign in', exact: true }).click();
    await dashboard.getByText(`${name} · Administrator`, { exact: true }).waitFor();
    return { browser, popup, dashboard };
  }

  const first = await managedProfile('Pilot author');
  const second = await managedProfile('Pilot reviewer');
  const sync = async ({ popup }, version) => {
    const button = popup.getByRole('button', { name: 'Sync now', exact: true });
    await button.click();
    await popup.getByText(`Connected to Control · MONITOR v${version}`, { exact: true }).waitFor();
    await popup.waitForFunction(() => !document.querySelector('#sync').disabled);
  };
  await first.dashboard.getByLabel('Blocked paths', { exact: true }).fill('work.other.test/reviewed');
  await first.dashboard.getByRole('button', { name: 'Request navigation review', exact: true }).click();
  const link = first.dashboard.getByRole('link', { name: 'Open review request', exact: true });
  await link.waitFor();
  const url = new URL(await link.getAttribute('href'), web);
  assert.deepEqual((await admin('policies'))[0], original);
  for (const profile of [first, second]) {
    await sync(profile, original.version);
    await domains.visit(profile.browser, 'work.other.test', false, '/reviewed');
  }

  await second.dashboard.goto(url.href);
  const review = second.dashboard.locator(url.hash);
  await review.getByText('work.other.test/reviewed', { exact: true }).waitFor();
  second.dashboard.once('dialog', (dialog) => dialog.accept());
  await review.getByRole('button', { name: 'Approve and publish', exact: true }).click();
  await review.getByText('Approved by Pilot reviewer', { exact: true }).waitFor();
  for (const profile of [first, second]) {
    await sync(profile, original.version + 1);
    await domains.visit(profile.browser, 'work.other.test', true, '/reviewed');
    await domains.visit(profile.browser, 'work.other.test', false, '/unrelated');
  }
  const installations = await admin('installations');
  assert.equal(installations.length, 2);
  assert.ok(installations.every(({ appliedPolicyVersion }) => appliedPolicyVersion === original.version + 1));
});
