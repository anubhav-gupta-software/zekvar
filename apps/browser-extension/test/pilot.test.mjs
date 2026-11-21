import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { fixtureUrl } from '../fixture/server.mjs';
import { domainFixtureArgs, startDomainFixture } from './domain-fixture.mjs';

const api = process.env.ZEKVAR_DEMO_API;
const web = process.env.ZEKVAR_DEMO_WEB;
const admin = process.env.ZEKVAR_DEMO_TOKEN;
const artifacts = process.env.ZEKVAR_DEMO_ARTIFACTS;
assert.match(api ?? '', /^http:\/\/127\.0\.0\.1:\d+$/);
assert.match(web ?? '', /^http:\/\/localhost:\d+$/);
assert.match(admin ?? '', /^[a-f0-9]{64}$/);
const fixture = await readFile(new URL('../fixture/index.html', import.meta.url), 'utf8');

async function installations() {
  const response = await fetch(`${api}/v1/admin/installations`, {
    headers: { Authorization: `Bearer ${admin}` }, signal: AbortSignal.timeout(4000),
  });
  assert.equal(response.status, 200);
  return response.json();
}

async function until(check, timeout, message) {
  const deadline = Date.now() + timeout;
  do {
    const result = await check();
    if (result) return result;
    await delay(500);
  } while (Date.now() < deadline);
  assert.fail(message);
}

test('two managed Chrome profiles enroll, receive policy, and recover after one stops reporting', { timeout: 220_000 }, async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'zekvar-pilot-'));
  const domains = await startDomainFixture();
  const dist = join(dir, 'extension');
  const contexts = new Set();
  t.after(async () => {
    await Promise.allSettled([...contexts].map((context) => context.close()));
    await domains.close();
    await rm(dir, { recursive: true, force: true });
  });
  execFileSync(process.execPath, ['build.mjs'], {
    cwd: fileURLToPath(new URL('..', import.meta.url)),
    env: { ...process.env, ZEKVAR_CONTROL_PORT: new URL(api).port, ZEKVAR_EXTENSION_OUTDIR: dist },
  });

  async function openProfile(name) {
    const browser = await chromium.launchPersistentContext(join(dir, name), {
      channel: 'chromium', headless: process.env.ZEKVAR_DEMO_HEADED !== '1', viewport: { width: 1440, height: 950 },
      args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`, ...domainFixtureArgs],
    });
    contexts.add(browser);
    browser.setDefaultTimeout(7000);
    await browser.route(fixtureUrl, (route) => route.fulfill({ contentType: 'text/html', body: fixture }));
    const worker = browser.serviceWorkers()[0] ?? await browser.waitForEvent('serviceworker');
    return { browser, worker, id: new URL(worker.url()).hostname };
  }

  async function setManagedGrant(profile, grant) {
    const page = await profile.browser.newPage();
    try {
      await page.goto('chrome://policy/test');
      const row = page.locator('policy-test-row').first();
      await row.locator('select.namespace').selectOption(profile.id);
      await row.locator('input.name').fill('EnrollmentGrant');
      await row.locator('input.value').fill(grant);
      await row.locator('select.preset').selectOption({ label: 'Local machine' });
      await page.getByRole('button', { name: 'Apply policies', exact: true }).click();
      await until(() => profile.worker.evaluate(async (expected) =>
        (await chrome.storage.managed.get('EnrollmentGrant')).EnrollmentGrant === expected, grant),
      7000, 'Chrome did not expose the applied test policy to the extension.');
    } finally {
      await page.close();
    }
  }

  async function popup(profile) {
    const page = await profile.browser.newPage();
    await page.goto(new URL('popup.html', profile.worker.url()).href);
    return page;
  }

  const first = await openProfile('first');
  let second = await openProfile('second');
  const dashboard = await first.browser.newPage();
  await dashboard.goto(web);
  await dashboard.getByLabel('Admin token').fill(admin);
  await dashboard.getByRole('button', { name: 'Sign in' }).click();
  await dashboard.getByRole('heading', { name: 'Security overview' }).waitFor();
  const health = dashboard.getByRole('table', { name: 'Browser health' });
  const browserRow = (id) => health.getByRole('row').filter({ hasText: id.slice(0, 13) });
  const refresh = dashboard.getByRole('button', { name: 'Refresh browser health' });
  const capture = (file) => artifacts ? dashboard.screenshot({ path: join(artifacts, file), fullPage: true }) : undefined;

  async function grant() {
    await dashboard.reload();
    await dashboard.getByRole('button', { name: 'Create enrollment grant' }).click();
    return dashboard.getByLabel('Enrollment grant', { exact: true }).inputValue();
  }

  let idA;
  let idB;
  await t.test('Chrome policy enrolls two profiles with distinct credentials and rejects reused grants', async () => {
    await setManagedGrant(first, 'malformed-synthetic-grant');
    const popupA = await popup(first);
    await popupA.getByText('Chrome policy contains an invalid enrollment grant.', { exact: true }).waitFor();
    assert.equal((await installations()).length, 0);

    const grantA = await grant();
    await setManagedGrant(first, grantA);
    await popupA.getByText('Enrolled by Chrome policy.', { exact: true }).waitFor();
    [idA] = (await installations()).map(({ installationId }) => installationId);
    assert.ok(idA);
    assert.equal(await first.worker.evaluate(async (value) => JSON.stringify(await chrome.storage.local.get()).includes(value), grantA), false);

    await setManagedGrant(second, grantA);
    const popupB = await popup(second);
    await popupB.getByText(/Chrome policy grant expired or was already used/).waitFor();
    assert.equal((await installations()).length, 1);
    const grantB = await grant();
    await setManagedGrant(second, grantB);
    await popupB.getByText('Enrolled by Chrome policy.', { exact: true }).waitFor();
    idB = (await installations()).find(({ installationId }) => installationId !== idA)?.installationId;
    assert.ok(idB);
    await dashboard.reload();
    await browserRow(idA).getByText('Reporting', { exact: true }).waitFor();
    await browserRow(idB).getByText('Reporting', { exact: true }).waitFor();
    await Promise.all([popupA.close(), popupB.close()]);
  });

  await t.test('both profiles receive a centrally published policy on their background cadence', async () => {
    await dashboard.getByLabel('Blocked domains', { exact: true }).fill('apps.test');
    await dashboard.getByRole('button', { name: 'Publish domain rules', exact: true }).click();
    await dashboard.getByText('Domain rules published as version 2.', { exact: true }).waitFor();
    await dashboard.getByLabel('Test marker', { exact: true }).selectOption('block');
    await dashboard.getByRole('button', { name: 'Publish policy' }).click();
    await dashboard.getByText('Version 3 published in block mode.', { exact: true }).waitFor();
    await until(async () => {
      const browsers = await installations();
      return browsers.length === 2 && browsers.every(({ appliedPolicyVersion }) => appliedPolicyVersion === 3);
    }, 45_000, 'Both browsers should apply v3 without a manual sync.');
    await refresh.click();
    for (const id of [idA, idB]) await browserRow(id).getByText('v3', { exact: true }).waitFor();
    await capture('07-pilot-two-browsers.png');

    for (const profile of [first, second]) {
      await domains.visit(profile.browser, 'apps.test', true);
      const page = await profile.browser.newPage();
      await page.goto(fixtureUrl);
      await page.getByText('Control policy: BLOCK · v3', { exact: true }).waitFor();
      await page.getByLabel('Prompt', { exact: true }).fill('ZEKVAR_TEST_SECRET');
      await page.getByRole('button', { name: 'Send prompt' }).click();
      await page.getByText(/Submission blocked/).waitFor();
      assert.equal(await page.locator('#submission-count').textContent(), '0');
      await page.close();
    }
  });

  await t.test('Control flags a stopped browser and the same installation picks up rollback after restart', async () => {
    await second.browser.close();
    contexts.delete(second.browser);
    await dashboard.getByRole('button', { name: 'Restore version 1', exact: true }).click();
    await dashboard.getByText('Version 1 restored as version 4.', { exact: true }).waitFor();
    await until(async () => (await installations()).find(({ installationId }) => installationId === idA)?.appliedPolicyVersion === 4,
      45_000, 'The running browser should apply the rolled back policy.');
    await domains.visit(first.browser, 'apps.test', false);
    const stopped = await until(async () => {
      const row = (await installations()).find(({ installationId }) => installationId === idB);
      return Date.now() - Date.parse(row.lastSeenAt) >= 90_000 && row;
    }, 100_000, 'The stopped browser should pass the stale threshold.');
    assert.equal(stopped.appliedPolicyVersion, 3);
    await refresh.click();
    await browserRow(idB).getByText('Stale', { exact: true }).waitFor();
    await browserRow(idB).getByText('Update pending', { exact: true }).waitFor();
    await browserRow(idA).getByText('Reporting', { exact: true }).waitFor();
    await browserRow(idA).getByText('v4', { exact: true }).waitFor();
    await capture('08-pilot-stale-browser.png');

    second = await openProfile('second');
    await until(async () => {
      const browsers = await installations();
      return browsers.length === 2 && browsers.find(({ installationId }) => installationId === idB)?.appliedPolicyVersion === 4;
    }, 45_000, 'The restarted browser should retain enrollment and apply v4.');
    await domains.visit(second.browser, 'apps.test', false);
    await refresh.click();
    await browserRow(idB).getByText('Reporting', { exact: true }).waitFor();
    await browserRow(idB).getByText('v4', { exact: true }).waitFor();
    await capture('09-pilot-recovered-browser.png');
  });
});
