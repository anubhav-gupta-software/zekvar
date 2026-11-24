import { readBrowserState } from './browser-state.mjs';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
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
const uploadFixture = await readFile(new URL('./upload-composer.html', import.meta.url), 'utf8');

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

test('two managed Chrome profiles enroll, receive policy, and recover after one stops reporting', { timeout: 260_000 }, async (t) => {
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
  await dashboard.getByLabel('Control token').fill(admin);
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
    assert.equal(JSON.stringify(await readBrowserState(first.worker)).includes(grantA), false);

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
    await dashboard.getByRole('button', { name: 'Publish navigation rules', exact: true }).click();
    await dashboard.getByText('Navigation rules published as version 2.', { exact: true }).waitFor();
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
      75_000, 'The running browser should apply the rolled back policy.');
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

  await t.test('one managed browser tests a rollout group before its policy is promoted', async () => {
    const delegation = await fetch(`${api}/v1/admin/access`, {
      method: 'POST', headers: { Authorization: `Bearer ${admin}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Pilot administrator', role: 'administrator', hours: 1 }), signal: AbortSignal.timeout(4000),
    });
    assert.equal(delegation.status, 200);
    const delegated = await delegation.json();
    await dashboard.getByRole('button', { name: 'Sign out', exact: true }).click();
    await dashboard.getByLabel('Control token').fill(delegated.token);
    await dashboard.getByRole('button', { name: 'Sign in', exact: true }).click();
    await dashboard.getByText('Pilot administrator · Administrator', { exact: true }).waitFor();
    await dashboard.getByRole('link', { name: 'Rollout groups', exact: true }).click();
    await dashboard.getByRole('heading', { name: 'Rollout groups', exact: true }).waitFor();
    await dashboard.getByLabel('Group name', { exact: true }).fill('Managed browser pilot');
    await dashboard.getByRole('button', { name: 'Create group', exact: true }).click();
    await dashboard.getByText('Managed browser pilot created.', { exact: true }).waitFor();
    const unavailable = await first.browser.newPage();
    try {
      await unavailable.goto(`${web}/groups?group=00000000-0000-0000-0000-000000000000`);
      await unavailable.getByRole('alert').filter({ hasText: 'This rollout group is unavailable.' }).waitFor();
      assert.equal(await unavailable.getByRole('button', { name: 'Publish group policy', exact: true }).count(), 0);
    } finally { await unavailable.close(); }
    const assignments = dashboard.getByRole('table', { name: 'Browser assignments' });
    const assignmentA = assignments.getByLabel(`Assignment for ${idA.slice(0, 13)}`, { exact: true });
    const [groupId] = await assignmentA.selectOption({ label: 'Managed browser pilot' });
    const save = assignments.getByRole('button', { name: `Save assignment for ${idA.slice(0, 13)}`, exact: true });
    await save.click();
    await assignments.getByText('Browser assignment saved.', { exact: true }).waitFor();

    const popupA = await popup(first);
    const popupB = await popup(second);
    const sync = async (page, name) => {
      await page.getByRole('button', { name: 'Sync now' }).click();
      await page.getByText(name, { exact: true }).waitFor();
    };
    await sync(popupA, 'Connected to Control · MONITOR v4');
    await dashboard.getByLabel('Test marker', { exact: true }).selectOption('block');
    await dashboard.getByLabel('Payment card number', { exact: true }).selectOption('block');
    await dashboard.getByLabel('Gemini file uploads', { exact: true }).selectOption('block');
    await dashboard.getByLabel('Gemini file types', { exact: true }).fill('.txt');
    await dashboard.getByRole('button', { name: 'Publish group policy', exact: true }).click();
    await dashboard.getByText('Version 5 published in block mode.', { exact: true }).waitFor();
    await dashboard.getByLabel('Blocked domains', { exact: true }).fill('apps.test');
    await dashboard.getByLabel('Allowed paths', { exact: true }).fill('apps.test/approved');
    await dashboard.getByLabel('Blocked paths', { exact: true }).fill('work.other.test/restricted');
    await dashboard.getByRole('button', { name: 'Publish navigation rules', exact: true }).click();
    await dashboard.getByText('Navigation rules published as version 6.', { exact: true }).waitFor();
    await sync(popupA, 'Connected to Control · BLOCK v6');
    await sync(popupB, 'Connected to Control · MONITOR v4');
    const groupHealth = await first.browser.newPage();
    try {
      await groupHealth.goto(dashboard.url());
      await groupHealth.getByRole('link', { name: 'Review browser rollout', exact: true }).click();
      const cohort = groupHealth.getByRole('table', { name: 'Browser health', exact: true });
      const { version: extensionVersion } = JSON.parse(await readFile(new URL('../manifest.json', import.meta.url), 'utf8'));
      await cohort.getByText(idA.slice(0, 13), { exact: true }).waitFor();
      assert.equal(await cohort.getByText(idB.slice(0, 13), { exact: true }).count(), 0);
      const release = groupHealth.getByRole('table', { name: 'Extension rollout', exact: true })
        .getByRole('link', { name: extensionVersion, exact: true });
      await release.waitFor();
      await release.click();
      await groupHealth.waitForURL((url) => url.searchParams.get('rolloutGroup') === groupId && url.searchParams.get('browserVersion') === extensionVersion);
      await cohort.getByText('v6', { exact: true }).waitFor();
    } finally { await groupHealth.close(); }
    await domains.visit(first.browser, 'apps.test', true);
    await domains.visit(second.browser, 'apps.test', false);
    await domains.visit(first.browser, 'apps.test', false, '/approved');
    await domains.visit(first.browser, 'work.other.test', true, '/restricted');
    await domains.visit(second.browser, 'work.other.test', false, '/restricted');

    const checkPrompt = async (profile, label, draft, blocked) => {
      const page = await profile.browser.newPage();
      try {
        await page.goto(fixtureUrl);
        await page.getByText(`Control policy: ${label}`, { exact: true }).waitFor();
        await page.getByLabel('Prompt', { exact: true }).fill(draft);
        await page.getByRole('button', { name: 'Send prompt' }).click();
        if (blocked) await page.getByText(/Submission blocked/).waitFor();
        assert.equal(await page.locator('#submission-count').textContent(), blocked ? '0' : '1');
      } finally { await page.close(); }
    };
    await checkPrompt(first, 'BLOCK · v6 · Payment card block', 'ZEKVAR_TEST_SECRET', true);
    await checkPrompt(second, 'MONITOR · v4', 'ZEKVAR_TEST_SECRET', false);
    await checkPrompt(first, 'BLOCK · v6 · Payment card block', '4242-4242-4242-4242', true);
    await checkPrompt(second, 'MONITOR · v4', '4242-4242-4242-4242', false);
    const attachment = join(dir, 'synthetic-rollout-upload.txt');
    const nonmatching = join(dir, 'synthetic-rollout-upload.csv');
    await writeFile(attachment, 'Synthetic rollout file.');
    await writeFile(nonmatching, 'Synthetic rollout file.');
    const checkUpload = async (profile, version, blocked, file = attachment) => {
      const page = await profile.browser.newPage();
      try {
        await page.route('https://gemini.google.com/app', (route) => route.fulfill({ contentType: 'text/html', body: uploadFixture }));
        await page.goto('https://gemini.google.com/app');
        await page.getByText(new RegExp(` v${version}(?:$| ·)`)).waitFor();
        const picker = page.getByLabel('Attach fixture files');
        await picker.setInputFiles(file);
        if (blocked) await page.getByRole('alert').filter({ hasText: 'File upload blocked' }).waitFor();
        assert.deepEqual(await page.evaluate(() => window.fileEvents), blocked ? [] : [['input', 1], ['change', 1]]);
      } finally { await page.close(); }
    };
    await checkUpload(first, 6, true);
    await checkUpload(first, 6, false, nonmatching);
    await checkUpload(second, 4, false);
    const browserStatus = await installations();
    assert.equal(browserStatus.find(({ installationId }) => installationId === idA).expectedPolicyVersion, 6);
    assert.equal(browserStatus.find(({ installationId }) => installationId === idB).expectedPolicyVersion, 4);
    await capture('15-control-rollout-groups.png');
    const preview = await dashboard.context().newPage();
    try {
      const href = await dashboard.getByRole('link', { name: 'Preview group policy', exact: true }).getAttribute('href');
      await preview.goto(new URL(href, web).href);
      await preview.getByText('Current Managed browser pilot v6', { exact: true }).waitFor();
      await preview.getByLabel('Load draft from').selectOption({ label: 'Baseline v4' });
      assert.equal(await preview.getByLabel('Draft test marker').inputValue(), 'monitor');
      await preview.getByLabel('Custom navigation URL').fill('http://apps.test/');
      await preview.getByRole('button', { name: 'Run preview', exact: true }).click();
      const table = preview.getByRole('table', { name: 'Preview results' });
      for (const [sample, draft] of [['Synthetic test marker', 'Monitor'], ['Synthetic payment card', 'Allow'],
        ['Custom navigation', 'Allow'], ['Gemini TXT upload', 'Allow']]) {
        const cells = table.getByRole('row', { name: new RegExp(`^${sample} `) }).getByRole('cell');
        await cells.nth(0).getByText('Block', { exact: true }).waitFor();
        await cells.nth(1).getByText(draft, { exact: true }).waitFor();
      }
      await preview.getByLabel('Custom navigation URL').fill('http://work.other.test/restricted');
      await preview.getByRole('button', { name: 'Run preview', exact: true }).click();
      const pathSample = table.getByRole('row', { name: /^Custom navigation / }).getByRole('cell');
      await pathSample.nth(0).getByText('Block', { exact: true }).waitFor();
      await pathSample.nth(0).getByText('work.other.test/restricted', { exact: true }).waitFor();
      await pathSample.nth(1).getByText('Allow', { exact: true }).waitFor();
      await preview.goto(`${web}/preview?group=00000000-0000-0000-0000-000000000000`);
      await preview.getByRole('alert').filter({ hasText: 'This policy scope is unavailable.' }).waitFor();
      assert.equal(await preview.getByRole('button', { name: 'Run preview', exact: true }).count(), 0);
    } finally { await preview.close(); }

    await dashboard.getByRole('button', { name: 'Restore version 5', exact: true }).click();
    await dashboard.getByText('Version 5 restored as version 7.', { exact: true }).waitFor();
    await sync(popupA, 'Connected to Control · BLOCK v7');
    await checkUpload(first, 7, true);
    await checkUpload(first, 7, false, nonmatching);
    await domains.visit(first.browser, 'apps.test', false);
    await domains.visit(first.browser, 'work.other.test', false, '/restricted');
    const { enrollment: { token } } = await readBrowserState(first.worker);
    const stalePolicy = await first.worker.evaluate(async ({ origin, token }) => {
      const response = await fetch(`${origin}/v1/browser/policy`, {
        headers: { Authorization: `Bearer ${token}`, 'X-Zekvar-Assignment-Aware': '1' },
      });
      if (!response.ok) throw new Error(`Policy fetch failed with status ${response.status}.`);
      return response.json();
    }, { origin: api, token });
    assert.equal(stalePolicy.version, 7);
    assert.equal(stalePolicy.assignmentVersion, 1);
    const [impact] = await Promise.all([dashboard.waitForEvent('popup'),
      dashboard.getByRole('link', { name: 'Review baseline impact', exact: true }).click()]);
    try {
      await impact.getByRole('heading', { name: 'Organization baseline · v4', exact: true }).waitFor();
      const affected = impact.getByRole('table', { name: 'Affected rollout cohorts', exact: true });
      assert.equal(await affected.getByRole('row', { name: /^Unassigned browsers/ }).getByRole('cell').first().textContent(), '1');
      await impact.getByRole('article').filter({ hasText: 'Browsers outside scope' }).getByText('1', { exact: true }).waitFor();
    } finally {
      await impact.close();
    }
    await assignmentA.selectOption('');
    await save.click();
    await assignments.getByRole('row').filter({ hasText: idA.slice(0, 13) }).getByText('v4', { exact: true }).waitFor();
    await sync(popupA, 'Connected to Control · MONITOR v4');
    await first.worker.evaluate((previous) => {
      const request = globalThis.fetch;
      globalThis.fetch = (url, options) => {
        if (String(url).endsWith('/v1/browser/policy')) {
          globalThis.fetch = request;
          return Promise.resolve(Response.json(previous));
        }
        return request(url, options);
      };
    }, stalePolicy);
    await sync(popupA, 'Connected to Control · MONITOR v4');
    await popupA.waitForFunction(() => !document.querySelector('#sync').disabled);
    await popupA.getByText('Connected to Control · MONITOR v4', { exact: true }).waitFor();
    await checkPrompt(first, 'MONITOR · v4', '4242-4242-4242-4242', false);

    const concurrentPublish = await fetch(`${api}/v1/admin/policy-groups/${groupId}/policies`, {
      method: 'POST', headers: { Authorization: `Bearer ${admin}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ pathRules: { allow: [], block: ['work.other.test/restricted'] } }), signal: AbortSignal.timeout(4000),
    });
    assert.equal(concurrentPublish.status, 200);
    assert.equal((await concurrentPublish.json()).version, 8);
    const promote = dashboard.getByRole('button', { name: 'Promote group policy', exact: true });
    dashboard.once('dialog', (dialog) => dialog.accept());
    await promote.click();
    await dashboard.getByRole('alert').filter({ hasText: 'The group or organization baseline version changed.' }).waitFor();
    await sync(popupB, 'Connected to Control · MONITOR v4');
    await dashboard.reload();
    dashboard.once('dialog', (dialog) => dialog.accept());
    await promote.click();
    await dashboard.getByText('Group policy promoted as organization version 9.', { exact: true }).waitFor();
    await sync(popupB, 'Connected to Control · BLOCK v9');
    await domains.visit(second.browser, 'work.other.test', true, '/restricted');
    await checkPrompt(second, 'BLOCK · v9 · Payment card block', '4242-4242-4242-4242', true);
    await checkUpload(second, 9, true);
    const audited = await fetch(`${api}/v1/admin/audit?action=policy_published`, {
      headers: { Authorization: `Bearer ${admin}` }, signal: AbortSignal.timeout(4000),
    });
    assert.equal(audited.status, 200);
    const { entries } = await audited.json();
    assert.deepEqual(entries.find(({ policyVersion }) => policyVersion === 9)?.actorAccess, {
      id: delegated.access.id, name: 'Pilot administrator', role: 'administrator',
    });
    await Promise.all([popupA.close(), popupB.close()]);
  });
});
