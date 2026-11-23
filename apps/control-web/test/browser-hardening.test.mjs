import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { chromium } from 'playwright';

const web = process.env.ZEKVAR_TEST_WEB_ORIGIN;
const api = process.env.ZEKVAR_TEST_API_ORIGIN;
const owner = process.env.ZEKVAR_TEST_ADMIN_TOKEN;
assert.match(web ?? '', /^http:\/\/localhost:\d+$/);
assert.match(api ?? '', /^http:\/\/127\.0\.0\.1:\d+$/);
assert.match(owner ?? '', /^[a-f0-9]{64}$/);

async function admin(path, body, expected = 200) {
  const response = await fetch(`${api}/v1/admin/${path}`, {
    method: body ? 'POST' : 'GET', signal: AbortSignal.timeout(5000), body: body && JSON.stringify(body),
    headers: { Authorization: `Bearer ${owner}`, 'Content-Type': 'application/json' },
  });
  assert.equal(response.status, expected, path);
  return expected === 204 ? undefined : response.json();
}

test('reviews, exports, applies, and rolls back a Chrome hardening plan in a managed Chromium profile', { timeout: 60_000 }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'zekvar-hardening-ui-'));
  const context = await chromium.launchPersistentContext(join(root, 'profile'), {
    channel: 'chromium', headless: process.env.ZEKVAR_DEMO_HEADED !== '1', viewport: { width: 1440, height: 1000 }, acceptDownloads: true,
  });
  t.after(async () => {
    await context.close();
    await rm(root, { recursive: true, force: true });
  });
  context.setDefaultTimeout(7000);
  const page = await context.newPage();
  const posts = [];
  const errors = [];
  page.on('request', (request) => { if (request.postData()) posts.push(request.postData()); });
  page.on('pageerror', (error) => errors.push(error.message));

  async function signIn(token) {
    await page.goto(web);
    await page.getByLabel('Control token').fill(token);
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await page.getByRole('heading', { name: 'Security overview' }).waitFor();
  }

  async function signOut() {
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await page.getByRole('heading', { name: 'Sign in to Control', exact: true }).waitFor();
  }

  async function confirm(label, accept = true) {
    page.once('dialog', (dialog) => accept ? dialog.accept() : dialog.dismiss());
    await page.getByRole('button', { name: label, exact: true }).click();
  }

  const group = await admin('policy-groups', { name: 'Hardening test cohort' });
  const groupPath = `policy-groups/${group.id}/policies`;
  const groupPage = `${web}/hardening?group=${group.id}`;
  await page.goto(groupPage);
  await page.getByRole('heading', { name: 'Sign in to Control', exact: true }).waitFor();
  await signIn(owner);
  await page.getByRole('link', { name: 'Chrome hardening', exact: true }).click();
  await page.getByLabel('Scope', { exact: true }).selectOption(group.id);
  await page.getByRole('button', { name: 'Open scope', exact: true }).click();
  await page.getByText(/Inherited from the baseline/).waitFor();
  const plan = page.getByRole('table', { name: 'Published hardening plan', exact: true });
  assert.equal(await plan.getByText('Preserve existing', { exact: true }).count(), 7);

  const fields = {
    'Safe Browsing protection': 'standard', 'Download restrictions': 'all', 'Safe Browsing warning bypass': 'restrict',
    'Guest profiles': 'restrict', 'Incognito windows': 'restrict', 'Chrome password saving': 'restrict', 'Chrome Sync': 'restrict',
  };
  const review = page.getByRole('button', { name: 'Review hardening changes', exact: true });
  await review.click();
  await page.getByText('The draft matches the published plan.').waitFor();
  async function edit() {
    for (const [label, value] of Object.entries(fields)) await page.getByLabel(label, { exact: true }).selectOption(value);
    await review.click();
    assert.equal(await page.getByRole('list', { name: 'Hardening changes', exact: true }).locator('li').count(), 7);
  }

  await edit();
  await confirm('Publish hardening plan', false);
  assert.deepEqual(await admin(groupPath), []);
  await admin('policies', { mode: 'warn' });
  await confirm('Publish hardening plan');
  await page.getByRole('alert').getByText(/The policy changed/).waitFor();
  assert.deepEqual(await admin(groupPath), []);

  const author = await admin('access', { name: 'Chrome hardening author', role: 'administrator', hours: 1 });
  const reviewer = await admin('access', { name: 'Chrome hardening reviewer', role: 'administrator', hours: 1 });
  const auditor = await admin('access', { name: 'Chrome hardening auditor', role: 'auditor', hours: 1 });
  await admin('policy-reviews/setting', { required: true }, 204);
  await signOut();
  await signIn(author.token);
  await page.goto(groupPage);
  await edit();
  await confirm('Request hardening review');
  await page.getByRole('link', { name: 'Open review request', exact: true }).click();
  await page.getByRole('list', { name: 'Policy setting changes', exact: true }).getByText(/Incognito windows.*Disable Incognito/).waitFor();
  assert.equal(await page.getByRole('button', { name: /^Approve/ }).count(), 0);
  const [{ id }] = (await admin('policy-reviews')).entries;
  await signOut();
  await signIn(reviewer.token);
  await page.goto(`${web}/reviews#review-${id}`);
  await confirm('Approve and publish');
  await page.getByText('Approved by Chrome hardening reviewer', { exact: true }).waitFor();
  const [published] = await admin(groupPath);
  assert.deepEqual(published.browserHardening, { safeBrowsing: 'standard', downloads: 'all', lockSafeBrowsingWarnings: true,
    disableGuest: true, disableIncognito: true, disablePasswordSaving: true, disableSync: true });
  await signOut();
  await signIn(auditor.token);
  await page.goto(groupPage);
  await plan.getByText('Disable Incognito', { exact: true }).waitFor();
  assert.equal(await review.count(), 0);

  const existing = page.getByLabel('Existing Chrome policy JSON', { exact: true });
  const compare = page.getByRole('button', { name: 'Review hardening export', exact: true });
  const download = page.getByRole('button', { name: 'Download hardened Chrome policy', exact: true });
  for (const [input, message] of [
    ['{', /Enter a flat Chrome policy/], ['{"policyValues":{}}', /Enter a flat Chrome policy/],
    ['{"BrowserGuestModeEnforced": true}', /Resolve BrowserGuestModeEnforced/],
    ['{"IncognitoModeAvailability": 2}', /Resolve forced Incognito/],
    ['{"IncognitoModeUrlAllowlist":["internal.fixture.test"]}', /Resolve forced Incognito/],
    ['{"DownloadRestrictions": "strict"}', /unsupported existing value for DownloadRestrictions/],
  ]) {
    await existing.fill(input);
    await compare.click();
    await page.getByRole('alert').getByText(message).waitFor();
    assert.equal(await download.count(), 0);
  }

  const native = {
    SafeBrowsingProtectionLevel: 2, DownloadRestrictions: 0, DisableSafeBrowsingProceedAnyway: false, BrowserGuestModeEnabled: true,
    IncognitoModeAvailability: 0, PasswordManagerEnabled: true, SyncDisabled: false,
  };
  const pinnedId = 'd'.repeat(32);
  const privateFixture = 'private-helpdesk-hardening-fixture';
  const original = { ...native, ExtensionSettings: { [pinnedId]: { installation_mode: 'force_installed',
    update_url: 'https://updates.example.test/pilot/update.xml', blocked_install_message: privateFixture } } };
  const originalText = JSON.stringify(original, null, 4);
  await existing.fill(originalText);
  await compare.click();
  assert.equal(await page.getByRole('list', { name: 'Chrome setting changes', exact: true }).locator('li').count(), 6);
  async function saveFile(button) {
    const [file] = await Promise.all([page.waitForEvent('download'), button.click()]);
    return { name: file.suggestedFilename(), text: await readFile(await file.path(), 'utf8') };
  }
  const hardened = await saveFile(download);
  const rollback = await saveFile(page.getByRole('button', { name: 'Download hardening rollback', exact: true }));
  assert.equal(hardened.name, `chrome-hardening-v${published.version}.json`);
  assert.equal(rollback.name, `chrome-hardening-v${published.version}-rollback.json`);
  assert.equal(rollback.text, originalText);
  const settings = JSON.parse(hardened.text);
  assert.deepEqual(settings, { ...original, DownloadRestrictions: 3, DisableSafeBrowsingProceedAnyway: true, BrowserGuestModeEnabled: false,
    IncognitoModeAvailability: 1, PasswordManagerEnabled: false, SyncDisabled: true });
  assert.ok(posts.every((content) => !content.includes(privateFixture)));
  await page.getByText('Review merged JSON', { exact: true }).click();
  await page.setViewportSize({ width: 390, height: 820 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth), 390);
  await page.setViewportSize({ width: 1440, height: 1000 });
  if (process.env.ZEKVAR_TEST_HARDENING_SCREENSHOT) {
    await page.screenshot({ path: process.env.ZEKVAR_TEST_HARDENING_SCREENSHOT, fullPage: true });
  }
  await existing.fill(hardened.text);
  assert.equal(await download.count(), 0);
  await compare.click();
  await page.getByText('The existing Chrome settings already meet this plan.').waitFor();

  const controls = await context.newPage();
  await controls.goto('chrome://policy/test');
  const nativeKeys = Object.keys(native);
  for (const [index, name] of nativeKeys.entries()) {
    if (index) await controls.locator('#add-policy-btn').click();
    const row = controls.locator('policy-test-row').nth(index);
    await row.locator('select.namespace').selectOption('chrome');
    await row.locator('input.name').fill(name);
    await row.locator('select.preset').selectOption({ label: 'Local machine' });
  }

  const status = await context.newPage();

  async function apply(policy) {
    for (const [index, key] of nativeKeys.entries()) {
      const row = controls.locator('policy-test-row').nth(index);
      if (typeof policy[key] === 'boolean') await row.locator('select.value').selectOption(String(policy[key]));
      else await row.locator('input.value').fill(String(policy[key]));
    }
    await controls.getByRole('button', { name: 'Apply policies', exact: true }).click();
    await status.goto('chrome://policy');
    for (const key of nativeKeys) {
      const row = status.locator('policy-row').filter({ has: status.getByRole('link', { name: key, exact: true }) });
      await row.locator('.policy.row .value').getByText(String(policy[key]), { exact: true }).waitFor();
      assert.match(await row.locator('.policy.row .messages').innerText(), /^(OK|Restart required)$/);
    }
  }

  await apply(settings);
  await apply(JSON.parse(rollback.text));
  assert.deepEqual(errors, []);
});
