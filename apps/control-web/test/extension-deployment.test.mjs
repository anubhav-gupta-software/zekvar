import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
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

async function syntheticExtension(root, name) {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'der' } });
  const id = createHash('sha256').update(publicKey).digest('hex').slice(0, 32)
    .replace(/./g, (character) => String.fromCharCode(97 + Number.parseInt(character, 16)));
  const path = join(root, name);
  await mkdir(path);
  await writeFile(join(path, 'manifest.json'), JSON.stringify({
    name: `Zekvar test ${name}`, version: '1.0', manifest_version: 3, key: publicKey.toString('base64'),
  }));
  return { id, path };
}

async function waitForNativeState(page, expected) {
  for (let attempt = 0; attempt < 40; attempt++) {
    const states = await page.evaluate(async (ids) => Object.fromEntries(
      (await chrome.developerPrivate.getExtensionsInfo({ includeDisabled: true, includeTerminated: true }))
        .filter((extension) => ids.includes(extension.id))
        .map((extension) => [extension.id, { state: extension.state, blocked: extension.disableReasons.blockedByPolicy }])),
    Object.keys(expected));
    if (Object.entries(expected).every(([id, enabled]) => states[id]?.state === (enabled ? 'ENABLED' : 'DISABLED') &&
        states[id].blocked === !enabled)) return;
    await delay(150);
  }
  assert.fail('Chrome did not apply the expected native extension states.');
}

test('publishes a scoped plan, downloads Chrome policy, and rolls back in a managed Chrome profile', { timeout: 45_000 }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'zekvar-deployment-ui-'));
  const [allowed, blocked, unlisted] = await Promise.all(['allowed-fixture', 'blocked-fixture', 'unlisted-fixture']
    .map((name) => syntheticExtension(root, name)));
  const paths = [allowed.path, blocked.path, unlisted.path].join(',');
  const browser = await chromium.launchPersistentContext(join(root, 'profile'), {
    channel: 'chromium', headless: process.env.ZEKVAR_DEMO_HEADED !== '1', viewport: { width: 1440, height: 1000 },
    args: [`--load-extension=${paths}`, `--disable-extensions-except=${paths}`, '--host-resolver-rules=MAP *.fixture.test ~NOTFOUND'],
  });
  t.after(async () => {
    await browser.close();
    await rm(root, { recursive: true, force: true });
  });
  browser.setDefaultTimeout(6000);
  const page = await browser.newPage();
  const captured = [];
  page.on('request', (request) => { if (request.postData()) captured.push(request.postData()); });
  const failures = [];
  page.on('pageerror', (error) => failures.push(error.message));
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
  async function confirm(label) {
    page.once('dialog', (dialog) => dialog.accept());
    await page.getByRole('button', { name: label, exact: true }).click();
  }
  async function download(label) {
    const [exported] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: label, exact: true }).click()]);
    return { name: exported.suggestedFilename(), data: JSON.parse(await readFile(await exported.path(), 'utf8')) };
  }
  const group = await admin('policy-groups', { name: 'Chrome managed canary' });
  const groupPath = `policy-groups/${group.id}/policies`;
  await signIn(owner);
  await page.getByRole('link', { name: 'Browser extensions', exact: true }).click();
  await page.getByRole('link', { name: 'Manage Chrome deployment', exact: true }).click();
  await page.getByLabel('Scope', { exact: true }).selectOption(group.id);
  await page.getByRole('button', { name: 'Open scope', exact: true }).click();
  await page.getByText(/Inherited from the baseline/).waitFor();
  const rules = page.getByLabel('Extension rules', { exact: true });
  const review = page.getByRole('button', { name: 'Review changes', exact: true });
  const publish = 'Publish deployment plan';
  await rules.fill(`${allowed.id}, allow\n${allowed.id}, block`);
  await review.click();
  await page.getByRole('alert').getByText('Line 2 repeats an extension ID.').waitFor();
  assert.equal(await page.getByRole('button', { name: publish }).count(), 0);
  const forceId = 'c'.repeat(32);
  const protectedId = 'd'.repeat(32);
  const update = 'https://updates.fixture.test/channel/update.xml';
  const draft = `${allowed.id}, allow\n${blocked.id}, block\n${forceId}, force, ${update}`;
  await rules.fill(draft);
  await page.getByLabel('Unlisted extensions', { exact: true }).selectOption('block');
  await review.click();
  await page.getByRole('list', { name: 'Deployment changes', exact: true }).getByText(/Force install/).waitFor();
  await admin('policies', { mode: 'warn' });
  await confirm(publish);
  await page.getByRole('alert').getByText(/The policy changed/).waitFor();
  assert.deepEqual(await admin(groupPath), []);
  await page.reload();

  const author = await admin('access', { name: 'Canary deployment author', role: 'administrator', hours: 1 });
  const reviewer = await admin('access', { name: 'Canary deployment reviewer', role: 'administrator', hours: 1 });
  const auditor = await admin('access', { name: 'Canary deployment auditor', role: 'auditor', hours: 1 });
  await admin('policy-reviews/setting', { required: true }, 204);
  await signOut();
  await signIn(author.token);
  const scopeUrl = `${web}/extensions/deployment?group=${group.id}`;
  await page.goto(scopeUrl);
  await rules.fill(draft);
  await page.getByLabel('Unlisted extensions', { exact: true }).selectOption('block');
  await review.click();
  await confirm('Request deployment review');
  await page.getByRole('link', { name: 'Open review request', exact: true }).click();
  await page.getByRole('list', { name: 'Policy setting changes', exact: true }).getByText(/Unlisted extensions.*Block unlisted/).waitFor();
  assert.equal(await page.getByRole('button', { name: /Approve/ }).count(), 0);
  const [{ id: reviewId }] = (await admin('policy-reviews')).entries;
  await signOut();
  await signIn(reviewer.token);
  await page.goto(`${web}/reviews#review-${reviewId}`);
  await confirm('Approve and publish');
  await page.getByText('Approved by Canary deployment reviewer', { exact: true }).waitFor();
  const scoped = await admin(groupPath);
  assert.equal(scoped.length, 1);
  assert.equal(scoped[0].extensionDeployment.rules.length, 3);
  assert.deepEqual((await admin('policies'))[0].extensionDeployment.rules, []);

  await signOut();
  await signIn(auditor.token);
  await page.goto(scopeUrl);
  await page.getByRole('table', { name: 'Published plan', exact: true }).getByText('Force install', { exact: true }).waitFor();
  assert.equal(await rules.count(), 0);
  const source = page.getByLabel('Existing ExtensionSettings', { exact: true });
  const pinned = page.getByLabel('Pinned Zekvar Browser extension ID', { exact: true });
  const exportReview = page.getByRole('button', { name: 'Review export', exact: true });
  const downloadButton = 'Download Chrome policy';
  await exportReview.click();
  await page.getByRole('alert').getByText(/keep its force-install rule/).waitFor();
  const privateMessage = 'internal-canary-helpdesk-fixture';
  const original = {
    '*': { blocked_permissions: ['history'], runtime_blocked_hosts: ['*://*.internal.fixture.test'], blocked_install_message: privateMessage },
    [protectedId]: { installation_mode: 'force_installed', update_url: update, override_update_url: true },
    [`${blocked.id},${'e'.repeat(32)}`]: { toolbar_pin: 'default_unpinned' },
    'update_url:https://legacy.fixture.test/update.xml': { blocked_permissions: ['downloads'] },
  };
  await source.fill(JSON.stringify({ ...original, [`${allowed.id},${unlisted.id}`]: {}, [allowed.id]: {} }));
  await pinned.fill(protectedId);
  await exportReview.click();
  await page.getByRole('alert').getByText(/non-overlapping selectors/).waitFor();
  await source.fill(JSON.stringify({ ExtensionSettings: original }));
  await pinned.fill(blocked.id);
  await exportReview.click();
  await page.getByRole('alert').getByText(/Remove the pinned Zekvar Browser ID/).waitFor();
  await pinned.fill(protectedId);
  await exportReview.click();
  const changes = page.getByRole('list', { name: 'Chrome policy changes', exact: true });
  assert.equal(await changes.locator('li').count(), 4);
  const policy = await download(downloadButton);
  const rollback = await download('Download rollback policy');
  assert.equal(policy.name, `chrome-extension-settings-v${scoped[0].version}.json`);
  assert.equal(rollback.name, `chrome-extension-settings-v${scoped[0].version}-rollback.json`);
  assert.deepEqual(rollback.data, { ExtensionSettings: original });
  const merged = policy.data.ExtensionSettings;
  assert.equal(merged['*'].installation_mode, 'blocked');
  assert.deepEqual(merged[protectedId], original[protectedId]);
  assert.deepEqual(merged[allowed.id], { ...original['*'], installation_mode: 'allowed' });
  assert.deepEqual(merged[blocked.id], { toolbar_pin: 'default_unpinned', installation_mode: 'blocked' });
  assert.deepEqual(merged['e'.repeat(32)], { toolbar_pin: 'default_unpinned' });
  assert.deepEqual(merged['update_url:https://legacy.fixture.test/update.xml'], { blocked_permissions: ['downloads'] });
  assert.deepEqual(merged[forceId], { ...original['*'], installation_mode: 'force_installed', update_url: update, override_update_url: true });
  assert.ok(captured.every((content) => !content.includes(privateMessage)));
  await page.getByText('Review merged JSON', { exact: true }).click();
  await page.setViewportSize({ width: 390, height: 820 });
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth === document.documentElement.clientWidth));
  await page.setViewportSize({ width: 1440, height: 1000 });
  if (process.env.ZEKVAR_TEST_DEPLOYMENT_SCREENSHOT) {
    await page.screenshot({ path: process.env.ZEKVAR_TEST_DEPLOYMENT_SCREENSHOT, fullPage: true });
  }
  await source.fill('{}');
  assert.equal(await page.getByRole('button', { name: downloadButton }).count(), 0);
  assert.deepEqual(failures, []);

  const inventory = await browser.newPage();
  await inventory.goto('chrome://extensions');
  const settings = await browser.newPage();
  await settings.goto('chrome://policy/test');
  const row = settings.locator('policy-test-row').first();
  await row.locator('select.namespace').selectOption('chrome');
  await row.locator('input.name').fill('ExtensionSettings');
  await row.locator('select.preset').selectOption({ label: 'Local machine' });
  async function apply(dictionary) {
    await row.locator('input.value').fill(JSON.stringify(dictionary));
    await settings.getByRole('button', { name: 'Apply policies', exact: true }).click();
  }
  await waitForNativeState(inventory, { [allowed.id]: true, [blocked.id]: true, [unlisted.id]: true });
  await apply(merged);
  await waitForNativeState(inventory, { [allowed.id]: true, [blocked.id]: false, [unlisted.id]: false });
  await apply(rollback.data.ExtensionSettings);
  await waitForNativeState(inventory, { [allowed.id]: true, [blocked.id]: true, [unlisted.id]: true });
});
