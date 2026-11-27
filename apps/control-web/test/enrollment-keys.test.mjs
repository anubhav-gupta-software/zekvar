import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
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

async function redeem(key) {
  const response = await fetch(`${api}/v1/enroll/key`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ key, nonce: randomBytes(32).toString('hex') }), signal: AbortSignal.timeout(5000) });
  return { status: response.status, body: await response.json() };
}

async function assertFitsViewport(page) {
  const { clientWidth, scrollWidth } = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth, scrollWidth: document.documentElement.scrollWidth,
  }));
  assert.equal(scrollWidth, clientWidth);
}

async function signIn(page, token) {
  await page.goto(web);
  await page.getByLabel('Control token').fill(token);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByRole('heading', { name: 'Security overview' }).waitFor();
}

test('creates, monitors, rotates, and revokes a device-manager enrollment key with managed policy snippets', { timeout: 60_000 }, async (t) => {
  const browser = await chromium.launch({ channel: 'chromium', headless: process.env.ZEKVAR_DEMO_HEADED !== '1' });
  t.after(() => browser.close());
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: web });
  const page = await context.newPage();
  page.setDefaultTimeout(6000);
  const failures = [];
  const posted = [];
  page.on('pageerror', (error) => failures.push(error.message));
  page.on('request', (request) => { if (request.postData()) posted.push(request.postData()); });
  page.on('dialog', (dialog) => dialog.accept());
  const group = await admin('policy-groups', { name: `Jamf scope ${randomBytes(3).toString('hex')}` });
  await signIn(page, owner);
  let key;

  await t.test('shows a new scoped key once and builds Google Admin, Intune, Jamf, and Chrome JSON policy from it', async () => {
    await page.goto(`${web}/enrollment-keys`);
    await page.getByRole('heading', { name: 'Enrollment keys', level: 1 }).waitFor();
    await page.getByLabel('Label').fill('Finance laptops');
    await page.getByLabel('Rollout group').selectOption(group.id);
    await page.getByLabel('Lifetime in days').fill('7');
    await page.getByLabel('Maximum browsers').fill('3');
    await page.getByRole('button', { name: 'Create enrollment key' }).click();
    await page.getByRole('button', { name: 'Copy key' }).waitFor();
    key = await page.locator('#created-key').inputValue();
    assert.match(key, /^zke_[a-f0-9]{64}$/);
    await page.getByText(/Finance laptops · .* · up to 3 browsers · expires/).waitFor();
    await page.getByRole('button', { name: 'Copy key' }).click();
    await page.getByText('Enrollment key copied.').waitFor();
    assert.equal(await page.evaluate(() => navigator.clipboard.readText()), key);

    const extensionId = 'abcdefghijklmnopabcdefghijklmnop';
    const created = page.getByRole('group', { name: 'Managed policy snippet' }).first();
    await created.getByText('Enter the 32-letter extension ID of the signed release.').waitFor();
    await created.getByLabel('Extension ID').fill(extensionId);
    await created.getByLabel('Update URL').fill('http://updates.example.com/updates.xml');
    await created.getByLabel('Control origin').fill('https://browser.example.com');
    await created.getByText('Enter the HTTPS update manifest URL.').waitFor();
    await created.getByLabel('Update URL').fill('https://updates.example.com/pilot/updates.xml');
    const snippet = async (manager) => {
      await created.getByLabel('Device manager').selectOption({ label: manager });
      return created.getByLabel(`${manager} policy`).inputValue();
    };
    assert.deepEqual(JSON.parse(await snippet('Google Admin console')),
      { ControlOrigin: { Value: 'https://browser.example.com' }, EnrollmentKey: { Value: key } });
    const chromeJson = JSON.parse(await snippet('Chrome policy JSON · Linux and Group Policy'));
    assert.deepEqual(chromeJson['3rdparty'].extensions[extensionId], { ControlOrigin: 'https://browser.example.com', EnrollmentKey: key });
    assert.equal(chromeJson.ExtensionSettings[extensionId].installation_mode, 'force_installed');
    const intune = await snippet('Microsoft Intune · Windows');
    const [omaUri] = JSON.parse(intune.slice(0, intune.indexOf('\n\n#')));
    assert.equal(omaUri.omaUri, './Device/Vendor/MSFT/Policy/Config/Chrome~Policy~googlechrome~Extensions/ExtensionSettings');
    assert.match(omaUri.value, /^<enabled\/><data id="ExtensionSettings" value="\{&quot;abcdefghijklmnopabcdefghijklmnop&quot;/);
    assert.ok(intune.includes(`3rdparty\\extensions\\${extensionId}\\policy`) && intune.includes(`-Name 'EnrollmentKey' -PropertyType String -Value '${key}'`));
    const jamf = await snippet('Jamf Pro · macOS');
    assert.ok(jamf.includes(`<!-- Preference domain: com.google.Chrome.extensions.${extensionId} -->`));
    assert.ok(jamf.includes(`<key>EnrollmentKey</key><string>${key}</string>`));
    assert.ok(jamf.includes('<key>installation_mode</key><string>force_installed</string>'));
    await created.getByRole('button', { name: 'Copy policy' }).click();
    assert.equal(await page.evaluate(() => navigator.clipboard.readText()), jamf);

    await page.reload();
    assert.ok(!(await page.content()).includes(key.slice(4)));
    const row = page.getByRole('row').filter({ hasText: 'Finance laptops' });
    await row.getByText('0 of 3', { exact: true }).waitFor();
    await row.getByText(group.name, { exact: true }).waitFor();
    await row.getByText('Never', { exact: true }).waitFor();
  });

  await t.test('counts redemptions and rejected attempts and flags a key near its limit', async () => {
    const results = [await redeem(key), await redeem(key), await redeem(key), await redeem(key)];
    assert.deepEqual(results.map(({ status }) => status), [200, 200, 200, 410]);
    await page.reload();
    const row = page.getByRole('row').filter({ hasText: 'Finance laptops' });
    await row.getByText('3 of 3', { exact: true }).waitFor();
    await row.getByText('Limit reached', { exact: true }).waitFor();
    await row.getByRole('cell', { name: '1', exact: true }).waitFor();
    assert.notEqual(await row.locator('time').first().textContent(), 'Never');
    await row.getByRole('link', { name: 'Review 3 active browsers enrolled by Finance laptops' }).waitFor();

    const watched = await admin('enrollment-keys', { requestId: crypto.randomUUID(), label: 'Unlimited lab key', groupId: null, days: 1, maxRedemptions: null });
    await page.reload();
    const attention = page.getByRole('status').filter({ has: page.getByRole('heading', { name: 'Review key redemptions' }) });
    await attention.getByText('No redemption limit', { exact: false }).waitFor();
    await admin(`enrollment-keys/${watched.key.id}/revoke`, {}, 204);
  });

  await t.test('revokes the browsers a key enrolled from the filtered fleet view', async () => {
    await page.getByRole('link', { name: 'Review 3 active browsers enrolled by Finance laptops' }).click();
    await page.getByRole('heading', { name: 'Browser fleet' }).waitFor();
    await page.getByText('Showing active browsers enrolled by key').waitFor();
    await page.getByRole('status').getByText('Finance laptops', { exact: true }).waitFor();
    const rows = page.getByRole('table', { name: 'Active browsers' }).getByRole('row');
    assert.equal(await rows.count(), 4);
    await page.setViewportSize({ width: 390, height: 844 });
    await assertFitsViewport(page);
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.getByRole('button', { name: 'Select first 3 shown' }).click();
    await page.getByText('3 selected · Maximum 25').waitFor();
    await page.getByLabel('Action', { exact: true }).selectOption('revoke');
    await page.getByRole('button', { name: 'Review browser batch' }).click();
    await page.getByRole('button', { name: 'Revoke selected browsers' }).click();
    await page.getByText(/3 of 3 browsers changed/).waitFor();
    await page.goto(`${web}/enrollment-keys`);
    const row = page.getByRole('row').filter({ hasText: 'Finance laptops' });
    await row.getByRole('link', { name: 'Review 0 active browsers enrolled by Finance laptops' }).waitFor();
  });

  await t.test('rotates with an overlap window, then revokes the old key', async () => {
    const [current] = (await admin('enrollment-keys')).filter(({ label }) => label === 'Finance laptops');
    await page.getByLabel('Key to replace').selectOption(current.id);
    await page.getByLabel('Keep the old key for').selectOption('24');
    await page.getByRole('button', { name: 'Rotate enrollment key' }).click();
    await page.locator('#rotated-key').waitFor();
    const rotated = await page.locator('#rotated-key').inputValue();
    assert.match(rotated, /^zke_[a-f0-9]{64}$/);
    assert.notEqual(rotated, key);
    assert.equal((await redeem(rotated)).status, 200);
    assert.equal((await redeem(key)).body.code, 'enrollment_key_exhausted');
    await page.reload();
    const old = page.getByRole('row').filter({ hasText: current.id.slice(0, 13) }).filter({ hasNotText: 'rotated from' });
    await old.getByRole('button', { name: 'Revoke enrollment key Finance laptops' }).click();
    // The row's action cell disappears once the key is revoked, so its status is the confirmation.
    await old.getByText('Revoked', { exact: true }).waitFor();
    await page.reload();
    await page.getByRole('row').filter({ hasText: `rotated from ${current.id.slice(0, 13)}` }).getByText('1 of 3', { exact: true }).waitFor();
    assert.equal((await redeem(key)).body.code, 'enrollment_key_revoked');
    await page.setViewportSize({ width: 390, height: 844 });
    await assertFitsViewport(page);
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.goto(`${web}/audit?action=enrollment_key_issued`);
    await page.getByRole('cell', { name: 'Enrollment key issued' }).first().waitFor();
    await page.getByText(/Rotated from/).first().waitFor();
  });

  await t.test('lets an auditor review keys without changing them', async () => {
    const auditor = await admin('access', { name: 'Key auditor', role: 'auditor', hours: 1 });
    const review = await browser.newContext({ viewport: { width: 390, height: 844 } });
    t.after(() => review.close());
    const auditorPage = await review.newPage();
    auditorPage.setDefaultTimeout(6000);
    await signIn(auditorPage, auditor.token);
    await auditorPage.goto(`${web}/enrollment-keys`);
    await auditorPage.getByRole('table', { name: 'Keys' }).getByText('Finance laptops').first().waitFor();
    assert.equal(await auditorPage.getByRole('heading', { name: 'Create an enrollment key' }).count(), 0);
    assert.equal(await auditorPage.getByRole('heading', { name: 'Rotate a key' }).count(), 0);
    assert.equal(await auditorPage.getByRole('button', { name: /^Revoke enrollment key/ }).count(), 0);
    await assertFitsViewport(auditorPage);
  });

  assert.ok(!posted.some((body) => body.includes(key.slice(4))), 'The dashboard sent an enrollment key back to the server.');
  assert.deepEqual(failures, []);
});
