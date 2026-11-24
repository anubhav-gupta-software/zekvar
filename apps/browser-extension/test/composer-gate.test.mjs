import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const { ZEKVAR_DEMO_API: api, ZEKVAR_DEMO_WEB: web, ZEKVAR_DEMO_TOKEN: owner, ZEKVAR_DEMO_ARTIFACTS: artifacts } = process.env;
assert.match(api ?? '', /^http:\/\/127\.0\.0\.1:\d+$/);
assert.match(web ?? '', /^http:\/\/localhost:\d+$/);
assert.match(owner ?? '', /^[a-f0-9]{64}$/);

async function until(check, message) {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (await check()) return;
    await delay(150);
  }
  assert.fail(message);
}

test('Control publishes and approves checked drafts using an enrolled Chrome cohort', { timeout: 110_000 }, async (t) => {
  const work = await mkdtemp(join(tmpdir(), 'zekvar-composer-gate-'));
  const extension = join(work, 'extension');
  let browser;
  t.after(async () => {
    await browser?.close();
    await rm(work, { recursive: true, force: true });
  });
  async function admin(path, body, expected = 200) {
    const response = await fetch(`${api}/v1/admin/${path}`, {
      method: body ? 'POST' : 'GET', signal: AbortSignal.timeout(5000),
      headers: { Authorization: `Bearer ${owner}`, ...(body && { 'Content-Type': 'application/json' }) },
      body: body && JSON.stringify(body),
    });
    assert.equal(response.status, expected, path);
    return expected === 204 ? undefined : response.json();
  }
  const initial = (await admin('policies'))[0].version;
  const group = await admin('policy-groups', { name: 'Composer rollout pilot' });
  const grant = await admin('enrollment-batches', { requestId: crypto.randomUUID(), groupId: group.id, count: 1 });
  const groupPolicies = () => admin(`policy-groups/${group.id}/policies`);
  const report = async () => (await admin(`reports/policy-impact?scope=${group.id}`)).composers.find(({ appId }) => appId === 'chatgpt').counts;
  const env = { ...process.env, ZEKVAR_CONTROL_PORT: new URL(api).port, ZEKVAR_EXTENSION_OUTDIR: extension };
  delete env.ZEKVAR_CONTROL_ORIGIN;
  execFileSync(process.execPath, ['build.mjs'], { cwd: fileURLToPath(new URL('..', import.meta.url)), env });
  browser = await chromium.launchPersistentContext(join(work, 'profile'), {
    channel: 'chromium', headless: process.env.ZEKVAR_DEMO_HEADED !== '1',
    args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`],
  });
  browser.setDefaultTimeout(10_000);
  const worker = browser.serviceWorkers()[0] ?? await browser.waitForEvent('serviceworker');
  const popup = await browser.newPage();
  await popup.goto(new URL('popup.html', worker.url()).href);
  await popup.getByText('Ready to enroll', { exact: true }).waitFor();
  await popup.getByLabel('Enrollment grant').fill(grant.grants[0]);
  await popup.getByRole('button', { name: 'Enroll this browser', exact: true }).click();
  const connected = (mode, version) => popup.getByText(`Connected to Control · ${mode} v${version}`, { exact: true }).waitFor();
  await connected('MONITOR', initial);

  const dashboard = await browser.newPage();
  dashboard.on('dialog', (dialog) => dialog.accept());
  const preview = `/preview?group=${group.id}`;
  async function signIn(token) {
    await browser.clearCookies();
    await dashboard.goto(web);
    await dashboard.getByLabel('Control token', { exact: true }).fill(token);
    await dashboard.getByRole('button', { name: 'Sign in', exact: true }).click();
    await dashboard.getByRole('heading', { name: 'Security overview', exact: true }).waitFor();
  }
  const requirement = dashboard.getByRole('group', { name: 'Require fresh composer checks', exact: true });
  const chatgpt = requirement.getByRole('checkbox', { name: 'ChatGPT', exact: true });
  async function prepare(mode) {
    await dashboard.goto(web + preview);
    await dashboard.getByLabel('Draft test marker', { exact: true }).selectOption(mode);
    await dashboard.getByRole('button', { name: 'Run preview', exact: true }).click();
    await chatgpt.check();
  }
  await signIn(owner);
  await prepare('block');
  const publish = dashboard.getByRole('button', { name: 'Publish previewed policy', exact: true });
  await publish.click();
  await dashboard.getByRole('alert').filter({ hasText: 'Composer coverage is incomplete' }).waitFor();
  assert.equal(await chatgpt.isChecked(), true);
  assert.deepEqual(await groupPolicies(), []);
  if (artifacts) {
    await mkdir(artifacts, { recursive: true });
    await dashboard.setViewportSize({ width: 390, height: 844 });
    await requirement.scrollIntoViewIfNeeded();
    assert.equal(await dashboard.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    await dashboard.screenshot({ path: join(artifacts, 'composer-gate-incomplete.png') });
    await dashboard.setViewportSize({ width: 1280, height: 900 });
  }

  const chat = await browser.newPage();
  const fixture = await readFile(new URL('./guest-chatgpt-composer.html', import.meta.url), 'utf8');
  let supported = true;
  await chat.route('https://chatgpt.com/**', (route) => route.fulfill({
    contentType: 'text/html', body: supported ? fixture : '<main>Unsupported synthetic layout</main>',
  }));
  const field = chat.getByPlaceholder('Ask ChatGPT', { exact: true });
  async function observeReady() {
    supported = true;
    await chat.goto('https://chatgpt.com/');
    await field.fill('Synthetic composer draft');
    await until(async () => (await report()).detected === 1, 'Control did not observe the real fixture composer.');
  }
  await observeReady();
  await publish.click();
  await dashboard.getByRole('status').filter({ hasText: 'Previewed policy published as version' }).waitFor();
  const [block] = await groupPolicies();
  await popup.getByRole('button', { name: 'Sync now', exact: true }).click();
  await connected('BLOCK', block.version);
  await chat.reload();
  await field.fill('ZEKVAR_TEST_SECRET');
  await field.press('Enter');
  await chat.getByRole('alert').filter({ hasText: 'Submission blocked' }).waitFor();
  assert.equal(await chat.locator('#fixture-sends').textContent(), '0');
  await field.fill('Clean synthetic draft');
  await chat.getByRole('button', { name: 'Send message', exact: true }).click();
  await chat.locator('#fixture-sends').getByText('1', { exact: true }).waitFor();
  await until(async () => (await admin('events')).some((event) => event.policyVersion === block.version && event.decision === 'block'),
    'Control did not record the published policy decision.');
  assert.doesNotMatch(JSON.stringify(await admin('events')), /ZEKVAR_TEST_SECRET|Clean synthetic draft/);

  const [author, reviewer] = await Promise.all(['Pilot author', 'Pilot reviewer'].map((name) =>
    admin('access', { name, role: 'administrator', hours: 1 })));
  await admin('policy-reviews/setting', { required: true }, 204);
  await observeReady();
  await signIn(author.token);
  await prepare('warn');
  await dashboard.getByRole('button', { name: 'Request review of previewed policy', exact: true }).click();
  await dashboard.getByRole('link', { name: 'Open review request', exact: true }).waitFor();
  await signIn(reviewer.token);
  await dashboard.goto(web + '/reviews');
  await dashboard.getByText('Required composer checks · ChatGPT', { exact: true }).waitFor();
  supported = false;
  await chat.reload();
  await until(async () => (await report()).unsupported === 1, 'Control did not observe the unsupported fixture.');
  const approve = dashboard.getByRole('button', { name: 'Approve and publish', exact: true });
  await approve.click();
  await dashboard.getByRole('alert').filter({ hasText: 'Refresh the missing checks and retry approval' }).waitFor();
  assert.equal((await groupPolicies())[0].version, block.version);
  await observeReady();
  await approve.click();
  await dashboard.getByRole('article', { name: 'Publish policy for Composer rollout pilot', exact: true })
    .getByText('Approved', { exact: true }).waitFor();
  const [warn] = await groupPolicies();
  assert.equal(warn.mode, 'warn');
  assert.equal((await admin('policies'))[0].version, initial);
  await dashboard.goto(web + '/audit?action=policy_published');
  const evidence = dashboard.getByRole('row').filter({ hasText: `v${warn.version} · ChatGPT ready on 1 browser under v${block.version}` });
  await evidence.getByText('Pilot reviewer', { exact: true }).waitFor();
});
