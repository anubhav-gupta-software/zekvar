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

test('Control halts, rolls back, and advances a staged rollout using an enrolled Chrome canary', { timeout: 150_000 }, async (t) => {
  const work = await mkdtemp(join(tmpdir(), 'zekvar-automated-rollout-'));
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
  const [initial] = await admin('policies');
  const [canary, pilot, staging] = await Promise.all(['Canary ring', 'Pilot ring', 'Staging ring'].map((name) => admin('policy-groups', { name })));
  const source = await admin(`policy-groups/${staging.id}/policies`, { mode: 'block' });
  const grant = await admin('enrollment-batches', { requestId: crypto.randomUUID(), groupId: canary.id, count: 1 });
  const canaryPolicy = async () => (await admin(`policy-groups/${canary.id}/policies`))[0];
  const applied = async (version) => (await admin('installations')).some((row) => row.appliedPolicyVersion === version);

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
  async function sync(mode, version) {
    await popup.getByRole('button', { name: 'Sync now', exact: true }).click();
    await connected(mode, version);
    await until(() => applied(version), `Control did not record acknowledgment of v${version}.`);
  }
  await connected('MONITOR', initial.version);

  const dashboard = await browser.newPage();
  dashboard.on('dialog', (dialog) => dialog.accept());
  await dashboard.setViewportSize({ width: 1440, height: 1000 });
  await dashboard.goto(web);
  await dashboard.getByLabel('Control token', { exact: true }).fill(owner);
  await dashboard.getByRole('button', { name: 'Sign in', exact: true }).click();
  await dashboard.getByRole('heading', { name: 'Security overview', exact: true }).waitFor();

  async function createPlan(name, stages) {
    await dashboard.goto(`${web}/rollouts?source=${source.version}`);
    await dashboard.getByLabel('Plan name', { exact: true }).fill(name);
    assert.equal(await dashboard.getByLabel('Policy version to roll out', { exact: true }).inputValue(), String(source.version));
    for (const [index, stage] of stages.entries()) {
      await dashboard.locator(`#stage${index}-target`).selectOption(stage.target);
      await dashboard.locator(`#stage${index}-soak`).fill(String(stage.soak));
      await dashboard.locator(`#stage${index}-ack`).fill(String(stage.ack));
      if (stage.blocks !== undefined) await dashboard.locator(`#stage${index}-blocks`).fill(String(stage.blocks));
    }
    await dashboard.getByRole('button', { name: 'Create rollout plan', exact: true }).click();
    await dashboard.getByRole('status').filter({ hasText: `${name} started. Stage 1 published as v` }).waitFor();
    await dashboard.goto(`${web}/rollouts`);
    await dashboard.getByRole('heading', { name, exact: true }).waitFor();
  }

  // Halt: a real block decision under the canary stage policy pauses the plan during its soak.
  await createPlan('Canary halt drill', [{ target: canary.id, soak: 60, ack: 0, blocks: 0 }]);
  const halting = await canaryPolicy();
  assert.equal(halting.mode, 'block');
  await sync('BLOCK', halting.version);
  const chat = await browser.newPage();
  const fixture = await readFile(new URL('./guest-chatgpt-composer.html', import.meta.url), 'utf8');
  await chat.route('https://chatgpt.com/**', (route) => route.fulfill({ contentType: 'text/html', body: fixture }));
  await chat.goto('https://chatgpt.com/');
  const field = chat.getByPlaceholder('Ask ChatGPT', { exact: true });
  await field.fill('ZEKVAR_TEST_SECRET');
  await field.press('Enter');
  await chat.getByRole('alert').filter({ hasText: 'Submission blocked' }).waitFor();
  await until(async () => (await admin('events')).some((event) => event.policyVersion === halting.version && event.decision === 'block'),
    'Control did not record the canary block decision.');
  await dashboard.reload();
  await dashboard.getByRole('alert').filter({ hasText: 'Paused at stage 1: Block events under the stage policy exceeded the limit.' }).waitFor();
  const blockRow = dashboard.getByRole('row').filter({ hasText: 'Block events' });
  await blockRow.getByText('At most 0', { exact: true }).waitFor();
  await blockRow.getByText('Fail', { exact: true }).waitFor();
  assert.doesNotMatch(await dashboard.content(), /ZEKVAR_TEST_SECRET/);
  for (const [width, height] of [[1440, 1000], [390, 844]]) {
    await dashboard.setViewportSize({ width, height });
    assert.equal(await dashboard.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `no horizontal scroll at ${width}px`);
    if (artifacts) {
      await mkdir(artifacts, { recursive: true });
      await dashboard.screenshot({ path: join(artifacts, `automated-rollout-paused-${width}.png`), fullPage: true });
    }
  }
  await dashboard.setViewportSize({ width: 1440, height: 1000 });

  // Rollback restores the canary's prior policy and the enrolled browser acknowledges it.
  await dashboard.getByRole('button', { name: 'Roll back plan', exact: true }).click();
  const badge = (name, status) => dashboard.getByRole('heading', { name, exact: true }).locator('..').getByText(status, { exact: true });
  await badge('Canary halt drill', 'Rolled back').waitFor();
  await dashboard.getByRole('row').filter({ hasText: 'Canary ring' }).getByText('Restored', { exact: true }).waitFor();
  const restored = await canaryPolicy();
  assert.equal(restored.restoredFrom, initial.version);
  assert.equal(restored.mode, initial.mode);
  await sync('MONITOR', restored.version);

  // Happy path: the canary must acknowledge before the plan advances to the pilot ring.
  await createPlan('Canary to pilot', [{ target: canary.id, soak: 0, ack: 100 }, { target: pilot.id, soak: 0, ack: 0 }]);
  await dashboard.getByRole('alert').filter({ hasText: 'Too few active browsers acknowledged the stage policy' }).waitFor();
  await dashboard.getByRole('row').filter({ hasText: 'Policy acknowledged' }).getByText('0 of 1 browsers (0%)', { exact: true }).waitFor();
  const canaryStage = await canaryPolicy();
  await sync('BLOCK', canaryStage.version);
  await dashboard.getByRole('button', { name: 'Resume rollout', exact: true }).click();
  await dashboard.getByRole('button', { name: 'Resume rollout', exact: true }).waitFor({ state: 'detached' });
  await dashboard.reload();
  await badge('Canary to pilot', 'Completed').waitFor();
  const pilotPolicy = (await admin(`policy-groups/${pilot.id}/policies`))[0];
  assert.equal(pilotPolicy.mode, 'block');
  const [plan] = await admin('rollout-plans');
  assert.deepEqual(plan.stages.map(({ publishedVersion }) => publishedVersion), [canaryStage.version, pilotPolicy.version]);
  assert.equal((await admin('policies'))[0].version, initial.version);

  await dashboard.goto(`${web}/audit?action=policy_published`);
  const automatic = dashboard.getByRole('row').filter({ hasText: `Canary to pilot · Stage published · Stage 2 · Pilot ring · v${pilotPolicy.version} · Automatic` });
  await automatic.getByText('Automated rollout', { exact: true }).waitFor();
});
