import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { domainFixtureArgs, startDomainFixture } from './domain-fixture.mjs';

const { ZEKVAR_DEMO_API: api, ZEKVAR_DEMO_WEB: web, ZEKVAR_DEMO_TOKEN: owner, ZEKVAR_DEMO_ARTIFACTS: artifacts } = process.env;
assert.match(api ?? '', /^http:\/\/127\.0\.0\.1:\d+$/);
assert.match(web ?? '', /^http:\/\/localhost:\d+$/);
assert.match(owner ?? '', /^[a-f0-9]{64}$/);

async function admin(path, body) {
  const response = await fetch(`${api}/v1/admin/${path}`, {
    method: body ? 'POST' : 'GET', headers: { Authorization: `Bearer ${owner}`, 'Content-Type': 'application/json' },
    body: body && JSON.stringify(body), signal: AbortSignal.timeout(5000),
  });
  assert.equal(response.status, 200, path);
  return response.json();
}

test('assigns and revokes two real Browser profiles from a reviewed Control batch', { timeout: 90_000 }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'zekvar-browser-fleet-'));
  const contexts = [];
  const domains = await startDomainFixture();
  t.after(async () => {
    await Promise.all(contexts.map((context) => context.close()));
    await domains.close();
    await rm(root, { recursive: true, force: true });
  });
  const dist = join(root, 'extension');
  const env = { ...process.env, ZEKVAR_CONTROL_PORT: new URL(api).port, ZEKVAR_EXTENSION_OUTDIR: dist };
  delete env.ZEKVAR_CONTROL_ORIGIN;
  execFileSync(process.execPath, ['build.mjs'], { cwd: fileURLToPath(new URL('..', import.meta.url)), env });

  const [baseline] = await admin('policies');
  const group = await admin('policy-groups', { name: 'Fleet browser canary' });
  const scope = `policy-groups/${group.id}/policies`;
  const original = await admin(scope, { mode: 'block', domainRules: { allow: [], block: ['apps.test'] } });

  async function enroll(label) {
    const before = new Set((await admin('installations')).map(({ installationId }) => installationId));
    const context = await chromium.launchPersistentContext(join(root, label), {
      channel: 'chromium', headless: process.env.ZEKVAR_DEMO_HEADED !== '1',
      args: [...domainFixtureArgs, `--disable-extensions-except=${dist}`, `--load-extension=${dist}`],
    });
    contexts.push(context);
    context.setDefaultTimeout(7000);
    const worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker');
    const popup = await context.newPage();
    await popup.goto(new URL('popup.html', worker.url()).href);
    const { grant } = await admin('enrollment-grants', {});
    await popup.getByLabel('Enrollment grant', { exact: true }).fill(grant);
    await popup.getByRole('button', { name: 'Enroll this browser', exact: true }).click();
    await popup.getByText(`Connected to Control · MONITOR v${baseline.version}`, { exact: true }).waitFor();
    const installed = (await admin('installations')).find(({ installationId }) => !before.has(installationId));
    assert.ok(installed?.assignmentAware);
    return { context, popup, id: installed.installationId };
  }

  const [first, second, untouched] = [await enroll('first'), await enroll('second'), await enroll('baseline')];
  await domains.visit(first.context, 'apps.test', false);
  await domains.visit(second.context, 'apps.test', false);
  const dashboard = await first.context.newPage();
  async function signIn(token) {
    await dashboard.goto(web);
    await dashboard.getByLabel('Control token').fill(token);
    await dashboard.getByRole('button', { name: 'Sign in', exact: true }).click();
    await dashboard.getByRole('heading', { name: 'Security overview', exact: true }).waitFor();
  }
  await signIn(owner);
  await dashboard.getByRole('link', { name: 'Browser fleet', exact: true }).click();
  const rows = dashboard.getByRole('table', { name: 'Active browsers', exact: true });
  const row = ({ id }) => rows.getByRole('row').filter({ hasText: id.slice(0, 13) });
  const review = dashboard.getByRole('button', { name: 'Review browser batch', exact: true });
  assert.equal(await review.isDisabled(), true);
  async function selectPair() {
    await row(first).getByRole('checkbox').check();
    await row(second).getByRole('checkbox').check();
  }
  async function assignPair() {
    await dashboard.getByLabel('Destination', { exact: true }).selectOption(group.id);
    await selectPair();
    await review.click();
    const selection = dashboard.getByRole('list', { name: 'Browsers in this batch', exact: true });
    assert.equal(await selection.locator('li').count(), 2);
    assert.equal(await selection.getByText(untouched.id.slice(0, 13), { exact: true }).count(), 0);
  }
  async function confirm(label, accept = true) {
    dashboard.once('dialog', (dialog) => accept ? dialog.accept() : dialog.dismiss());
    await dashboard.getByRole('button', { name: label, exact: true }).click();
  }

  await assignPair();
  assert.equal(await row(first).getByRole('checkbox').isDisabled(), true);
  await dashboard.getByRole('button', { name: 'Edit selection', exact: true }).click();
  assert.equal(await row(first).getByRole('checkbox').isChecked(), true);
  await review.click();
  await confirm('Assign selected browsers', false);
  assert.equal((await admin(`installations/fleet?rolloutGroup=${group.id}`)).entries.length, 0);
  const latest = await admin(scope, { mode: 'block' });
  assert.ok(latest.version > original.version);
  await confirm('Assign selected browsers');
  await dashboard.getByRole('alert').getByText(/destination policy changed/).waitFor();
  assert.equal((await admin(`installations/fleet?rolloutGroup=${group.id}`)).entries.length, 0);
  await dashboard.reload();
  await assignPair();
  await confirm('Assign selected browsers');
  await dashboard.getByRole('status').getByText(/2 of 2 browsers changed/).waitFor();
  await row(first).getByText(group.name, { exact: true }).waitFor();
  await row(second).getByText(group.name, { exact: true }).waitFor();
  await row(untouched).getByText('Organization baseline', { exact: true }).waitFor();
  const assigned = (await admin(`installations/fleet?rolloutGroup=${group.id}`)).entries;
  assert.deepEqual(assigned.map(({ installationId }) => installationId).sort(), [first.id, second.id].sort());
  assert.ok(assigned.every(({ expectedPolicyVersion, assignmentVersion }) => expectedPolicyVersion === latest.version && assignmentVersion === 1));

  for (const { popup } of [first, second]) {
    await popup.getByRole('button', { name: 'Sync now', exact: true }).click();
    await popup.getByText(`Connected to Control · BLOCK v${latest.version}`, { exact: true }).waitFor();
  }
  await domains.visit(first.context, 'apps.test', true);
  await domains.visit(second.context, 'redirect.test', true);
  await domains.visit(untouched.context, 'apps.test', false);

  await dashboard.getByLabel('Rollout group', { exact: true }).selectOption(group.id);
  await dashboard.getByRole('button', { name: 'Filter fleet', exact: true }).click();
  await dashboard.waitForURL((url) => url.searchParams.get('rolloutGroup') === group.id);
  assert.equal(await rows.locator('tbody tr').count(), 2);
  await dashboard.getByLabel('Action', { exact: true }).selectOption('revoke');
  await selectPair();
  await review.click();
  await confirm('Revoke selected browsers', false);
  assert.equal((await admin(`installations/fleet?rolloutGroup=${group.id}`)).entries.length, 2);
  const viewport = dashboard.viewportSize();
  await dashboard.setViewportSize({ width: 390, height: 820 });
  assert.equal(await dashboard.evaluate(() => document.documentElement.scrollWidth), 390);
  if (viewport) await dashboard.setViewportSize(viewport);
  if (artifacts) await dashboard.screenshot({ path: join(artifacts, 'browser-fleet-review.png'), fullPage: true });
  await confirm('Revoke selected browsers');
  await dashboard.getByRole('status').getByText(/2 of 2 browsers changed/).waitFor();
  await dashboard.getByText('No active browsers match this view.', { exact: true }).waitFor();
  for (const { popup } of [first, second]) {
    await popup.getByRole('button', { name: 'Sync now', exact: true }).click();
    await popup.getByText(/revoked/i).first().waitFor();
  }
  await domains.visit(untouched.context, 'apps.test', false);
  await dashboard.getByRole('link', { name: 'Review fleet audit', exact: true }).click();
  const audit = dashboard.getByRole('table', { name: 'Control activity', exact: true });
  await audit.getByText(/Assigned to Fleet browser canary.*2 of 2 changed/).waitFor();
  await audit.getByText(/Revoked browser access.*2 of 2 changed/).waitFor();
  assert.equal((await admin('audit?action=browser_fleet_changed')).entries.length, 2);

  const auditor = await admin('access', { name: 'Fleet lab auditor', role: 'auditor', hours: 1 });
  await dashboard.getByRole('button', { name: 'Sign out', exact: true }).click();
  await signIn(auditor.token);
  await dashboard.getByRole('link', { name: 'Browser fleet', exact: true }).click();
  await row(untouched).getByText('Organization baseline', { exact: true }).waitFor();
  assert.equal(await dashboard.getByRole('checkbox').count(), 0);
  assert.equal(await review.count(), 0);
  await dashboard.goto(`${web}/fleet?rolloutGroup=bad-group`);
  await dashboard.getByRole('alert').getByText(/fleet page is unavailable/).waitFor();
});
