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

async function admin(path, body, expected = 200) {
  const response = await fetch(`${api}/v1/admin/${path}`, {
    method: body ? 'POST' : 'GET', headers: { Authorization: `Bearer ${owner}`, 'Content-Type': 'application/json' },
    body: body && JSON.stringify(body), signal: AbortSignal.timeout(5000),
  });
  assert.equal(response.status, expected, path);
  return expected === 204 ? undefined : response.json();
}

test('reuses a pinned policy template across two Chromium cohorts with independent rollback', { timeout: 100_000 }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'zekvar-template-test-'));
  const domains = await startDomainFixture();
  const contexts = [];
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
  const [sourceGroup, early, later] = await Promise.all(['Template authoring group', 'Early cohort', 'Later cohort']
    .map((name) => admin('policy-groups', { name })));
  const scope = ({ id }) => `policy-groups/${id}/policies`;
  const sourceReason = 'Private source-scoped fixture exception';
  const source = await admin(scope(sourceGroup), { mode: 'block', domainRules: { allow: [], block: ['apps.test'] },
    promptExceptions: [{ appId: 'chatgpt', ruleId: 'fixture-secret', expiresAt: new Date(Date.now() + 3600_000).toISOString(), reason: sourceReason }] });

  async function launch(group) {
    const previous = new Set((await admin('installations')).map(({ installationId }) => installationId));
    const context = await chromium.launchPersistentContext(join(root, group.id), {
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
    const installed = (await admin('installations')).find(({ installationId }) => !previous.has(installationId));
    assert.ok(installed?.assignmentAware);
    await admin(`installations/${installed.installationId}/policy-group`, { groupId: group.id }, 204);
    return { context, popup };
  }
  const one = await launch(early);
  const two = await launch(later);
  const dashboard = await one.context.newPage();
  async function signIn(token) {
    await dashboard.goto(web);
    await dashboard.getByLabel('Control token').fill(token);
    await dashboard.getByRole('button', { name: 'Sign in', exact: true }).click();
    await dashboard.getByRole('heading', { name: 'Security overview', exact: true }).waitFor();
  }
  async function signOut() {
    await dashboard.getByRole('button', { name: 'Sign out', exact: true }).click();
    await dashboard.getByRole('heading', { name: 'Sign in to Control', exact: true }).waitFor();
  }
  async function confirm(label, accept = true) {
    dashboard.once('dialog', (dialog) => accept ? dialog.accept() : dialog.dismiss());
    await dashboard.getByRole('button', { name: label, exact: true }).click();
  }
  const library = dashboard.getByRole('navigation', { name: 'Saved templates', exact: true });
  const changes = dashboard.getByRole('list', { name: 'Policy setting changes', exact: true });
  const name = 'AI workstation controls';
  await signIn(owner);
  await dashboard.getByRole('link', { name: 'Policy templates', exact: true }).click();
  await dashboard.getByText(/No active templates/).waitFor();
  await dashboard.getByLabel('Source scope', { exact: true }).selectOption(sourceGroup.id);
  await dashboard.getByRole('button', { name: 'Load source policies', exact: true }).click();
  await dashboard.waitForURL((url) => url.searchParams.get('sourceGroup') === sourceGroup.id);
  await dashboard.getByLabel('Template name', { exact: true }).fill(name);
  await dashboard.getByLabel('Source policy version', { exact: true }).selectOption(String(source.version));
  await dashboard.getByRole('button', { name: 'Create template', exact: true }).click();
  await library.getByRole('link', { name: new RegExp(name) }).waitFor();
  const [template] = await admin('policy-templates');
  assert.equal(template.sourceVersion, source.version);
  const templateUrl = `${web}/templates?template=${template.id}`;
  await dashboard.waitForURL(templateUrl);

  async function compare(group, revision = 1) {
    await dashboard.getByLabel('Template revision', { exact: true }).selectOption(String(revision));
    await dashboard.getByLabel('Destination policy', { exact: true }).selectOption(group.id);
    await dashboard.getByRole('button', { name: 'Compare settings', exact: true }).click();
    await dashboard.waitForURL((url) => url.searchParams.get('targetGroup') === group.id && url.searchParams.get('revision') === String(revision));
    await changes.getByText(/Add to domain block list.*apps.test/).waitFor();
    assert.ok(!(await dashboard.content()).includes(sourceReason));
  }
  await compare(early);
  const earlyBefore = await admin(scope(early), { mode: 'warn' });
  await confirm('Apply template');
  await dashboard.getByRole('alert').filter({ hasText: /The destination policy changed/ }).waitFor();
  assert.equal((await admin(scope(early)))[0].version, earlyBefore.version);
  await domains.visit(one.context, 'apps.test', false);
  if (artifacts) await dashboard.screenshot({ path: join(artifacts, 'template-stale-comparison.png') });

  const author = await admin('access', { name: 'Lab template author', role: 'administrator', hours: 1 });
  const reviewer = await admin('access', { name: 'Lab template reviewer', role: 'administrator', hours: 1 });
  const auditor = await admin('access', { name: 'Lab template auditor', role: 'auditor', hours: 1 });
  await admin('policy-reviews/setting', { required: true }, 204);
  await signOut();
  await signIn(author.token);
  await dashboard.goto(templateUrl);
  await compare(early);
  const viewport = dashboard.viewportSize();
  await dashboard.setViewportSize({ width: 390, height: 820 });
  await dashboard.waitForFunction(() => window.innerWidth === 390);
  assert.ok(await dashboard.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth));
  if (viewport) await dashboard.setViewportSize(viewport);
  if (artifacts) await dashboard.screenshot({ path: join(artifacts, 'policy-template-comparison.png') });
  await confirm('Request template review');
  await dashboard.getByRole('link', { name: 'Open review request', exact: true }).click();
  await dashboard.getByText(/Template AI workstation controls.*revision 1/).waitFor();
  assert.equal(await dashboard.getByRole('button', { name: 'Approve and publish', exact: true }).count(), 0);
  const [{ id: reviewId }] = (await admin('policy-reviews')).entries;
  assert.equal((await admin(scope(early)))[0].version, earlyBefore.version);

  await dashboard.goto(templateUrl);
  await dashboard.getByLabel('Source policy version', { exact: true }).selectOption(String(baseline.version));
  await dashboard.getByRole('button', { name: 'Save template revision', exact: true }).click();
  await dashboard.getByText(/Current template revision 2/).waitFor();
  assert.equal((await admin('policy-templates'))[0].revision, 2);
  await signOut();
  await signIn(reviewer.token);
  await dashboard.goto(`${web}/reviews#review-${reviewId}`);
  await confirm('Approve and publish');
  await dashboard.getByText('Approved by Lab template reviewer', { exact: true }).waitFor();
  const [firstPolicy] = await admin(scope(early));
  assert.equal(firstPolicy.mode, 'block');
  assert.deepEqual(firstPolicy.promptExceptions, []);

  async function sync(profile, mode, version) {
    await profile.popup.getByRole('button', { name: 'Sync now', exact: true }).click();
    await profile.popup.getByText(`Connected to Control · ${mode.toUpperCase()} v${version}`, { exact: true }).waitFor();
  }
  await sync(one, 'block', firstPolicy.version);
  await domains.visit(one.context, 'redirect.test', true);
  await domains.visit(two.context, 'apps.test', false);

  await signOut();
  await signIn(auditor.token);
  await dashboard.goto(templateUrl);
  await compare(later);
  assert.equal(await dashboard.getByRole('button', { name: 'Request template review', exact: true }).count(), 0);
  assert.equal(await dashboard.getByRole('button', { name: 'Save template revision', exact: true }).count(), 0);
  await admin('policy-reviews/setting', { required: false }, 204);
  await signOut();
  await signIn(reviewer.token);
  await dashboard.goto(templateUrl);
  await compare(later);
  await confirm('Apply template');
  await dashboard.getByText(/Template revision 1 published as policy/).waitFor();
  const [secondPolicy] = await admin(scope(later));
  assert.deepEqual(secondPolicy.domainRules, firstPolicy.domainRules);
  await sync(two, 'block', secondPolicy.version);
  await domains.visit(two.context, 'apps.test', true);

  const restored = await admin(`${scope(early)}/${earlyBefore.version}/restore`, {});
  await sync(one, 'warn', restored.version);
  await domains.visit(one.context, 'apps.test', false);
  await domains.visit(two.context, 'apps.test', true);
  await admin('policy-reviews/setting', { required: true }, 204);
  await dashboard.goto(templateUrl);
  await compare(early);
  await confirm('Request template review');
  await dashboard.getByRole('link', { name: 'Open review request', exact: true }).waitFor();
  const [{ id: archivedReviewId }] = (await admin('policy-reviews')).entries;
  await confirm('Archive template', false);
  assert.equal((await admin('policy-templates')).length, 1);
  await confirm('Archive template');
  await dashboard.waitForURL(`${web}/templates`);
  await dashboard.getByText(/No active templates/).waitFor();
  assert.equal((await admin(scope(later)))[0].version, secondPolicy.version);
  await signOut();
  await signIn(author.token);
  await dashboard.goto(`${web}/reviews#review-${archivedReviewId}`);
  await confirm('Approve and publish');
  const archivedReview = dashboard.locator(`#review-${archivedReviewId}`);
  await archivedReview.getByText('Stale', { exact: true }).waitFor();
  await archivedReview.getByText(/Check the destination policy, template availability/).waitFor();
  assert.equal((await admin(scope(early)))[0].version, restored.version);
  await dashboard.goto(`${web}/audit?action=policy_template_changed`);
  const activity = dashboard.getByRole('table', { name: 'Control activity', exact: true });
  await activity.getByText(new RegExp(`${name}.*Revision 2.*archived`)).waitFor();
  await activity.getByText(new RegExp(`${name}.*Revision 1.*applied.*v${secondPolicy.version}`)).waitFor();
  const audit = await admin('audit?action=policy_template_changed');
  assert.equal(audit.entries.filter(({ templateChange }) => templateChange.operation === 'applied').length, 2);
  assert.ok(!JSON.stringify(audit).includes(sourceReason));
});
