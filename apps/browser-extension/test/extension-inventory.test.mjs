import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const api = process.env.ZEKVAR_DEMO_API;
const web = process.env.ZEKVAR_DEMO_WEB;
const owner = process.env.ZEKVAR_DEMO_TOKEN;
const artifacts = process.env.ZEKVAR_DEMO_ARTIFACTS;
assert.match(api ?? '', /^http:\/\/127\.0\.0\.1:\d+$/);
assert.match(web ?? '', /^http:\/\/localhost:\d+$/);
assert.match(owner ?? '', /^[a-f0-9]{64}$/);

test('Chrome inventory follows the policy and permission, with metadata-only updates and retry', { timeout: 100_000 }, async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'zekvar-inventory-'));
  const dist = join(dir, 'extension');
  const inspector = join(dir, 'inspector');
  const utility = join(dir, 'utility');
  const reviewExtension = join(dir, 'review-extension');
  const profiles = new Set();
  const reported = [];
  let dropAcknowledgment = false;
  const proxy = createServer(async (incoming, outgoing) => {
    try {
      if (!incoming.url?.startsWith('/v1/browser/') && incoming.url !== '/v1/enroll') return outgoing.writeHead(404).end();
      const chunks = [];
      for await (const chunk of incoming) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      const isInventory = incoming.url === '/v1/browser/extension-inventory';
      if (isInventory) reported.push(JSON.parse(body.toString()));
      const response = await fetch(api + incoming.url, {
        method: incoming.method,
        headers: {
          ...(incoming.headers.authorization ? { Authorization: incoming.headers.authorization } : {}),
          ...(incoming.headers['x-zekvar-assignment-aware'] ? { 'X-Zekvar-Assignment-Aware': '1' } : {}),
          ...(body.length ? { 'Content-Type': 'application/json' } : {}),
        },
        body: body.length ? body : undefined,
        signal: AbortSignal.timeout(5000),
      });
      if (isInventory && response.ok && dropAcknowledgment) {
        dropAcknowledgment = false;
        return outgoing.writeHead(503).end();
      }
      outgoing.writeHead(response.status, { 'Content-Type': 'application/json' }).end(await response.text());
    } catch {
      outgoing.writeHead(502).end();
    }
  });
  proxy.listen(0, '127.0.0.1');
  await once(proxy, 'listening');
  t.after(async () => {
    await Promise.allSettled([...profiles].map((profile) => profile.close()));
    await new Promise((resolve) => {
      proxy.close(resolve);
      proxy.closeAllConnections();
    });
    await rm(dir, { recursive: true, force: true });
  });
  execFileSync(process.execPath, ['build.mjs'], {
    cwd: fileURLToPath(new URL('..', import.meta.url)),
    env: { ...process.env, ZEKVAR_CONTROL_PORT: String(proxy.address().port), ZEKVAR_EXTENSION_OUTDIR: dist },
  });
  await Promise.all([mkdir(inspector), mkdir(utility), mkdir(reviewExtension)]);
  const fingerprint = 'private-inventory.example.test';
  const inspectionManifest = { manifest_version: 3, name: 'Inventory Inspector Fixture', version: '1.0',
    permissions: ['cookies', 'tabs', 'storage'], host_permissions: ['https://*/*'] };
  await writeFile(join(inspector, 'manifest.json'), JSON.stringify(inspectionManifest));
  await Promise.all([
    writeFile(join(utility, 'manifest.json'), JSON.stringify({ manifest_version: 3, name: 'Inventory Utility Fixture',
      version: '2.1', permissions: ['storage'], host_permissions: ['https://' + fingerprint + '/*'],
      description: 'Private fixture description', homepage_url: 'https://' + fingerprint })),
    writeFile(join(utility, 'remove.html'), '<meta charset="utf-8"><button>Remove fixture</button><script src="remove.js"></script>'),
    writeFile(join(utility, 'remove.js'), "document.querySelector('button').onclick = () => chrome.management.uninstallSelf();\n"),
    writeFile(join(reviewExtension, 'manifest.json'), JSON.stringify({ manifest_version: 3, name: 'New Review Fixture', version: '1.0',
      permissions: ['cookies'], host_permissions: ['https://*/*'] })),
  ]);

  async function launch(name, additional = []) {
    const extensions = [dist, inspector, utility, ...additional].join(',');
    const browser = await chromium.launchPersistentContext(join(dir, name), {
      channel: 'chromium', headless: process.env.ZEKVAR_DEMO_HEADED !== '1',
      args: ['--disable-extensions-except=' + extensions, '--load-extension=' + extensions],
    });
    profiles.add(browser);
    browser.setDefaultTimeout(9000);
    return browser;
  }
  const workerFor = async (browser) => browser.serviceWorkers()[0] ?? browser.waitForEvent('serviceworker');
  const openPopup = async (browser) => {
    const worker = await workerFor(browser);
    const popup = await browser.newPage();
    await popup.goto(new URL('popup.html', worker.url()).href);
    return { popup, worker };
  };
  // Seed the granted state in an isolated profile. Tests below use the restored optional manifest.
  const manifestPath = join(dist, 'manifest.json');
  const optional = await readFile(manifestPath, 'utf8');
  const seedManifest = JSON.parse(optional);
  seedManifest.permissions.push('management');
  delete seedManifest.optional_permissions;
  await writeFile(manifestPath, JSON.stringify(seedManifest));
  const seed = await launch('consented');
  assert.ok(await (await workerFor(seed)).evaluate(() => chrome.permissions.contains({ permissions: ['management'] })));
  await seed.close();
  profiles.delete(seed);
  await writeFile(manifestPath, optional);

  const browser = await launch('consented');
  let { popup, worker } = await openPopup(browser);
  assert.ok(await worker.evaluate(() => chrome.runtime.getManifest().optional_permissions.includes('management')));
  assert.ok(await worker.evaluate(() => chrome.permissions.contains({ permissions: ['management'] })));

  let dashboard = await browser.newPage();
  await dashboard.goto(web);
  await dashboard.getByLabel('Control token', { exact: true }).fill(owner);
  await dashboard.getByRole('button', { name: 'Sign in', exact: true }).click();
  await dashboard.getByRole('heading', { name: 'Security overview', exact: true }).waitFor();
  const enroll = async (extensionPopup) => {
    await dashboard.getByRole('button', { name: 'Create enrollment grant', exact: true }).click();
    const grant = await dashboard.getByLabel('Enrollment grant', { exact: true }).inputValue();
    await extensionPopup.getByLabel('Enrollment grant', { exact: true }).fill(grant);
    await extensionPopup.getByRole('button', { name: 'Enroll this browser', exact: true }).click();
    await extensionPopup.getByText(/^Connected to Control/).waitFor();
  };
  const sync = async (tab = popup) => {
    await tab.getByRole('button', { name: 'Sync now', exact: true }).click();
    await tab.waitForFunction(() => !document.querySelector('#sync').disabled);
  };
  const installationId = () => worker.evaluate(async () => (await chrome.storage.local.get('controlState')).controlState.enrollment.installationId);
  const inventory = async (id) => {
    const response = await fetch(api + '/v1/admin/extension-inventory/' + id, {
      headers: { Authorization: 'Bearer ' + owner }, signal: AbortSignal.timeout(5000),
    });
    assert.equal(response.status, 200);
    return response.json();
  };
  await enroll(popup);
  const id = await installationId();
  const baseline = await inventory(id);
  assert.equal(baseline.status, 'off');
  assert.deepEqual(reported, []);
  await dashboard.getByLabel('Extension inventory', { exact: true }).selectOption('on');
  await dashboard.getByRole('button', { name: 'Publish policy', exact: true }).click();
  await dashboard.getByText('Version 2 published in monitor mode.', { exact: true }).waitFor();
  await sync();
  await popup.getByText('Extension inventory reported to Control.', { exact: true }).waitFor();
  const actual = await inventory(id);
  assert.deepEqual(actual.changeHistory, []);
  const entry = (name) => actual.entries.find((item) => item.name === name);
  const inspectorId = entry('Inventory Inspector Fixture').id;
  const utilityId = entry('Inventory Utility Fixture').id;
  assert.deepEqual(entry('Inventory Inspector Fixture'), { id: inspectorId, name: 'Inventory Inspector Fixture', version: '1.0',
    enabled: true, installType: 'development', siteAccess: 'all', permissions: ['cookies', 'tabs'] });
  assert.deepEqual(entry('Inventory Utility Fixture'), { id: utilityId, name: 'Inventory Utility Fixture', version: '2.1',
    enabled: true, installType: 'development', siteAccess: 'selected', permissions: [] });
  assert.equal(actual.entries.some(({ name }) => name === 'Zekvar Browser'), false);
  const firstReportCount = reported.length;
  await sync();
  await sync();
  assert.equal(reported.length, firstReportCount);

  const clean = await launch('unconsented');
  const second = await openPopup(clean);
  await dashboard.reload();
  await enroll(second.popup);
  await second.popup.getByRole('button', { name: 'Allow extension inventory', exact: true }).waitFor();
  assert.ok(!await second.worker.evaluate(() => chrome.permissions.contains({ permissions: ['management'] })));
  const secondId = await second.worker.evaluate(async () => (await chrome.storage.local.get('controlState')).controlState.enrollment.installationId);
  assert.equal((await inventory(secondId)).status, 'permission_required');
  assert.equal(reported.at(-1).entries.length, 0);
  await clean.close();
  profiles.delete(clean);

  const path = '/extensions?browser=' + id;
  await dashboard.getByRole('link', { name: 'Browser extensions', exact: true }).click();
  await dashboard.getByRole('link', { name: 'View extensions for ' + id, exact: true }).click();
  const monitorTable = () => dashboard.getByRole('table', { name: /^Extensions on / });
  await monitorTable().getByText('Broad site access', { exact: true }).waitFor();
  await monitorTable().getByText('cookies, tabs', { exact: true }).waitFor();
  for (const name of ['Inventory Inspector Fixture', 'Inventory Utility Fixture']) {
    await monitorTable().getByRole('row').filter({ hasText: name }).getByText('Review', { exact: true }).waitFor();
  }
  assert.equal((await dashboard.content()).includes(fingerprint), false);
  if (artifacts) await dashboard.screenshot({ path: join(artifacts, '24-control-extension-inventory.png'), fullPage: true });
  await dashboard.setViewportSize({ width: 390, height: 844 });
  assert.ok(await dashboard.evaluate(() => document.documentElement.scrollWidth === document.documentElement.clientWidth));

  const manager = await browser.newPage();
  await manager.goto('chrome://extensions/');
  const card = manager.locator('extensions-item').filter({ hasText: 'Inventory Inspector Fixture' });
  await card.locator('#enableToggle').click();
  dropAcknowledgment = true;
  await sync();
  await popup.getByText('Extension inventory is unavailable. Zekvar will retry.', { exact: true }).waitFor();
  await popup.getByText('Connected to Control · MONITOR v2', { exact: true }).waitFor();
  assert.ok(!dropAcknowledgment);
  const firstDisabled = (await inventory(id)).entries.find(({ id }) => id === inspectorId);
  assert.equal(firstDisabled.enabled, false);
  const beforeRetry = reported.length;
  await sync();
  await popup.getByText('Extension inventory reported to Control.', { exact: true }).waitFor();
  assert.equal(reported.length, beforeRetry + 1);
  const disabledHistory = (await inventory(id)).changeHistory;
  assert.equal(disabledHistory.length, 1);
  assert.deepEqual(disabledHistory[0].changes.map(({ extensionId, before, after }) => [extensionId, before.enabled, after.enabled]),
    [[inspectorId, true, false]]);
  await dashboard.reload();
  await monitorTable().getByRole('row').filter({ hasText: 'Inventory Inspector Fixture' }).getByText('Disabled', { exact: true }).waitFor();
  const removal = await browser.newPage();
  await removal.goto('chrome-extension://' + utilityId + '/remove.html');
  await removal.getByRole('button', { name: 'Remove fixture', exact: true }).click();
  await manager.locator('extensions-item').filter({ hasText: 'Inventory Utility Fixture' }).waitFor({ state: 'detached' });
  await sync();
  assert.equal((await inventory(id)).entries.some(({ id }) => id === utilityId), false);
  const removed = (await inventory(id)).changeHistory[0].changes.find(({ extensionId }) => extensionId === utilityId);
  assert.equal(removed.before.version, '2.1');
  assert.equal(removed.after, null);
  await browser.close();
  profiles.delete(browser);

  await writeFile(join(inspector, 'manifest.json'), JSON.stringify({ ...inspectionManifest, version: '1.2',
    permissions: ['tabs'], host_permissions: [] }));
  const restarted = await launch('consented', [reviewExtension]);
  ({ popup, worker } = await openPopup(restarted));
  await popup.getByText('Extension inventory reported to Control.', { exact: true }).waitFor();
  assert.equal(await installationId(), id);
  const updated = (await inventory(id)).entries.find(({ id }) => id === inspectorId);
  assert.equal(updated.version, '1.2');
  assert.deepEqual(updated.permissions, ['tabs']);
  assert.equal(updated.siteAccess, 'none');
  const withUpdate = await inventory(id);
  const latest = withUpdate.changeHistory[0];
  const changed = latest.changes.find(({ extensionId }) => extensionId === inspectorId);
  const added = latest.changes.find(({ extensionId }) => extensionId === withUpdate.entries.find(({ name }) => name === 'New Review Fixture').id);
  assert.deepEqual([changed.before.version, changed.after.version, changed.before.siteAccess, changed.after.siteAccess], ['1.0', '1.2', 'all', 'none']);
  assert.deepEqual([added.before, added.after.siteAccess, added.after.permissions], [null, 'all', ['cookies']]);
  assert.doesNotMatch(JSON.stringify(withUpdate.changeHistory), /Inventory Inspector Fixture|Inventory Utility Fixture|New Review Fixture|private-inventory|hostPermissions/);
  dashboard = await restarted.newPage();
  await dashboard.goto(web + path);
  await monitorTable().getByText('1.2', { exact: true }).waitFor();
  const history = dashboard.getByRole('region', { name: 'Extension change history', exact: true });
  await history.locator('summary').first().getByText(/\d:\d{2}:\d{2} [AP]M UTC/).waitFor();
  await history.getByText('1.0 → 1.2', { exact: false }).waitFor();
  await history.getByRole('row').filter({ hasText: 'New Review Fixture' }).getByText('Review access', { exact: true }).waitFor();
  await history.locator('details').nth(1).locator('summary').click();
  await history.getByRole('row').filter({ hasText: utilityId }).getByText('Removed', { exact: true }).waitFor();
  if (artifacts) await history.screenshot({ path: join(artifacts, 'extension-change-history.png') });
  await dashboard.setViewportSize({ width: 390, height: 844 });
  assert.ok(await dashboard.evaluate(() => document.documentElement.scrollWidth === document.documentElement.clientWidth));
  await popup.getByRole('button', { name: 'Remove extension inventory permission', exact: true }).click();
  await popup.getByRole('button', { name: 'Allow extension inventory', exact: true }).waitFor();
  await sync();
  assert.equal((await inventory(id)).status, 'permission_required');
  assert.deepEqual((await inventory(id)).entries, []);
  await dashboard.getByRole('link', { name: 'Overview', exact: true }).click();
  await dashboard.getByRole('button', { name: 'Restore version 1', exact: true }).click();
  await dashboard.getByText('Version 1 restored as version 3.', { exact: true }).waitFor();
  await sync();
  assert.equal((await inventory(id)).status, 'off');
  assert.equal((await inventory(id)).changeHistory, undefined);
  assert.equal(await popup.getByRole('button', { name: 'Allow extension inventory', exact: true }).count(), 0);
  const cache = await worker.evaluate(async () => JSON.stringify(await chrome.storage.local.get('controlState')));
  assert.doesNotMatch(cache, /Inventory Inspector Fixture|Inventory Utility Fixture|private-inventory\.example\.test/);
  assert.doesNotMatch(JSON.stringify(reported), /private-inventory\.example\.test|Private fixture description|hostPermissions|homepageUrl|updateUrl/);
});
