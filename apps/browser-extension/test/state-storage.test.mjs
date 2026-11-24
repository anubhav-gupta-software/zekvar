import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { readBrowserState } from './browser-state.mjs';

const api = process.env.ZEKVAR_EXTENSION_TEST_API;
const owner = process.env.ZEKVAR_EXTENSION_TEST_ADMIN_TOKEN;
const executablePath = process.env.ZEKVAR_TEST_CHROME;
const freshOnly = process.env.ZEKVAR_TEST_FRESH_ONLY === '1';
assert.match(api ?? '', /^http:\/\/127\.0\.0\.1:\d+$/);
assert.match(owner ?? '', /^[a-f0-9]{64}$/);

async function call(path, token, body) {
  const response = await fetch(api + '/v1/' + path, {
    method: body ? 'POST' : 'GET', headers: { ...(token && { Authorization: 'Bearer ' + token }), 'Content-Type': 'application/json' },
    body: body && JSON.stringify(body), signal: AbortSignal.timeout(5000),
  });
  assert.equal(response.status, 200, path);
  return response.json();
}

test(freshOnly ? 'enrolls with private storage and keeps Browser enforcement after restart'
  : 'migrates enrollment into private storage and keeps Browser enforcement after restart', { timeout: 65_000 }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'zekvar-browser-storage-'));
  const dist = join(root, 'extension');
  await mkdir(dist);
  let context;
  let worker;
  t.after(async () => {
    await context?.close();
    await rm(root, { recursive: true, force: true });
  });
  async function launch(profile, workerName, extensionId, reload = false) {
    context = await chromium.launchPersistentContext(join(root, profile), {
      channel: executablePath ? undefined : 'chromium', executablePath, headless: process.env.ZEKVAR_DEMO_HEADED !== '1',
      ignoreDefaultArgs: executablePath ? ['--disable-extensions'] : undefined,
      args: [...(executablePath ? ['--disable-gpu'] : []), `--disable-extensions-except=${dist}`, `--load-extension=${dist}`],
    });
    context.setDefaultTimeout(9000);
    const matches = (candidate) => candidate.url().endsWith('/' + workerName);
    let tab;
    if (workerName !== 'seed-worker.js') {
      tab = await context.newPage();
      if (!extensionId || reload) {
        await tab.goto('chrome://extensions/');
        const card = tab.locator('extensions-item').filter({ hasText: /Zekvar (?:Browser|legacy cache fixture)/ });
        extensionId = await card.evaluate((element) => element.data.id);
        if (reload) {
          const developerMode = tab.locator('#devMode');
          if (await developerMode.getAttribute('aria-checked') !== 'true') await developerMode.click();
          await card.locator('#dev-reload-button').click();
        }
      }
    }
    if (tab) await tab.goto(`chrome-extension://${extensionId}/popup.html`);
    worker = context.serviceWorkers().find(matches) ?? await context.waitForEvent('serviceworker', matches);
    return tab;
  }
  const initialInstallations = (await call('admin/installations', owner)).length;
  const policy = await call('admin/policies', owner, { mode: 'block' });
  const grant = () => call('admin/enrollment-grants', owner, {});
  let extensionId;
  let installationId;
  let legacy;
  const profile = freshOnly ? 'fresh' : 'upgrade';
  if (!freshOnly) {
    const seedManifest = { manifest_version: 3, name: 'Zekvar legacy cache fixture', version: '0.36.0',
      permissions: ['storage'], background: { service_worker: 'seed-worker.js' } };
    await writeFile(join(dist, 'manifest.json'), JSON.stringify(seedManifest));
    await writeFile(join(dist, 'seed-worker.js'), 'chrome.runtime.onInstalled.addListener(() => {});\n');
    await launch(profile, 'seed-worker.js');
    extensionId = new URL(worker.url()).host;
    const enrollment = await call('enroll', undefined, { grant: (await grant()).grant });
    installationId = enrollment.installationId;
    legacy = { status: 'offline', controlOrigin: api, enrollment: { installationId, token: enrollment.token, source: 'manual' },
      discarded: 0, queue: [], chatGptEnabled: true };
    await worker.evaluate((controlState) => chrome.storage.local.set({ controlState }), legacy);
    await context.close();
  }

  execFileSync(process.execPath, ['build.mjs'], {
    cwd: fileURLToPath(new URL('..', import.meta.url)), env: { ...process.env,
      ZEKVAR_CONTROL_PORT: new URL(api).port, ZEKVAR_EXTENSION_OUTDIR: dist },
  });
  const current = JSON.parse(await readFile(join(dist, 'manifest.json'), 'utf8'));
  async function connected(tab, mode, version) {
    try {
      await tab.getByText(`Connected to Control · ${mode} v${version}`, { exact: true }).waitFor();
    } catch (error) {
      const status = await tab.locator('#status').textContent();
      const detail = await tab.locator('#error').textContent();
      throw new Error(`Unexpected Browser status: ${status}. ${detail}`, { cause: error });
    }
  }
  const previousCopyExists = () => worker.evaluate(async () => Object.hasOwn(await chrome.storage.local.get('controlState'), 'controlState'));
  async function enrollFromPopup(tab) {
    if (process.env.ZEKVAR_TEST_NO_PROTECTED_MANAGED === '1') {
      await tab.getByText('Paste an enrollment grant to connect. Automatic enrollment requires protected managed settings.', { exact: true }).waitFor();
    }
    await tab.getByLabel('Enrollment grant', { exact: true }).fill('invalid');
    await tab.getByRole('button', { name: 'Enroll this browser', exact: true }).click();
    await tab.getByText('Paste the 64-character enrollment grant from Control.', { exact: true }).waitFor();
    await tab.getByLabel('Enrollment grant', { exact: true }).fill((await grant()).grant);
    await tab.getByRole('button', { name: 'Enroll this browser', exact: true }).click();
    await connected(tab, 'BLOCK', policy.version);
  }

  const popup = await launch(profile, current.background.service_worker, extensionId, !freshOnly);
  extensionId ??= new URL(worker.url()).host;
  assert.equal(new URL(worker.url()).host, extensionId);
  if (freshOnly) {
    await enrollFromPopup(popup);
    installationId = (await readBrowserState(worker)).enrollment.installationId;
  }
  await connected(popup, 'BLOCK', policy.version);
  assert.equal((await readBrowserState(worker)).enrollment.installationId, installationId);
  assert.equal(await previousCopyExists(), false);

  const chat = await context.newPage();
  const fixture = await readFile(new URL('./guest-chatgpt-composer.html', import.meta.url), 'utf8');
  await chat.route('https://chatgpt.com/**', (route) => route.fulfill({ contentType: 'text/html', body: fixture }));
  await chat.goto('https://chatgpt.com/');
  const editor = chat.getByPlaceholder('Ask ChatGPT', { exact: true });
  await editor.fill('ZEKVAR_TEST_SECRET');
  await chat.getByRole('button', { name: 'Send message', exact: true }).click();
  await chat.getByRole('alert').filter({ hasText: 'Submission blocked' }).waitFor();
  for (let attempt = 0; attempt < 30; attempt++) {
    if ((await call('admin/events', owner)).some((entry) => entry.installationId === installationId)) break;
    await delay(100);
  }
  const events = await call('admin/events', owner);
  assert.equal(events.filter(({ installationId: recorded }) => recorded === installationId).length, 1);
  assert.doesNotMatch(JSON.stringify(events), /ZEKVAR_TEST_SECRET/);
  const devtools = await context.newCDPSession(chat);
  try {
    const isolated = [];
    devtools.on('Runtime.executionContextCreated', ({ context }) => {
      if (context.auxData?.type === 'isolated') isolated.push(context.id);
    });
    await devtools.send('Runtime.enable');
    let checked = false;
    for (const contextId of isolated) {
      const present = await devtools.send('Runtime.evaluate', { contextId, expression: 'Boolean(chrome.runtime?.id)' });
      if (!present.result.value) continue;
      const { result } = await devtools.send('Runtime.evaluate', { contextId, awaitPromise: true, returnByValue: true,
        expression: '(async () => ({ privateDatabase: (await indexedDB.databases()).some(({ name }) => name === "zekvar-browser"), oldCopy: await chrome.storage.local.get("controlState").then((state) => "controlState" in state, () => false) }))()' });
      assert.deepEqual(result.value, { privateDatabase: false, oldCopy: false });
      checked = true;
    }
    assert.equal(checked, true);
  } finally {
    await devtools.detach();
  }

  // An interrupted migration can leave a legacy copy after the private transaction commits.
  if (legacy) await worker.evaluate((controlState) => chrome.storage.local.set({ controlState }), { ...legacy, enrollment: undefined });
  await context.close();
  const restarted = await launch(profile, current.background.service_worker, extensionId);
  await connected(restarted, 'BLOCK', policy.version);
  assert.equal((await readBrowserState(worker)).enrollment.installationId, installationId);
  assert.equal(await previousCopyExists(), false);
  assert.equal((await call('admin/installations', owner)).length, initialInstallations + 1);
  if (!freshOnly) {
    await context.close();
    const fresh = await launch('fresh', current.background.service_worker, extensionId);
    await enrollFromPopup(fresh);
    assert.equal((await call('admin/installations', owner)).length, initialInstallations + 2);
    assert.equal(await previousCopyExists(), false);
  }
});
