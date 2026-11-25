import { readBrowserState } from './browser-state.mjs';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const { ZEKVAR_DEMO_API: api, ZEKVAR_DEMO_WEB: web, ZEKVAR_DEMO_TOKEN: owner, ZEKVAR_DEMO_ARTIFACTS: artifacts } = process.env;
const fixture = await readFile(new URL('./claude-composer.html', import.meta.url), 'utf8');
const marker = 'ZEKVAR_TEST_SECRET';
const draft = `Private synthetic Claude draft ${marker}`;
const credential = `ghp_${'0'.repeat(36)}`;
const origin = 'https://claude.ai';
const conversation = `${origin}/chat/42ff77c3-44cb-4b96-b049-8ba45f68689e`;
assert.match(owner ?? '', /^[a-f0-9]{64}$/);

async function call(path, { token = owner, body, expected = 200, headers = {} } = {}) {
  const response = await fetch(`${api}/v1/${path}`, {
    method: body === undefined ? 'GET' : 'POST', signal: AbortSignal.timeout(5000),
    headers: { Authorization: `Bearer ${token}`, ...(body && { 'Content-Type': 'application/json' }), ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  assert.equal(response.status, expected, path);
  if (expected === 200 || expected === 202) return response.json();
}

async function until(check, message) {
  for (let attempt = 0; attempt < 70; attempt++) {
    if (await check()) return;
    await delay(150);
  }
  assert.fail(message);
}

test('Claude opt-in, coverage, and recovery with Control and real Chrome', { timeout: 100_000 }, async (t) => {
  const scratch = await mkdtemp(join(tmpdir(), 'zekvar-claude-test-'));
  const build = join(scratch, 'dist');
  const attempts = [];
  let loseAcknowledgment = false;
  let browser;
  const proxy = createServer(async (request, reply) => {
    try {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      if (request.url === '/v1/browser/events') attempts.push(body.toString());
      const response = await fetch(api + request.url, {
        method: request.method, signal: AbortSignal.timeout(5000),
        headers: Object.fromEntries(Object.entries(request.headers).filter(([key]) =>
          key === 'authorization' || key === 'content-type' || key.startsWith('x-zekvar-'))),
        body: body.length ? body : undefined,
      });
      if (request.url === '/v1/browser/events' && response.ok && loseAcknowledgment) {
        loseAcknowledgment = false;
        return reply.writeHead(503).end();
      }
      reply.writeHead(response.status, { 'Content-Type': 'application/json' }).end(await response.text());
    } catch {
      reply.writeHead(502).end();
    }
  }).listen(0, '127.0.0.1');
  t.after(async () => {
    await browser?.close();
    await new Promise((resolve) => proxy.close(resolve));
    await rm(scratch, { recursive: true, force: true });
  });
  await once(proxy, 'listening');
  const env = { ...process.env, ZEKVAR_CONTROL_PORT: String(proxy.address().port), ZEKVAR_EXTENSION_OUTDIR: build };
  delete env.ZEKVAR_CONTROL_ORIGIN;
  execFileSync(process.execPath, ['build.mjs'], { cwd: fileURLToPath(new URL('..', import.meta.url)), env });
  browser = await chromium.launchPersistentContext(join(scratch, 'profile'), {
    channel: 'chromium', headless: process.env.ZEKVAR_DEMO_HEADED !== '1',
    args: [`--disable-extensions-except=${build}`, `--load-extension=${build}`],
  });
  browser.setDefaultTimeout(9000);
  const worker = browser.serviceWorkers()[0] ?? await browser.waitForEvent('serviceworker');
  const popup = await browser.newPage();
  const dashboard = await browser.newPage();
  const page = await browser.newPage();
  await page.route('https://claude.ai/**', (route) => route.fulfill({ contentType: 'text/html', body: fixture }));
  await browser.grantPermissions(['clipboard-read', 'clipboard-write'], { origin });
  const admin = (path, body, expected, token) => call(`admin/${path}`, { body, expected, token });
  const events = () => admin('events?appId=claude');
  const installation = (id) => admin('installations').then((rows) => rows.find(({ installationId }) => installationId === id));
  const editor = page.getByRole('textbox', { name: 'Fixture prompt' }).first();
  const submit = page.locator('#composer button').first();
  const sent = () => page.locator('#submitted').textContent().then(Number);
  const badge = page.locator('#zekvar-claude');
  const panelVersion = (mode, version) => page.getByText(new RegExp(`^Zekvar · ${mode.toUpperCase()} v${version}(?!\\d)`));
  const sync = async (mode, version) => {
    await popup.getByRole('button', { name: 'Sync now', exact: true }).click();
    await popup.getByText(`Connected to Control · ${mode.toUpperCase()} v${version}`, { exact: true }).waitFor();
  };
  const grant = async () => (await admin('enrollment-grants', {})).grant;
  const during = async (count) => until(async () => (await events()).length === count, `Expected ${count} Claude events`);

  await dashboard.goto(web);
  await dashboard.getByLabel('Control token', { exact: true }).fill(owner);
  await dashboard.getByRole('button', { name: 'Sign in', exact: true }).click();
  await dashboard.getByRole('heading', { name: 'Security overview', exact: true }).waitFor();
  const setting = dashboard.getByLabel('Claude prompt protection', { exact: true });
  assert.equal(await setting.inputValue(), 'off');
  await dashboard.getByLabel('Test marker', { exact: true }).selectOption('block');
  await dashboard.getByRole('button', { name: 'Publish policy', exact: true }).click();
  await dashboard.getByText('Version 2 published in block mode.', { exact: true }).waitFor();

  await popup.goto(new URL('popup.html', worker.url()).href);
  await popup.getByLabel('Enrollment grant').fill(await grant());
  await popup.getByRole('button', { name: 'Enroll this browser', exact: true }).click();
  await popup.getByText('Connected to Control · BLOCK v2', { exact: true }).waitFor();
  const id = (await readBrowserState(worker)).enrollment.installationId;
  await page.goto(`${origin}/new`);
  await editor.fill(draft);
  await submit.click();
  assert.equal(await sent(), 1);
  assert.equal(await badge.count(), 0);
  assert.deepEqual(await events(), []);

  const group = await admin('policy-groups', { name: 'Claude canary' });
  const groupPath = `policy-groups/${group.id}/policies`;
  const assign = (installationId, groupId) => admin(`installations/${installationId}/policy-group`, { groupId }, 204);
  await assign(id, group.id);
  let loadPreview;
  const scriptsReady = new Promise((resolve) => { loadPreview = resolve; });
  const scripts = '**/_next/static/**/*.js';
  await dashboard.route(scripts, async (route) => { await scriptsReady; await route.continue(); });
  try {
    await dashboard.goto(`${web}/preview?group=${group.id}`, { waitUntil: 'commit' });
    assert.equal(await dashboard.getByLabel('Load draft from').isDisabled(), true);
  } finally {
    loadPreview();
  }
  await dashboard.getByLabel('Draft Claude prompt protection', { exact: true }).selectOption('on');
  await dashboard.getByLabel('Draft Claude file uploads', { exact: true }).selectOption('block');
  await dashboard.getByLabel('Draft Claude file types', { exact: true }).fill('.BIN');
  await dashboard.getByLabel('Draft Claude file content protection', { exact: true }).selectOption('monitor');
  await dashboard.getByLabel('Prompt sample destination', { exact: true }).selectOption('claude');
  await dashboard.getByRole('button', { name: 'Run preview', exact: true }).click();
  const sample = dashboard.getByRole('row', { name: /^Synthetic test marker/ });
  await sample.getByText('Allow', { exact: true }).waitFor();
  await sample.getByText('Block', { exact: true }).waitFor();
  await dashboard.getByText('Claude prompt protection · Off → On', { exact: true }).waitFor();
  await dashboard.getByText('Claude file content protection · Off → Monitor', { exact: true }).waitFor();
  await dashboard.getByRole('row', { name: /^Claude synthetic text file/ }).getByText('Monitor', { exact: false }).waitFor();
  dashboard.once('dialog', (dialog) => dialog.accept());
  await dashboard.getByRole('button', { name: 'Publish previewed policy', exact: true }).click();
  await dashboard.getByText('Previewed policy published as version 3.', { exact: true }).waitFor();
  assert.equal((await admin('policies'))[0].claudePromptEnabled, false);
  const [canary] = await admin(groupPath);
  assert.equal(canary.claudePromptEnabled, true);
  assert.deepEqual([canary.uploadModes.claude, canary.uploadTypes.claude, canary.fileContentModes.claude], ['block', ['.bin'], 'monitor']);

  await sync('block', 3);
  await panelVersion('block', 3).waitFor();
  assert.equal((await installation(id)).claudeCoverage, null);
  await page.bringToFront();
  await editor.focus();
  await page.evaluate((text) => navigator.clipboard.writeText(text), draft);
  await editor.press('ControlOrMeta+V');
  await until(async () => (await editor.textContent()).includes(marker), 'The Chrome clipboard did not populate the draft');
  await editor.press('Shift+Enter');
  assert.equal(await sent(), 1);
  loseAcknowledgment = true;
  await editor.press('Enter');
  await page.getByRole('alert').filter({ hasText: 'Submission blocked' }).waitFor();
  assert.equal(await sent(), 1);
  await during(1);
  await popup.getByText(/^Control offline · BLOCK v3$/).waitFor();
  await sync('block', 3);
  await until(() => attempts.length === 2, 'Chrome did not retry the event');
  assert.equal(attempts[0], attempts[1]);
  assert.equal((await events()).length, 1);
  await until(async () => (await installation(id)).claudeCoverage === 'ready', 'Coverage was not confirmed by Control');
  if (artifacts) await page.screenshot({ path: join(artifacts, '28-claude-fixture-block.png') });
  const beforeEdit = await editor.innerText();
  await page.getByRole('button', { name: 'Redact detected values' }).click();
  const afterEdit = await editor.innerText();
  const notice = await badge.locator('#notice').textContent();
  assert.match(notice, /^Detected values redacted/, `Expected verified redaction after editing ${beforeEdit.length} characters to ${afterEdit.length}`);
  assert.equal(await sent(), 1);
  await submit.click();
  assert.equal(await sent(), 2);
  assert.match(await page.locator('#submitted').getAttribute('data-last'), /\[REDACTED\]/);
  assert.doesNotMatch(await page.locator('#submitted').getAttribute('data-last'), new RegExp(marker));

  await page.goto(conversation);
  await panelVersion('block', 3).waitFor();
  await editor.fill(marker);
  await submit.click();
  assert.equal(await sent(), 0);
  await during(2);
  await page.locator('#feedback button').click();
  assert.equal(await page.locator('#unrelated').textContent(), '1');
  await page.locator('#composer').evaluate((node) => node.append(node.querySelector('button').cloneNode(true)));
  await page.getByText('Zekvar · Unsupported composer (multiple Send controls)', { exact: true }).waitFor();
  await until(async () => (await installation(id)).claudeCoverage === 'unsupported', 'Unsupported layout was not reported');
  await page.getByRole('button', { name: 'Copy composer diagnostics' }).click();
  const diagnostics = JSON.parse(await page.evaluate(() => navigator.clipboard.readText()));
  assert.equal(diagnostics.route, 'conversation');
  assert.equal(diagnostics.hasPairedSend, false);
  assert.doesNotMatch(JSON.stringify(diagnostics), /42ff77c3|ZEKVAR_TEST_SECRET|claude\.ai/);
  await page.locator('#composer button').last().evaluate((button) => button.remove());
  await panelVersion('block', 3).waitFor();
  await until(async () => (await installation(id)).claudeCoverage === 'ready', 'Layout recovery was not reported');
  await editor.evaluate((input) => input.after(input.cloneNode(true)));
  await page.getByText('Zekvar · Unsupported composer (multiple editable fields)', { exact: true }).waitFor();
  await page.getByRole('textbox', { name: 'Fixture prompt' }).last().evaluate((input) => input.remove());
  await panelVersion('block', 3).waitFor();

  const warned = await admin(groupPath, { mode: 'warn' });
  await sync('warn', warned.version);
  await panelVersion('warn', warned.version).waitFor();
  await editor.fill(draft);
  await submit.click();
  await page.getByRole('button', { name: 'Continue anyway' }).waitFor();
  assert.equal(await sent(), 0);
  await page.getByRole('button', { name: 'Continue anyway' }).click();
  assert.equal(await sent(), 1);
  await during(4);

  const older = await call('enroll', { body: { grant: await grant() } });
  const legacy = (path, body, expected) => call(`browser/${path}`, { token: older.token, body, expected, headers: { 'X-Zekvar-Assignment-Aware': '1' } });
  await legacy('policy');
  await assign(older.installationId, group.id);
  const exception = { appId: 'claude', ruleId: 'fixture-secret', expiresAt: new Date(Date.now() + 60_000).toISOString(), reason: 'Synthetic test approval only' };
  const enabled = await admin(groupPath, { mode: 'block', githubPatMode: 'block', promptExceptions: [exception, { ...exception, appId: 'chatgpt' }] });
  const legacyPolicy = await legacy('policy');
  assert.equal(legacyPolicy.version, enabled.version);
  assert.equal(legacyPolicy.mode, 'block');
  assert.equal(legacyPolicy.claudePromptEnabled, false);
  assert.equal(legacyPolicy.appIds.includes('claude'), false);
  assert.deepEqual(legacyPolicy.promptExceptionLease.grants.map(({ appId }) => appId), ['chatgpt']);
  const legacyHeartbeat = { policyVersion: enabled.version, assignmentVersion: legacyPolicy.assignmentVersion };
  await legacy('heartbeat', legacyHeartbeat, 204);
  await legacy('heartbeat', { ...legacyHeartbeat, claudePromptApplied: true, claudeCoverage: 'ready' }, 400);
  await legacy('events', { ...legacyHeartbeat, eventId: randomUUID(), appId: 'claude', timestamp: new Date().toISOString(),
    ruleId: 'fixture-secret', detectorCategory: 'synthetic-secret', decision: 'block' }, 400);
  assert.notEqual((await installation(older.installationId)).appliedPolicyVersion, enabled.version);

  await t.test('withholds Claude files from a text-only browser and rejects its file acknowledgments and events', async () => {
    const headers = { 'X-Zekvar-Assignment-Aware': '1', 'X-Zekvar-Claude-Prompt': '1',
      'X-Zekvar-File-Inspection': '1', 'X-Zekvar-File-Content-Block': '1' };
    const textOnly = (path, body, expected) => call(`browser/${path}`, { token: older.token, body, expected, headers });
    const textPolicy = await textOnly('policy');
    assert.equal(textPolicy.claudePromptEnabled, true);
    assert.deepEqual(textPolicy.uploadModes, { chatgpt: 'off', gemini: 'off' });
    assert.equal(textPolicy.fileContentModes.claude, undefined);
    assert.equal(textPolicy.targetedUploads?.claude, undefined);
    const heartbeat = { ...legacyHeartbeat, claudePromptApplied: true, promptExceptionsApplied: true };
    await textOnly('heartbeat', heartbeat, 204);
    assert.notEqual((await installation(older.installationId)).appliedPolicyVersion, enabled.version);
    await textOnly('heartbeat', { ...heartbeat, claudeFilesApplied: true }, 400);
    const event = { ...legacyHeartbeat, eventId: randomUUID(), appId: 'claude', timestamp: new Date().toISOString(), uploadMethod: 'picker' };
    await textOnly('events', { ...event, ruleId: 'fixture-secret', detectorCategory: 'synthetic-secret', decision: 'monitor' }, 400);
    await textOnly('events', { ...event, ruleId: 'ai-file-upload', detectorCategory: 'file-upload', decision: 'block' }, 400);
  });

  await sync('block', enabled.version);
  await panelVersion('block', enabled.version).waitFor();
  await editor.fill(draft);
  await submit.click();
  assert.equal(await sent(), 2);
  await during(5);
  await editor.fill(`${draft} ${credential}`);
  await editor.press('Enter');
  assert.equal(await sent(), 2);
  await during(6);
  assert.ok((await events()).some((event) => event.decision === 'exception_applied'));
  await until(async () => (await installation(id)).claudeCoverage === 'ready', 'Control did not confirm the current Claude composer');

  await dashboard.goto(web);
  await dashboard.getByRole('table', { name: 'Browser health' }).getByRole('row').filter({ hasText: id.slice(0, 13) })
    .getByText('Detected', { exact: true }).waitFor();
  await dashboard.getByLabel('Application', { exact: true }).selectOption('claude');
  await dashboard.getByRole('button', { name: 'Apply filters', exact: true }).click();
  await dashboard.getByRole('table', { name: 'Security events' }).getByText('Claude', { exact: true }).first().waitFor();
  const exportUrl = await dashboard.getByRole('link', { name: 'Export security events (JSON)' }).getAttribute('href');
  assert.equal(new URL(exportUrl, web).searchParams.get('appId'), 'claude');
  const exported = await dashboard.evaluate(async (url) => {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`Export failed with HTTP ${response.status}`);
    return response.json();
  }, exportUrl);
  assert.equal(exported.entries.length, 6);
  assert.ok(exported.entries.every(({ appId }) => appId === 'claude'));
  assert.doesNotMatch(JSON.stringify([exported, attempts]), /Private synthetic Claude draft|ZEKVAR_TEST_SECRET|ghp_0|Synthetic test approval/);
  if (artifacts) await dashboard.getByRole('table', { name: 'Security events' }).screenshot({ path: join(artifacts, '29-claude-events.png') });

  const monitored = await admin(groupPath, { mode: 'monitor', promptExceptions: [] });
  await sync('monitor', monitored.version);
  await panelVersion('monitor', monitored.version).waitFor();
  await editor.fill(draft);
  await submit.click();
  assert.equal(await sent(), 3);
  await during(7);
  assert.ok((await events()).some((event) => event.decision === 'monitor'));

  const disabled = await admin(groupPath, { mode: 'block', claudePromptEnabled: false });
  await sync('block', disabled.version);
  await badge.waitFor({ state: 'detached' });
  assert.equal((await installation(id)).claudeCoverage, null);
  assert.equal((await installation(id)).claudePromptEnabled, false);
  await editor.fill(draft);
  await submit.click();
  assert.equal(await sent(), 4);
  assert.equal((await events()).length, 7);
  const restored = await admin(`${groupPath}/3/restore`, {});
  assert.equal(restored.claudePromptEnabled, true);
  assert.deepEqual([restored.uploadModes.claude, restored.uploadTypes.claude, restored.fileContentModes.claude], ['block', ['.bin'], 'monitor']);
  await sync('block', restored.version);
  await panelVersion('block', restored.version).waitFor();
  for (const path of ['/login', '/projects/fixture', '/chat/not-a-conversation']) {
    await page.goto(origin + path);
    assert.equal(await badge.count(), 0);
  }
});
