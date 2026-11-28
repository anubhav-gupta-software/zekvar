import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const api = process.env.ZEKVAR_DEMO_API;
const web = process.env.ZEKVAR_DEMO_WEB;
const owner = process.env.ZEKVAR_DEMO_TOKEN;
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

async function until(check, message) {
  for (let attempt = 0; attempt < 200; attempt++) {
    const result = await check();
    if (result) return result;
    await delay(100);
  }
  assert.fail(message);
}

test('guards native text paste before it reaches supported AI composers and reports only decision metadata', { timeout: 100_000 }, async (t) => {
  const scratch = await mkdtemp(join(tmpdir(), 'zekvar-clipboard-test-'));
  const dist = join(scratch, 'dist');
  const requests = [];
  let browser;
  let loseReceipt = false;
  let substitutedClipboardMode;
  const proxy = createServer(async (request, reply) => {
    try {
      if (!request.url?.startsWith('/v1/browser/') && request.url !== '/v1/enroll') return reply.writeHead(404).end();
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      const isEvent = request.url === '/v1/browser/events';
      if (isEvent) requests.push(JSON.parse(body));
      const headers = Object.fromEntries(Object.entries(request.headers).filter(([name]) =>
        name === 'authorization' || name === 'content-type' || name.startsWith('x-zekvar-')));
      const upstream = await fetch(api + request.url, { method: request.method, headers,
        body: body.length ? body : undefined, signal: AbortSignal.timeout(5000) });
      const text = await upstream.text();
      if (isEvent && upstream.ok && loseReceipt) {
        loseReceipt = false;
        return reply.writeHead(503).end();
      }
      const result = request.url === '/v1/browser/policy' && upstream.ok && substitutedClipboardMode !== undefined
        ? JSON.stringify({ ...JSON.parse(text), clipboardMode: substitutedClipboardMode }) : text;
      reply.writeHead(upstream.status, { 'Content-Type': 'application/json' }).end(result);
    } catch {
      reply.writeHead(502).end();
    }
  }).listen(0, '127.0.0.1');
  t.after(async () => {
    await browser?.close();
    proxy.closeAllConnections();
    await new Promise((resolve) => proxy.close(resolve));
    await rm(scratch, { recursive: true, force: true });
  });
  await once(proxy, 'listening');
  const env = { ...process.env, ZEKVAR_CONTROL_PORT: String(proxy.address().port), ZEKVAR_EXTENSION_OUTDIR: dist };
  delete env.ZEKVAR_CONTROL_ORIGIN;
  execFileSync(process.execPath, ['build.mjs'], { cwd: fileURLToPath(new URL('..', import.meta.url)), env });
  browser = await chromium.launchPersistentContext(join(scratch, 'profile'), {
    channel: 'chromium', headless: process.env.ZEKVAR_DEMO_HEADED !== '1',
    args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`],
  });
  browser.setDefaultTimeout(7000);
  const worker = browser.serviceWorkers()[0] ?? await browser.waitForEvent('serviceworker');
  const popup = await browser.newPage();
  const dashboard = await browser.newPage();
  const candidate = 'ZEKVAR_TEST_SECRET clipboard-private-synthetic';
  const tokenFixture = `ghp_${'Q'.repeat(36)}`;
  const original = await admin('policies', { mode: 'monitor', githubPatMode: 'monitor', claudePromptEnabled: true,
    uploadModes: { chatgpt: 'monitor' } });
  await dashboard.goto(web);
  await dashboard.getByLabel('Control token').fill(owner);
  await dashboard.getByRole('button', { name: 'Sign in', exact: true }).click();
  await dashboard.getByRole('link', { name: 'Policy preview', exact: true }).click();
  await dashboard.getByLabel('Draft clipboard paste protection', { exact: true }).selectOption('monitor');
  await dashboard.getByRole('button', { name: 'Run preview', exact: true }).click();
  await dashboard.getByRole('row', { name: /ChatGPT test marker paste/ }).getByText('Monitor', { exact: true }).waitFor();
  dashboard.once('dialog', (dialog) => dialog.accept());
  await dashboard.getByRole('button', { name: 'Publish previewed policy', exact: true }).click();
  await dashboard.getByText(/Previewed policy published as version/).waitFor();
  const [monitor] = await admin('policies');
  assert.equal(monitor.clipboardMode, 'monitor');

  const { grant } = await admin('enrollment-grants', {});
  await popup.goto(new URL('popup.html', worker.url()).href);
  await popup.getByLabel('Enrollment grant').fill(grant);
  await popup.getByRole('button', { name: 'Enroll this browser', exact: true }).click();
  await popup.getByText(`Connected to Control · MONITOR v${monitor.version}`, { exact: true }).waitFor();

  async function open(url, fixture, selector) {
    const page = await browser.newPage();
    const origin = new URL(url).origin;
    await browser.grantPermissions(['clipboard-read', 'clipboard-write'], { origin });
    const html = await readFile(new URL(fixture, import.meta.url), 'utf8');
    await page.route(`${origin}/**`, (route) => route.fulfill({ contentType: 'text/html', body: html }));
    await page.goto(url);
    // Count native events that reach the site without storing or echoing the clipboard data.
    await page.evaluate(() => {
      window.nativePastes = 0;
      document.addEventListener('paste', (event) => { if (event.isTrusted) window.nativePastes++; }, true);
    });
    return { page, editor: page.locator(selector) };
  }
  const guest = await open('https://chatgpt.com/uc/clipboard-lab', './guest-chatgpt-composer.html', 'textarea[placeholder="Ask ChatGPT"]');
  const gemini = await open('https://gemini.google.com/app/clipboard-lab', './gemini-composer.html', '.ql-editor');
  const claude = await open('https://claude.ai/new', './claude-composer.html', '.ProseMirror');
  const chat = await open('https://chatgpt.com/c/clipboard-lab', './chatgpt-composer.html', '#prompt-textarea');
  const apps = [guest, gemini, claude, chat];
  const events = () => admin('events');
  const pasteEvents = async () => (await events()).filter(({ clipboardPaste }) => clipboardPaste);
  const count = ({ page }) => page.evaluate(() => window.nativePastes);
  const editValue = ({ editor }) => editor.evaluate((element) => element instanceof HTMLTextAreaElement ? element.value : element.innerText);
  async function paste({ page, editor }, text, mime = 'text/plain') {
    await page.bringToFront();
    await editor.focus();
    await page.evaluate(async ({ text, mime }) => {
      if (mime === 'text/plain') await navigator.clipboard.writeText(text);
      else await navigator.clipboard.write([new ClipboardItem({ [mime]: new Blob([text], { type: mime }) })]);
    }, { text, mime });
    await editor.press('ControlOrMeta+V');
  }

  await guest.page.getByText(/Clipboard monitor/).waitFor();
  await paste(guest, candidate);
  await until(async () => (await editValue(guest)) === candidate, 'Monitor did not allow native insertion.');
  assert.equal(await count(guest), 1);
  const monitored = await until(async () => (await pasteEvents()).find(({ decision }) => decision === 'monitor'), 'Monitor metadata was not reported.');
  assert.equal(monitored.policyVersion, monitor.version);
  assert.equal(monitored.uploadMethod, undefined);

  await dashboard.goto(web);
  await dashboard.getByLabel('Clipboard paste protection', { exact: true }).selectOption('block');
  await dashboard.getByRole('button', { name: 'Publish policy', exact: true }).click();
  const block = await until(async () => {
    const [policy] = await admin('policies');
    return policy.clipboardMode === 'block' && policy;
  }, 'The dashboard did not publish clipboard Block.');
  await popup.getByRole('button', { name: 'Sync now', exact: true }).click();
  for (const { page } of apps) await page.getByText(new RegExp(`v${block.version}.*Clipboard block`)).waitFor();
  for (const surface of apps) {
    await surface.editor.fill('Existing clean draft');
    const before = await count(surface);
    await paste(surface, surface === gemini ? tokenFixture : candidate);
    await surface.page.getByRole('alert').filter({ hasText: 'Paste blocked because sensitive text was detected' }).waitFor();
    assert.equal(await editValue(surface), 'Existing clean draft');
    assert.equal(await count(surface), before);
  }
  const denied = await until(async () => {
    const matches = (await pasteEvents()).filter(({ policyVersion }) => policyVersion === block.version);
    return matches.length === apps.length && matches;
  }, 'The four native paste blocks were not reported.');
  assert.deepEqual(denied.map(({ appId }) => appId).sort(), ['chatgpt', 'chatgpt', 'claude', 'gemini']);
  assert.ok(denied.some(({ appId, ruleId }) => appId === 'gemini' && ruleId === 'github-classic-pat'));
  if (process.env.ZEKVAR_DEMO_ARTIFACTS) {
    await guest.page.screenshot({ path: join(process.env.ZEKVAR_DEMO_ARTIFACTS, 'clipboard-paste-block.png') });
  }
  const receivedUntrusted = await guest.editor.evaluate((input, text) => {
    const transfer = new DataTransfer();
    transfer.setData('text/plain', text);
    const event = new ClipboardEvent('paste', { clipboardData: transfer, bubbles: true, cancelable: true });
    return input.dispatchEvent(event);
  }, candidate);
  assert.equal(receivedUntrusted, true);

  await guest.editor.fill('');
  await paste(guest, 'Clean replacement');
  await until(async () => (await editValue(guest)) === 'Clean replacement', 'A clean retry did not reach the editor.');
  await guest.page.getByRole('alert').filter({ hasText: 'Paste blocked' }).waitFor({ state: 'hidden' });
  const unrelated = guest.page.getByLabel('Account field');
  await paste({ page: guest.page, editor: unrelated }, candidate);
  assert.equal(await unrelated.inputValue(), candidate);
  const blockedRoute = await open('https://chatgpt.com/settings', './guest-chatgpt-composer.html', 'textarea[placeholder="Ask ChatGPT"]');
  await paste(blockedRoute, candidate);
  assert.equal(await editValue(blockedRoute), candidate);

  await gemini.editor.fill('Unchanged');
  const attempted = await count(gemini);
  loseReceipt = true;
  await paste(gemini, 'x'.repeat(64_001));
  await gemini.page.getByRole('alert').filter({ hasText: 'could not check the clipboard text' }).waitFor();
  assert.equal(await editValue(gemini), 'Unchanged');
  assert.equal(await count(gemini), attempted);
  const incomplete = await until(async () => (await pasteEvents()).find(({ ruleId }) => ruleId === 'clipboard-inspection-unavailable'),
    'Blocked oversize paste was not recorded.');
  await popup.getByRole('button', { name: 'Sync now', exact: true }).click();
  await until(() => requests.filter(({ eventId }) => eventId === incomplete.eventId).length >= 2, 'The worker did not retry the lost acknowledgment.');
  assert.equal((await events()).filter(({ eventId }) => eventId === incomplete.eventId).length, 1);

  const attachment = await open('https://chatgpt.com/c/clipboard-file-lab', './upload-composer.html', '#prompt-textarea');
  await attachment.page.getByText(/Clipboard block/).waitFor();
  await attachment.page.bringToFront();
  await attachment.editor.focus();
  await attachment.page.evaluate(async () => {
    const canvas = document.createElement('canvas');
    canvas.width = canvas.height = 2;
    canvas.getContext('2d').fillRect(0, 0, 2, 2);
    const image = await new Promise((resolve) => canvas.toBlob(resolve, 'image/png'));
    await navigator.clipboard.write([new ClipboardItem({ 'image/png': image })]);
  });
  await attachment.editor.press('ControlOrMeta+V');
  await until(async () => (await events()).find(({ uploadMethod, clipboardPaste }) => uploadMethod === 'paste' && !clipboardPaste),
    'A file-only paste did not follow the separate upload policy.');
  assert.equal((await pasteEvents()).length, apps.length + 2);

  await chat.editor.fill('Existing clean draft');
  const beforeHtml = await count(chat);
  await paste(chat, '<p>Synthetic HTML-only paste</p>', 'text/html');
  await chat.page.getByRole('alert').filter({ hasText: 'could not check the clipboard text' }).waitFor();
  assert.equal(await editValue(chat), 'Existing clean draft');
  assert.equal(await count(chat), beforeHtml);
  await until(async () => (await pasteEvents()).length === apps.length + 3, 'The HTML-only block was not recorded.');

  substitutedClipboardMode = 'off';
  await popup.getByRole('button', { name: 'Sync now', exact: true }).click();
  await paste(chat, candidate);
  await chat.page.getByRole('alert').filter({ hasText: 'Paste blocked' }).waitFor();
  substitutedClipboardMode = 'warn';
  await popup.getByRole('button', { name: 'Sync now', exact: true }).click();
  await guest.editor.fill('');
  await paste(guest, candidate);
  await guest.page.getByRole('alert').filter({ hasText: 'Paste blocked' }).waitFor();
  assert.equal(await editValue(guest), '');
  substitutedClipboardMode = undefined;
  await popup.getByRole('button', { name: 'Sync now', exact: true }).click();
  await popup.getByText(`Connected to Control · MONITOR v${block.version}`, { exact: true }).waitFor();
  const beforeSend = requests.length;
  await chat.editor.fill(candidate);
  await chat.editor.press('Enter');
  assert.equal(await chat.page.locator('#fixture-sends').textContent(), '1');
  await until(() => requests.slice(beforeSend).some(({ clipboardPaste, decision }) => !clipboardPaste && decision === 'monitor'),
    'Send did not follow the independent prompt policy.');

  const restored = await admin(`policies/${original.version}/restore`, {});
  assert.equal(restored.clipboardMode, 'off');
  await popup.getByRole('button', { name: 'Sync now', exact: true }).click();
  await guest.page.getByText(new RegExp(`MONITOR v${restored.version}`)).waitFor();
  await guest.editor.fill('');
  await paste(guest, candidate);
  await until(async () => (await editValue(guest)) === candidate, 'A restored Off plan still blocked paste.');
  assert.ok(!(await pasteEvents()).some(({ policyVersion }) => policyVersion === restored.version));
  await dashboard.goto(`${web}/events/${incomplete.installationId}/${incomplete.eventId}`);
  await dashboard.getByText(/Clipboard check unavailable.*Clipboard paste/).waitFor();
  const fineGrained = `github_pat_${'F'.repeat(22)}_${'0'.repeat(59)}`;
  const stateless = `ghs_900001_${'A'.repeat(30)}.${'a-_'.repeat(128)}.${'Z'.repeat(87)}`;
  const ruleId = 'github-app-or-fine-grained-token';
  await dashboard.goto(`${web}/preview`);
  await dashboard.getByLabel('Draft GitHub classic PAT', { exact: true }).selectOption('off');
  await dashboard.getByLabel('Draft GitHub App, OAuth, or fine-grained token', { exact: true }).selectOption('warn');
  await dashboard.getByLabel('Draft ChatGPT file content protection', { exact: true }).selectOption('block');
  await dashboard.getByLabel('Draft clipboard paste protection', { exact: true }).selectOption('block');
  await dashboard.getByLabel('Custom prompt', { exact: true }).fill(stateless);
  await dashboard.getByRole('button', { name: 'Run preview', exact: true }).click();
  const preview = dashboard.getByRole('table', { name: 'Preview results', exact: true });
  await preview.getByRole('row', { name: /^Custom prompt / }).getByText('Warn', { exact: true }).waitFor();
  await preview.getByRole('row', { name: /^Synthetic GitHub fine-grained token / }).getByText('Warn', { exact: true }).waitFor();
  await preview.getByRole('row', { name: /^ChatGPT synthetic GitHub token file / }).getByText('Block', { exact: true }).waitFor();
  dashboard.once('dialog', (dialog) => dialog.accept());
  await dashboard.getByRole('button', { name: 'Publish previewed policy', exact: true }).click();
  await dashboard.getByText(/Previewed policy published as version/).waitFor();
  const [githubPolicy] = await admin('policies');
  assert.equal(githubPolicy.githubTokenMode, 'warn');
  assert.equal(githubPolicy.githubPatMode, 'off');
  await popup.getByRole('button', { name: 'Sync now', exact: true }).click();
  for (const { page } of [chat, gemini, attachment]) {
    await page.getByText(new RegExp(`v${githubPolicy.version}.*GitHub tokens warn`)).waitFor();
  }

  const sendCount = await chat.page.locator('#fixture-sends').textContent();
  await chat.editor.fill(`Review this value ${stateless}.`);
  await chat.editor.press('Enter');
  const redact = chat.page.getByRole('button', { name: 'Redact detected values', exact: true });
  await redact.waitFor();
  assert.equal(await chat.page.locator('#fixture-sends').textContent(), sendCount);
  await redact.click();
  assert.equal(await editValue(chat), 'Review this value [REDACTED].');
  if (process.env.ZEKVAR_DEMO_ARTIFACTS) {
    await chat.page.screenshot({ path: join(process.env.ZEKVAR_DEMO_ARTIFACTS, 'github-token-redaction.png') });
  }
  await chat.editor.press('Enter');
  assert.equal(Number(await chat.page.locator('#fixture-sends').textContent()), Number(sendCount) + 1);

  await gemini.editor.fill('');
  const beforeTokenPaste = await editValue(gemini);
  const beforeNativePastes = await count(gemini);
  await paste(gemini, fineGrained);
  await gemini.page.getByRole('alert').filter({ hasText: 'Paste blocked because sensitive text was detected' }).waitFor();
  assert.equal(await editValue(gemini), beforeTokenPaste);
  assert.equal(await count(gemini), beforeNativePastes);
  await paste(gemini, tokenFixture);
  await until(async () => (await editValue(gemini)).trim() === tokenFixture, 'Disabling the classic rule did not allow the classic PAT.');
  assert.equal(await count(gemini), beforeNativePastes + 1);

  const field = attachment.page.getByLabel('Attach fixture files');
  async function pick(name, text) {
    const file = join(scratch, name);
    await writeFile(file, text, { mode: 0o600 });
    const chooser = attachment.page.waitForEvent('filechooser');
    await field.click();
    await (await chooser).setFiles(file);
  }
  const priorFiles = await attachment.page.evaluate(() => window.fileEvents.length);
  await pick('synthetic.txt', `config=${stateless}`);
  await attachment.page.getByRole('alert').filter({ hasText: 'File upload blocked because sensitive content was detected' }).waitFor();
  assert.equal(await attachment.page.evaluate(() => window.fileEvents.length), priorFiles);
  await pick('clean.txt', 'A safe synthetic attachment.');
  await attachment.page.waitForFunction((before) => window.fileEvents.length > before, priorFiles);
  const githubEvents = await until(async () => {
    const detections = (await events()).filter((entry) => entry.ruleId === ruleId);
    return detections.length === 3 && detections;
  }, 'The prompt, paste, and file decisions were not reported.');
  assert.equal(githubEvents.filter(({ decision, clipboardPaste, uploadMethod }) => decision === 'warn' && !clipboardPaste && !uploadMethod).length, 1);
  assert.equal(githubEvents.filter(({ decision, clipboardPaste }) => decision === 'block' && clipboardPaste).length, 1);
  assert.equal(githubEvents.filter(({ decision, uploadMethod }) => decision === 'block' && uploadMethod === 'picker').length, 1);
  assert.ok(githubEvents.every(({ policyVersion, detectorCategory }) => policyVersion === githubPolicy.version && detectorCategory === 'credential'));
  const unprotected = await admin(`policies/${restored.version}/restore`, {});
  await popup.getByRole('button', { name: 'Sync now', exact: true }).click();
  await chat.page.getByText(new RegExp(`MONITOR v${unprotected.version}`)).waitFor();
  const beforeRollbackSend = Number(await chat.page.locator('#fixture-sends').textContent());
  await chat.editor.fill(fineGrained);
  await chat.editor.press('Enter');
  assert.equal(Number(await chat.page.locator('#fixture-sends').textContent()), beforeRollbackSend + 1);
  const exported = await admin('events/export');
  const json = JSON.stringify({ exported, requests });
  for (const sample of [candidate, tokenFixture, fineGrained, stateless, 'Clean replacement', 'clipboardText', 'clipboardData']) {
    assert.ok(!json.includes(sample));
  }
});
