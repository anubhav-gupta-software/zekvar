import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { officeSamples } from './office-fixture.mjs';

const api = process.env.ZEKVAR_EXTENSION_TEST_API;
const owner = process.env.ZEKVAR_EXTENSION_TEST_ADMIN_TOKEN;
assert.match(api ?? '', /^http:\/\/127\.0\.0\.1:\d+$/);
assert.match(owner ?? '', /^[a-f0-9]{64}$/);
const fixture = await readFile(new URL('./upload-composer.html', import.meta.url), 'utf8');
const marker = 'ZEKVAR_TEST_SECRET';
const pat = `ghp_${'0'.repeat(36)}`;
const key = ['-----BEGIN PRIVATE KEY-----', 'c3lk'.repeat(16), '-----END PRIVATE KEY-----'].join('\n');

async function admin(path, body) {
  const response = await fetch(`${api}/v1/admin/${path}`, { method: body ? 'POST' : 'GET',
    headers: { Authorization: `Bearer ${owner}`, 'Content-Type': 'application/json' },
    body: body && JSON.stringify(body), signal: AbortSignal.timeout(5_000) });
  assert.equal(response.status, 200, path);
  return response.json();
}

async function until(check, message) {
  for (let attempt = 0; attempt < 50; attempt++) {
    const result = await check();
    if (result) return result;
    await delay(100);
  }
  assert.fail(message);
}

test('monitors Office files through native Chrome intake and Control reporting', { timeout: 45_000 }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'zekvar-office-upload-'));
  let browser;
  let loseNextAcknowledgment = false;
  const posts = [];
  const proxy = createServer(async (request, response) => {
    try {
      if (request.url !== '/v1/enroll' && !request.url?.startsWith('/v1/browser/')) return response.writeHead(404).end();
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      const isEvent = request.url === '/v1/browser/events';
      if (isEvent) posts.push(JSON.parse(body));
      const headers = Object.fromEntries(Object.entries(request.headers).filter(([name]) =>
        name === 'content-type' || name === 'authorization' || name.startsWith('x-zekvar-')));
      const upstream = await fetch(api + request.url, { method: request.method, headers,
        body: body.length ? body : undefined, signal: AbortSignal.timeout(5_000) });
      const text = await upstream.text();
      if (isEvent && upstream.ok && loseNextAcknowledgment) {
        loseNextAcknowledgment = false;
        return response.writeHead(503).end();
      }
      response.writeHead(upstream.status, { 'Content-Type': 'application/json' }).end(text);
    } catch {
      response.writeHead(502).end();
    }
  });
  await new Promise((resolve, reject) => {
    proxy.once('error', reject);
    proxy.listen(0, '127.0.0.1', resolve);
  });
  t.after(async () => {
    await browser?.close();
    await new Promise((resolve) => proxy.close(resolve));
    await rm(root, { recursive: true, force: true });
  });
  const dist = join(root, 'extension');
  execFileSync(process.execPath, ['build.mjs'], { cwd: fileURLToPath(new URL('..', import.meta.url)),
    env: { ...process.env, ZEKVAR_CONTROL_PORT: String(proxy.address().port), ZEKVAR_EXTENSION_OUTDIR: dist } });

  const generated = process.env.ZEKVAR_TEST_OFFICE_DIRECTORY;
  const docs = generated ? {
    docx: await readFile(join(generated, 'synthetic-real-word.docx')),
    xlsx: await readFile(join(generated, 'synthetic-real-excel.xlsx')),
    pptx: await readFile(join(generated, 'synthetic-real-powerpoint.pptx')),
  } : officeSamples(marker, pat, key);
  const word = join(root, 'synthetic-office-disguised.jpg');
  const excel = join(root, 'synthetic-office-tabular.xlsx');
  const slides = join(root, 'synthetic-office-slides.pptx');
  const blocked = join(root, 'synthetic-office-blocked.bin');
  await Promise.all([writeFile(word, docs.docx), writeFile(excel, docs.xlsx), writeFile(slides, docs.pptx), writeFile(blocked, docs.pptx)]);

  const [original] = await admin('policies');
  const policy = await admin('policies', { mode: 'monitor', githubPatMode: 'block', privateKeyMode: 'block',
    fileInspection: { chatgpt: true, gemini: true }, uploadModes: { gemini: 'block' }, uploadTypes: { gemini: ['.bin'] } });
  const { grant } = await admin('enrollment-grants', {});
  browser = await chromium.launchPersistentContext(join(root, 'profile'), {
    channel: 'chromium', headless: process.env.ZEKVAR_DEMO_HEADED !== '1',
    args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`],
  });
  browser.setDefaultTimeout(7_000);
  const worker = browser.serviceWorkers()[0] ?? await browser.waitForEvent('serviceworker');
  const popup = await browser.newPage();
  await popup.goto(new URL('popup.html', worker.url()).href);
  await popup.getByLabel('Enrollment grant').fill(grant);
  await popup.getByRole('button', { name: 'Enroll this browser', exact: true }).click();
  await popup.getByText(`Connected to Control · MONITOR v${policy.version}`, { exact: true }).waitFor();

  const chat = await browser.newPage();
  const gemini = await browser.newPage();
  for (const [page, url] of [[chat, 'https://chatgpt.com/'], [gemini, 'https://gemini.google.com/app']]) {
    await page.route(`${new URL(url).origin}/**`, (route) => route.fulfill({ contentType: 'text/html', body: fixture }));
    await page.goto(url);
    await page.getByText(/File content monitor$/).waitFor();
  }
  const actions = (page) => page.evaluate(() => window.fileEvents);
  const input = (page) => page.getByLabel('Attach fixture files');
  const events = async () => (await admin('events')).filter(({ policyVersion }) => policyVersion === policy.version);
  async function pick(page, files) {
    const chooser = page.waitForEvent('filechooser');
    await input(page).click();
    await (await chooser).setFiles(files);
  }
  async function drop(page, target, files) {
    const cdp = await browser.newCDPSession(page);
    try {
      const { x, y } = await target.boundingBox();
      for (const type of ['dragEnter', 'dragOver', 'drop']) {
        await cdp.send('Input.dispatchDragEvent', { type, x: x + 10, y: y + 10, data: { items: [], files, dragOperationsMask: 1 } });
      }
    } finally { await cdp.detach(); }
  }

  await pick(chat, [word]);
  await until(async () => (await events()).length === 1, 'Word match was not recorded.');
  await drop(gemini, gemini.locator('#drop-zone'), [excel]);
  await until(async () => (await events()).length === 2, 'Excel match was not recorded.');
  await input(chat).setInputFiles([]);
  loseNextAcknowledgment = true;
  await drop(chat, input(chat), [word, slides]);
  await until(() => !loseNextAcknowledgment, 'The proxy did not drop the PowerPoint acknowledgment.');
  const retried = posts.at(-1).eventId;
  await popup.getByRole('button', { name: 'Sync now' }).click();
  await until(() => posts.filter(({ eventId }) => eventId === retried).length === 2, 'The browser did not retry the Office decision.');
  await pick(gemini, [blocked]);
  await gemini.getByRole('alert').filter({ hasText: 'File upload blocked' }).waitFor();
  await until(async () => (await events()).length === 4, 'The four expected events did not reach Control.');
  assert.deepEqual(await actions(chat), [['input', 1], ['change', 1], ['drop', 2], ['input', 2], ['change', 2]]);
  assert.deepEqual(await actions(gemini), [['drop', 1]]);
  assert.deepEqual((await events()).map(({ appId, decision, ruleId, uploadMethod }) => `${appId}/${decision}/${ruleId}/${uploadMethod}`).sort(),
    ['chatgpt/monitor/fixture-secret/picker', 'chatgpt/monitor/pem-private-key/drop', 'gemini/block/ai-file-upload/picker',
      'gemini/monitor/github-classic-pat/drop']);
  await delay(10);
  const report = await admin('reports/ai-enforcement?rolloutGroup=baseline');
  assert.equal(report.bySource.find(({ id }) => id === 'file_content').counts.monitor, 3);
  assert.equal(report.bySource.find(({ id }) => id === 'file_policy').counts.block, 1);
  assert.doesNotMatch(JSON.stringify([...posts, ...await events(), report]), /synthetic-office|c3lkc3lk|BEGIN PRIVATE KEY|ghp_|ZEKVAR_TEST_SECRET/);

  const restored = await admin(`policies/${original.version}/restore`, {});
  await popup.getByRole('button', { name: 'Sync now' }).click();
  await chat.getByText(`Zekvar · MONITOR v${restored.version}`, { exact: true }).waitFor();
  await pick(chat, [slides]);
  assert.deepEqual((await actions(chat)).slice(-2), [['input', 1], ['change', 1]]);
  assert.equal(posts.length, 5);
});
