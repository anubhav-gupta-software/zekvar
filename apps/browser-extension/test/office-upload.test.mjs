import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { crc32 } from 'node:zlib';
import { chromium } from 'playwright';
import { officeSamples } from './office-fixture.mjs';
import { odfXml, openDocumentFile, openDocumentSamples } from './opendocument-fixture.mjs';
import { pdfFixture } from './pdf-fixture.mjs';
import { textImage } from './image-fixture.mjs';

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

test('protects attachments through native Chrome intake and Control reporting', { timeout: 90_000 }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'zekvar-office-upload-'));
  let browser;
  let loseNextAcknowledgment = false;
  let fileDataSentToControl = false;
  const posts = [];
  const proxy = createServer(async (request, response) => {
    try {
      if (request.url !== '/v1/enroll' && !request.url?.startsWith('/v1/browser/')) return response.writeHead(404).end();
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      fileDataSentToControl ||= body.includes('%PDF-') || body.includes('JVBERi') || body.includes('iVBORw0KGgo') ||
        body.includes('/9j/') || body.includes(marker);
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
    channel: 'chromium', executablePath: process.env.ZEKVAR_TEST_CHROME, headless: process.env.ZEKVAR_DEMO_HEADED !== '1',
    args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`, '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1'],
  });
  browser.setDefaultTimeout(7_000);
  const worker = browser.serviceWorkers()[0] ?? await browser.waitForEvent('serviceworker');
  const popup = await browser.newPage();
  await popup.goto(new URL('popup.html', worker.url()).href);
  await popup.getByText('Ready to enroll', { exact: true }).waitFor();
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
  async function expectFileMode(page, version, mode) {
    const badge = page.getByText(new RegExp(`v${version}.*File content ${mode}$`));
    try {
      await badge.waitFor();
    } catch (error) {
      const active = await page.getByText(/^Zekvar · /).allTextContents();
      const popupStatus = await popup.locator('#status').textContent();
      throw new Error(`Expected file mode ${mode} at v${version}. Composer: ${active.join(' / ')}. Popup: ${popupStatus}.`, { cause: error });
    }
  }
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

  await t.test('releases scanned snapshots and keeps sensitive, unsupported, and stale selections from the site', async () => {
    const deliveries = [];
    for (const [page, app] of [[chat, 'chatgpt'], [gemini, 'gemini']]) {
      await page.route('**/fixture-upload', async (route) => {
        deliveries.push({ app, bytes: route.request().postDataBuffer() });
        await route.fulfill({ status: 204 });
      });
      await page.evaluate(() => { window.captureUploads = true; window.fileEvents = []; });
    }
    const allowedText = 'Synthetic safe text attachment';
    const cleanWord = officeSamples('Safe word report', 'Safe workbook report', 'Safe slide report').docx;
    const clean = join(root, 'synthetic-clean.txt');
    const cleanOffice = join(root, 'synthetic-clean.docx');
    const raw = join(root, 'synthetic-sensitive-disguised.png');
    const badPdf = join(root, 'synthetic-unsupported.dat');
    const oversized = join(root, 'synthetic-large.txt');
    const slow = join(root, 'synthetic-slow.txt');
    const slowBytes = 'Synthetic safe text while pending';
    await Promise.all([writeFile(clean, allowedText), writeFile(cleanOffice, cleanWord), writeFile(raw, marker),
      writeFile(badPdf, '%PDF-1.7\nSynthetic unscanned bytes'), writeFile(oversized, 'X'.repeat(256 * 1024 + 1)), writeFile(slow, slowBytes)]);
    const blocking = await admin('policies', { mode: 'monitor', githubPatMode: 'warn', privateKeyMode: 'block',
      fileContentModes: { chatgpt: 'block', gemini: 'block' }, uploadModes: { gemini: 'block' }, uploadTypes: { gemini: ['.bin'] } });
    await popup.getByRole('button', { name: 'Sync now' }).click();
    for (const page of [chat, gemini]) await page.getByText(/File content block$/).waitFor();
    await until(async () => (await admin('installations')).some(({ appliedPolicyVersion }) => appliedPolicyVersion === blocking.version),
      'The browser did not acknowledge content blocking.');
    const refused = (page, reason = 'sensitive content') => page.getByRole('alert').filter({ hasText: reason }).waitFor();
    const seen = (count) => until(() => deliveries.length === count, 'The fixture did not receive the exact verified file count.');
    const reportRows = async () => (await admin('events')).filter(({ policyVersion }) => policyVersion === blocking.version);

    await pick(chat, [clean]);
    await seen(1);
    assert.deepEqual(await actions(chat), [['input', 1], ['change', 1]]);
    assert.equal(deliveries[0].bytes.toString(), allowedText);
    await drop(gemini, gemini.locator('#drop-zone'), [cleanOffice]);
    await seen(2);
    assert.deepEqual(deliveries[1], { app: 'gemini', bytes: cleanWord });
    await drop(chat, input(chat), [clean]);
    await seen(3);
    assert.deepEqual((await actions(chat)).slice(-3), [['drop', 1], ['input', 1], ['change', 1]]);

    await pick(chat, [clean, raw]);
    await refused(chat);
    assert.deepEqual(await input(chat).evaluate((field) => field.files.length), 0);
    const screenshot = process.env.ZEKVAR_TEST_FILE_BLOCK_SCREENSHOT;
    if (screenshot) await chat.screenshot({ path: screenshot });
    await drop(gemini, gemini.locator('#drop-zone'), [cleanOffice, excel]);
    await refused(gemini);
    await drop(chat, input(chat), [slides]);
    await refused(chat);
    await pick(gemini, [blocked]);
    await refused(gemini, 'policy');
    await pick(chat, [badPdf]);
    await refused(chat, 'could not complete');
    await pick(gemini, [oversized]);
    await refused(gemini, 'could not complete');
    await browser.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: 'https://chatgpt.com' });
    await chat.bringToFront();
    await chat.evaluate(async () => {
      const canvas = document.createElement('canvas');
      canvas.width = canvas.height = 2;
      const png = await new Promise((done) => canvas.toBlob(done, 'image/png'));
      await navigator.clipboard.write([new ClipboardItem({ 'image/png': png })]);
    });
    await chat.getByRole('textbox', { name: 'Fixture text' }).press('ControlOrMeta+v');
    await refused(chat, 'could not complete');
    assert.equal(deliveries.length, 3);
    assert.deepEqual(await actions(chat), [['input', 1], ['change', 1], ['drop', 1], ['input', 1], ['change', 1]]);
    assert.deepEqual(await actions(gemini), [['drop', 1]]);

    const cdp = await browser.newCDPSession(chat);
    try {
      const contexts = [];
      cdp.on('Runtime.executionContextCreated', ({ context }) => contexts.push(context));
      await cdp.send('Runtime.enable');
      let contextId;
      const extensionId = new URL(worker.url()).host;
      for (const context of contexts.filter(({ auxData }) => auxData?.type === 'isolated')) {
        const { result } = await cdp.send('Runtime.evaluate', { expression: 'globalThis.chrome?.runtime?.id', contextId: context.id });
        if (result.value === extensionId) contextId = context.id;
      }
      assert.ok(contextId, 'Chrome did not expose the extension world for the delayed-read fixture.');
      async function extension(expression) {
        const { result, exceptionDetails } = await cdp.send('Runtime.evaluate', { expression, contextId });
        assert.equal(exceptionDetails, undefined);
        return result.value;
      }
      await extension(`globalThis.pendingFixtureReads = [];
        const readFile = File.prototype.arrayBuffer;
        File.prototype.arrayBuffer = function () {
          if (this.name !== 'synthetic-slow.txt') return readFile.call(this);
          return new Promise((resolve, reject) => pendingFixtureReads.push(() => readFile.call(this).then(resolve, reject)));
        };`);
      await pick(chat, [slow]);
      await until(() => extension('pendingFixtureReads.length'), 'The slow file read did not start.');
      await pick(chat, [clean]);
      await seen(4);
      await extension('void pendingFixtureReads.shift()()');
      await pick(chat, [slow]);
      await until(() => extension('pendingFixtureReads.length'), 'The timeout file read did not start.');
      await refused(chat, 'could not complete');
      await extension('void pendingFixtureReads.shift()()');

      await pick(chat, [slow]);
      await until(() => extension('pendingFixtureReads.length'), 'The stale policy file read did not start.');
      const downgraded = await admin('policies', { fileContentModes: { chatgpt: 'monitor' } });
      await popup.getByRole('button', { name: 'Sync now' }).click();
      await expectFileMode(chat, downgraded.version, 'monitor');
      await extension('void pendingFixtureReads.shift()()');
      await pick(chat, [raw]);
      await seen(5);
      assert.equal(deliveries.at(-1).bytes.toString(), marker);
    } finally { await cdp.detach(); }

    const expected = ['chatgpt/file-inspection-unavailable/paste', 'chatgpt/file-inspection-unavailable/picker',
      'chatgpt/file-inspection-unavailable/picker', 'chatgpt/fixture-secret/picker', 'chatgpt/pem-private-key/drop',
      'gemini/ai-file-upload/picker', 'gemini/file-inspection-unavailable/picker', 'gemini/github-classic-pat/drop'];
    const stored = await until(async () => {
      const rows = await reportRows();
      return rows.length >= expected.length && rows;
    }, 'Control did not receive the complete set of reported file decisions.');
    assert.deepEqual(stored.map(({ appId, ruleId, uploadMethod }) => `${appId}/${ruleId}/${uploadMethod}`).sort(), expected);
    assert.ok(stored.every(({ decision }) => decision === 'block'));
    assert.doesNotMatch(JSON.stringify([...posts, ...stored]), /synthetic-(?:office|slow|clean|sensitive|large|unsupported)|ZEKVAR_TEST_SECRET|%PDF/);
  });

  await t.test('monitors and blocks OpenDocument intake and releases clean document bytes', async () => {
    const approval = odfXml.body('odt', '<text:p>Approved synthetic OpenDocument text</text:p>');
    const odfDirectory = process.env.ZEKVAR_TEST_OPENDOCUMENT_DIRECTORY;
    const docs = odfDirectory ? {
      odt: await readFile(join(odfDirectory, 'synthetic-real.odt')),
      ods: await readFile(join(odfDirectory, 'synthetic-real.ods')),
      odp: await readFile(join(odfDirectory, 'synthetic-real.odp')),
    } : openDocumentSamples(marker, pat, key);
    const safeBytes = odfDirectory ? await readFile(join(odfDirectory, 'synthetic-approved.odt')) : openDocumentFile('odt', approval);
    const fixtures = [
      ['private-odf-disguised.jpg', docs.odt], ['private-odf-worksheet.ods', docs.ods], ['private-odf-slides.odp', docs.odp],
      ['private-odf-approved.odt', safeBytes],
      ['private-odf-protected.odt', openDocumentFile('odt', approval, { encrypted: ['content.xml'] })],
    ];
    const paths = await Promise.all(fixtures.map(async ([name, bytes]) => {
      const path = join(root, name);
      await writeFile(path, bytes);
      return path;
    }));
    const [writer, spreadsheet, presentation, cleanOdf, encryptedOdf] = paths;
    const transfers = [];
    for (const [page, appId] of [[chat, 'chatgpt'], [gemini, 'gemini']]) {
      await page.unroute('**/fixture-upload');
      await page.route('**/fixture-upload', async (route) => {
        transfers.push({ appId, bytes: route.request().postDataBuffer() });
        await route.fulfill({ status: 204 });
      });
      await page.evaluate(() => { window.fileEvents = []; });
    }
    async function apply(fileContentModes) {
      const applied = await admin('policies', { fileContentModes, uploadModes: { chatgpt: 'off', gemini: 'off' } });
      await popup.getByRole('button', { name: 'Sync now' }).click();
      await expectFileMode(chat, applied.version, fileContentModes.chatgpt);
      await expectFileMode(gemini, applied.version, fileContentModes.gemini);
      return applied.version;
    }
    const monitor = await apply({ chatgpt: 'monitor', gemini: 'monitor' });
    await pick(chat, [writer]);
    await until(() => transfers.length === 1, 'Monitor did not release the Writer attachment.');
    assert.deepEqual(transfers[0], { appId: 'chatgpt', bytes: docs.odt });
    const block = await apply({ chatgpt: 'block', gemini: 'block' });
    await drop(gemini, gemini.locator('#drop-zone'), [spreadsheet]);
    await gemini.getByRole('alert').filter({ hasText: 'sensitive content' }).waitFor();
    await pick(chat, [presentation]);
    await chat.getByRole('alert').filter({ hasText: 'sensitive content' }).waitFor();
    await pick(gemini, [encryptedOdf]);
    await gemini.getByRole('alert').filter({ hasText: 'could not complete' }).waitFor();
    if (process.env.ZEKVAR_DEMO_ARTIFACTS) {
      await gemini.getByRole('alert').screenshot({ path: join(process.env.ZEKVAR_DEMO_ARTIFACTS, 'opendocument-check-unavailable.png') });
    }
    assert.equal(transfers.length, 1);
    await pick(chat, [cleanOdf]);
    await until(() => transfers.length === 2, 'Block did not release the checked clean OpenDocument attachment.');
    assert.deepEqual(transfers[1], { appId: 'chatgpt', bytes: safeBytes });
    const stored = await until(async () => {
      const entries = (await admin('events')).filter(({ policyVersion }) => [monitor, block].includes(policyVersion));
      return entries.length === 4 && entries;
    }, 'Control did not receive every OpenDocument decision.');
    assert.deepEqual(stored.map(({ appId, decision, ruleId, uploadMethod }) => `${appId}/${decision}/${ruleId}/${uploadMethod}`).sort(),
      ['chatgpt/block/pem-private-key/picker', 'chatgpt/monitor/fixture-secret/picker', 'gemini/block/file-inspection-unavailable/picker',
        'gemini/block/github-classic-pat/drop']);
    assert.doesNotMatch(JSON.stringify([...posts, ...stored]), /private-odf|ZEKVAR_TEST_SECRET|ghp_|BEGIN PRIVATE KEY|Approved synthetic/);
  });

  await t.test('scans PDF page text locally and blocks incomplete checks before native attachments reach the site', async () => {
    const safeBytes = process.env.ZEKVAR_TEST_PDF_DIRECTORY
      ? await readFile(join(process.env.ZEKVAR_TEST_PDF_DIRECTORY, 'approved.pdf'))
      : pdfFixture([['Approved synthetic PDF text']]);
    const samples = new Map([
      ['public-summary.pdf', safeBytes],
      ['private-pdf-disguised.png', pdfFixture([['Synthetic cover page'], [[marker.slice(0, 7), marker.slice(7)]]])],
      ['private-pdf-credential.pdf', pdfFixture([key.split('\n')])],
      ['private-pdf-unreadable.pdf', pdfFixture([[]])],
      ['private-pdf-embedded.pdf', pdfFixture([['Ordinary page alongside an attachment']], { embedded: true })],
      ['private-pdf-too-many-pages.pdf', pdfFixture(Array(25).fill(['Approved synthetic PDF text']))],
    ]);
    if (process.env.ZEKVAR_TEST_PDF_DIRECTORY) {
      samples.set('private-pdf-encrypted.pdf', await readFile(join(process.env.ZEKVAR_TEST_PDF_DIRECTORY, 'encrypted.pdf')));
      samples.set('private-pdf-exported.pdf', await readFile(join(process.env.ZEKVAR_TEST_PDF_DIRECTORY, 'sensitive.pdf')));
    }
    await Promise.all([...samples].map(([name, bytes]) => writeFile(join(root, name), bytes)));
    const deliveries = [];
    for (const page of [chat, gemini]) {
      await page.unroute('**/fixture-upload');
      await page.route('**/fixture-upload', async (route) => {
        deliveries.push(route.request().postDataBuffer());
        await route.fulfill({ status: 204 });
      });
      await page.evaluate(() => { window.fileEvents = []; });
    }
    const [block] = await admin('policies');
    const monitored = await admin('policies', { fileContentModes: { chatgpt: 'monitor' } });
    await popup.getByRole('button', { name: 'Sync now' }).click();
    await expectFileMode(chat, monitored.version, 'monitor');
    const refused = (page, reason) => page.getByRole('alert').filter({ hasText: reason }).waitFor();
    const pickPdf = (page, name) => pick(page, [join(root, name)]);
    const rows = async (version) => (await admin('events')).filter(({ policyVersion }) => policyVersion === version);

    await pickPdf(chat, 'private-pdf-disguised.png');
    await until(async () => (await rows(monitored.version)).some(({ ruleId, decision }) => ruleId === 'fixture-secret' && decision === 'monitor'),
      'The PDF text from the second page did not reach the metadata report.');
    assert.deepEqual(deliveries, [samples.get('private-pdf-disguised.png')]);
    const [installation] = await admin('installations');
    const unauthorized = await popup.evaluate(async (request) => {
      const contentRequest = chrome.runtime.sendMessage({ ...request, type: 'inspect-pdf' }).then((reply) => reply ?? null, () => null);
      const port = chrome.runtime.connect({ name: 'inspect-offscreen-pdf' });
      const parserRequest = new Promise((resolve) => {
        const timer = setTimeout(() => { port.disconnect(); resolve('timeout'); }, 1500);
        port.onDisconnect.addListener(() => { clearTimeout(timer); resolve(null); });
        port.onMessage.addListener((reply) => { clearTimeout(timer); port.disconnect(); resolve(reply); });
        port.postMessage(request);
      });
      return Promise.all([contentRequest, parserRequest]);
    }, { encoded: samples.get('private-pdf-disguised.png').toString('base64'), installationId: installation.installationId,
      version: monitored.version, assignmentVersion: 0, detectors: { mode: 'monitor' } });
    assert.deepEqual(unauthorized, [null, null]);

    const restored = await admin(`policies/${block.version}/restore`, {});
    await popup.getByRole('button', { name: 'Sync now' }).click();
    await expectFileMode(chat, restored.version, 'block');
    await expectFileMode(gemini, restored.version, 'block');
    await drop(gemini, gemini.locator('#drop-zone'), [join(root, 'private-pdf-credential.pdf')]);
    await refused(gemini, 'sensitive content');
    await input(chat).setInputFiles([]);
    await pickPdf(chat, 'private-pdf-disguised.png');
    await refused(chat, 'sensitive content');
    for (const name of [...samples.keys()].filter((name) => /(?:unreadable|embedded|too-many-pages|encrypted)/.test(name))) {
      await pickPdf(chat, name);
      await refused(chat, 'could not complete');
    }
    if (samples.has('private-pdf-exported.pdf')) {
      await pickPdf(chat, 'private-pdf-exported.pdf');
      await refused(chat, 'sensitive content');
    }
    assert.equal(deliveries.length, 1);
    if (process.env.ZEKVAR_DEMO_ARTIFACTS) {
      await chat.getByRole('alert').screenshot({ path: join(process.env.ZEKVAR_DEMO_ARTIFACTS, 'pdf-upload-blocked.png') });
    }
    await pickPdf(chat, 'public-summary.pdf');
    await until(() => deliveries.length === 2, 'The clean PDF did not reach the upload fixture.');
    assert.deepEqual(deliveries[1], safeBytes);

    const expected = ['gemini/pem-private-key/drop', 'chatgpt/fixture-secret/picker', ...Array(3).fill('chatgpt/file-inspection-unavailable/picker')];
    if (samples.has('private-pdf-encrypted.pdf')) expected.push('chatgpt/file-inspection-unavailable/picker', 'chatgpt/fixture-secret/picker');
    const evidence = await until(async () => {
      const stored = await rows(restored.version);
      return stored.length === expected.length && stored;
    }, 'Control did not retain the expected PDF metadata decisions.');
    assert.deepEqual(evidence.map(({ appId, ruleId, uploadMethod }) => `${appId}/${ruleId}/${uploadMethod}`).sort(), expected.sort());
    assert.ok(evidence.every(({ decision }) => decision === 'block'));
    assert.doesNotMatch(JSON.stringify([...posts, ...evidence]), /private-pdf|public-summary|ZEKVAR_TEST_SECRET|BEGIN PRIVATE KEY|%PDF|JVBERi/);
    assert.equal(fileDataSentToControl, false);
  });

  await t.test('recognizes English image text from bundled OCR and holds unclear or malformed images', async () => {
    const render = (...options) => textImage(chat, ...options);
    const sensitive = await render('image/png', ['Synthetic screenshot', marker]);
    const credential = await render('image/jpeg', ['Synthetic personnel form', 'SSN: 234-56-7890']);
    const clean = await render('image/jpeg', ['Approved synthetic image', 'Public reference manual']);
    function chunk(name, data) {
      const output = Buffer.alloc(data.length + 12);
      output.writeUInt32BE(data.length);
      output.write(name, 4);
      data.copy(output, 8);
      output.writeUInt32BE(crc32(output.subarray(4, -4)), output.length - 4);
      return output;
    }
    // Declare an animated PNG with two frames and reuse the original compressed data for frame two.
    const images = [];
    for (let index = 8; index + 12 <= sensitive.length;) {
      const length = sensitive.readUInt32BE(index);
      if (sensitive.toString('ascii', index + 4, index + 8) === 'IDAT') images.push(sensitive.subarray(index + 8, index + 8 + length));
      index += length + 12;
    }
    const frame = Buffer.alloc(26);
    sensitive.copy(frame, 4, 16, 24);
    const secondFrame = Buffer.from(frame);
    secondFrame.writeUInt32BE(1);
    const sequence = Buffer.from([0, 0, 0, 2]);
    const animated = Buffer.concat([sensitive.subarray(0, 33), chunk('acTL', Buffer.from([0, 0, 0, 2, 0, 0, 0, 0])),
      chunk('fcTL', frame), sensitive.subarray(33, -12), chunk('fcTL', secondFrame),
      chunk('fdAT', Buffer.concat([sequence, ...images])), sensitive.subarray(-12)]);
    const samples = new Map([
      ['ocr-secret.txt', sensitive],
      ['ocr-record.jpg', credential],
      ['ocr-public.jpg', clean],
      ['ocr-blank.png', await render('image/png', [])],
      ['ocr-too-wide.png', await render('image/png', ['Outside image limits'], 4100, 200)],
      ['ocr-truncated.png', sensitive.subarray(0, -12)],
      ['ocr-extra.jpg', Buffer.concat([clean, credential])],
      ['ocr-animated.png', animated],
    ]);
    await Promise.all([...samples].map(([name, bytes]) => writeFile(join(root, name), bytes)));
    const deliveries = [];
    for (const page of [chat, gemini]) {
      await page.unroute('**/fixture-upload');
      await page.route('**/fixture-upload', async (route) => {
        deliveries.push(route.request().postDataBuffer());
        await route.fulfill({ status: 204 });
      });
      await input(page).setInputFiles([]);
    }
    async function apply(mode) {
      const policy = await admin('policies', { ssnMode: 'block', fileContentModes: { chatgpt: mode, gemini: mode } });
      await popup.getByRole('button', { name: 'Sync now' }).click();
      await expectFileMode(chat, policy.version, mode);
      await expectFileMode(gemini, policy.version, mode);
      return policy.version;
    }
    const rows = async (version) => (await admin('events')).filter(({ policyVersion }) => policyVersion === version);
    const pickImage = (page, name) => pick(page, [join(root, name)]);
    const refused = (page, reason) => page.getByRole('alert').filter({ hasText: reason }).waitFor();
    const monitor = await apply('monitor');
    await pickImage(chat, 'ocr-secret.txt');
    await until(async () => (await rows(monitor)).some(({ ruleId, decision }) => ruleId === 'fixture-secret' && decision === 'monitor'),
      'The PNG text did not reach the Monitor metadata report.');
    assert.deepEqual(deliveries, [sensitive]);
    const [installation] = await admin('installations');
    const unauthorized = await popup.evaluate(async (request) => {
      const answer = await chrome.runtime.sendMessage(request).catch(() => undefined);
      return answer ?? null;
    }, { type: 'inspect-image', encoded: sensitive.toString('base64'), installationId: installation.installationId,
      version: monitor, assignmentVersion: 0 });
    assert.equal(unauthorized, null);

    const block = await apply('block');
    await drop(gemini, gemini.locator('#drop-zone'), [join(root, 'ocr-record.jpg')]);
    await refused(gemini, 'sensitive content');
    await input(chat).setInputFiles([]);
    await pickImage(chat, 'ocr-secret.txt');
    await refused(chat, 'sensitive content');
    if (process.env.ZEKVAR_DEMO_ARTIFACTS) {
      await chat.getByRole('alert').screenshot({ path: join(process.env.ZEKVAR_DEMO_ARTIFACTS, 'image-upload-blocked.png') });
    }
    for (const name of ['ocr-blank.png', 'ocr-too-wide.png', 'ocr-truncated.png', 'ocr-extra.jpg', 'ocr-animated.png']) {
      await pickImage(chat, name);
      await refused(chat, 'could not complete');
    }
    assert.equal(deliveries.length, 1);
    await pickImage(chat, 'ocr-public.jpg');
    await until(() => deliveries.length === 2, 'The original clean JPEG did not reach the native upload fixture.');
    assert.deepEqual(deliveries[1], clean);
    const evidence = await until(async () => {
      const stored = await rows(block);
      return stored.length === 7 && stored;
    }, 'Control did not receive the expected image decisions.');
    assert.deepEqual(evidence.map(({ appId, decision, ruleId, uploadMethod }) => `${appId}/${decision}/${ruleId}/${uploadMethod}`).sort(),
      ['chatgpt/block/fixture-secret/picker', 'gemini/block/us-social-security-number/drop',
        ...Array(5).fill('chatgpt/block/file-inspection-unavailable/picker')].sort());
    assert.doesNotMatch(JSON.stringify([...posts, ...evidence]), /ocr-secret|ocr-record|ZEKVAR_TEST_SECRET|234-56-7890|iVBORw0KGgo|\/9j\//);
    assert.equal(fileDataSentToControl, false);
  });

  await t.test('recognizes scanned PDF pages even when the document also contains selectable text', async () => {
    const image = async (lines) => ({ bytes: await textImage(chat, 'image/jpeg', lines), width: 960, height: 260 });
    const cleanImage = await image(['Approved scanned page', 'Public reference manual']);
    const secretImage = await image(['Synthetic scanned document', marker]);
    const identifierImage = await image(['Synthetic personnel record', 'SSN: 234-56-7890']);
    const scan = pdfFixture([{ image: secretImage }]);
    const clean = pdfFixture(Array.from({ length: 3 }, () => ({ image: cleanImage })));
    const mixed = pdfFixture([['Public cover'], { image: cleanImage }, { lines: ['Public heading'], image: identifierImage }]);
    const overPages = pdfFixture(Array.from({ length: 4 }, () => ({ image: cleanImage })));
    const sensitiveOverPages = pdfFixture([['Synthetic cover', marker], ...Array.from({ length: 4 }, () => ({ image: cleanImage }))]);
    const oversized = pdfFixture([{ image: { ...cleanImage, width: 4500, height: 3000 } }]);
    const samples = new Map([
      ['ocr-scanned-disguised.txt', scan],
      ['ocr-clean-three-pages.pdf', clean],
      ['ocr-mixed.pdf', mixed],
      ['ocr-too-many-image-pages.pdf', overPages],
      ['ocr-sensitive-over-limit.pdf', sensitiveOverPages],
      ['ocr-oversized-embedded.pdf', oversized],
    ]);
    await Promise.all([...samples].map(([name, bytes]) => writeFile(join(root, name), bytes)));
    const delivered = [];
    for (const page of [chat, gemini]) {
      await page.unroute('**/fixture-upload');
      await page.route('**/fixture-upload', async (route) => {
        delivered.push(route.request().postDataBuffer());
        await route.fulfill({ status: 204 });
      });
      await input(page).setInputFiles([]);
    }
    async function apply(mode) {
      const policy = await admin('policies', { ssnMode: 'block', fileContentModes: { chatgpt: mode, gemini: mode } });
      await popup.getByRole('button', { name: 'Sync now' }).click();
      await expectFileMode(chat, policy.version, mode);
      await expectFileMode(gemini, policy.version, mode);
      return policy.version;
    }
    const records = async (version) => (await admin('events')).filter(({ policyVersion }) => policyVersion === version);
    const choose = (page, name) => pick(page, [join(root, name)]);
    const refused = (page, reason) => page.getByRole('alert').filter({ hasText: reason }).waitFor();
    const monitor = await apply('monitor');
    await choose(chat, 'ocr-scanned-disguised.txt');
    const monitored = await until(async () => (await records(monitor))[0], 'The scanned page did not generate a Monitor decision.');
    assert.deepEqual([monitored.decision, monitored.ruleId], ['monitor', 'fixture-secret']);
    assert.deepEqual(delivered, [scan]);

    const block = await apply('block');
    await drop(gemini, gemini.locator('#drop-zone'), [join(root, 'ocr-mixed.pdf')]);
    await refused(gemini, 'sensitive content');
    await input(chat).setInputFiles([]);
    await choose(chat, 'ocr-scanned-disguised.txt');
    await refused(chat, 'sensitive content');
    if (process.env.ZEKVAR_DEMO_ARTIFACTS) {
      await chat.getByRole('alert').screenshot({ path: join(process.env.ZEKVAR_DEMO_ARTIFACTS, 'scanned-pdf-upload-blocked.png') });
    }
    for (const name of ['ocr-too-many-image-pages.pdf', 'ocr-oversized-embedded.pdf']) {
      await choose(chat, name);
      await refused(chat, 'could not complete');
    }
    await choose(chat, 'ocr-sensitive-over-limit.pdf');
    await refused(chat, 'sensitive content');
    assert.equal(delivered.length, 1);
    await choose(chat, 'ocr-clean-three-pages.pdf');
    await until(() => delivered.length === 2, 'The original clean scanned PDF did not reach the native upload fixture.');
    assert.deepEqual(delivered[1], clean);
    const evidence = await until(async () => {
      const entries = await records(block);
      return entries.length === 5 && entries;
    }, 'Control did not retain the scanned PDF decisions.');
    assert.deepEqual(evidence.map(({ appId, decision, ruleId, uploadMethod }) => `${appId}/${decision}/${ruleId}/${uploadMethod}`).sort(),
      ['chatgpt/block/fixture-secret/picker', 'gemini/block/us-social-security-number/drop',
        'chatgpt/block/fixture-secret/picker',
        ...Array(2).fill('chatgpt/block/file-inspection-unavailable/picker')].sort());
    assert.doesNotMatch(JSON.stringify([...posts, ...evidence]), /ocr-scanned|ocr-mixed|ZEKVAR_TEST_SECRET|234-56-7890|Public heading|%PDF|JVBERi/);
    assert.equal(fileDataSentToControl, false);
  });
});
