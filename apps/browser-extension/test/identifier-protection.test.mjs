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
import { officeFile, textXml } from './office-fixture.mjs';

const { ZEKVAR_DEMO_API: api, ZEKVAR_DEMO_WEB: web, ZEKVAR_DEMO_TOKEN: owner, ZEKVAR_DEMO_ARTIFACTS: artifacts } = process.env;
assert.match(api ?? '', /^http:\/\/127\.0\.0\.1:\d+$/);
assert.match(web ?? '', /^http:\/\/(?:localhost|127\.0\.0\.1):\d+$/);
assert.match(owner ?? '', /^[a-f0-9]{64}$/);
const id = 'CUST-07392468';
const ticket = 'CASE_463821';

async function admin(path, body) {
  const response = await fetch(`${api}/v1/admin/${path}`, {
    method: body === undefined ? 'GET' : 'POST', headers: { Authorization: `Bearer ${owner}`, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(5000),
  });
  assert.equal(response.status, 200, path);
  return response.json();
}

async function until(check, failure) {
  for (let attempt = 0; attempt < 50; attempt++) {
    const result = await check();
    if (result) return result;
    await delay(100);
  }
  assert.fail(failure);
}

test('configures identifier protection in Control and enforces it in enrolled Chrome', { timeout: 90_000 }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'zekvar-identifier-browser-'));
  const uploads = [];
  const posts = [];
  let browser;
  let responseMode;
  let policyResponses = 0;
  let alteredPolicySent = false;
  let checkedAlteredPolicy = false;
  let alteredSsnModeSent = false;
  let checkedAlteredSsnPolicy = false;
  let lostEventId;
  const proxy = createServer(async (request, response) => {
    try {
      if (request.url !== '/v1/enroll' && !request.url?.startsWith('/v1/browser/')) return response.writeHead(404).end();
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      const event = request.url === '/v1/browser/events' ? JSON.parse(body) : undefined;
      if (event) posts.push(event);
      const headers = Object.fromEntries(Object.entries(request.headers).filter(([name]) =>
        name === 'authorization' || name === 'content-type' || name.startsWith('x-zekvar-')));
      const upstream = await fetch(api + request.url, { method: request.method, headers,
        body: body.length ? body : undefined, signal: AbortSignal.timeout(5000) });
      let output = await upstream.text();
      if (responseMode && request.url === '/v1/browser/policy' && upstream.ok) {
        const policy = JSON.parse(output);
        if (responseMode === 'ssnChanged') {
          policy.ssnMode = 'off';
          alteredSsnModeSent = true;
        } else {
          policy.identifierProtection = responseMode === 'changed'
            ? { mode: 'off', formats: [] } : { mode: 'block', formats: [{ prefix: '.*', digits: 8 }] };
        }
        output = JSON.stringify(policy);
        if (responseMode === 'changed') alteredPolicySent = true;
      }
      if (request.url === '/v1/browser/policy' && upstream.ok) policyResponses++;
      if (responseMode === 'changed' && alteredPolicySent && request.url === '/v1/browser/heartbeat') {
        checkedAlteredPolicy = JSON.parse(body).identifiersApplied === true;
      }
      if (responseMode === 'ssnChanged' && alteredSsnModeSent && request.url === '/v1/browser/heartbeat') {
        checkedAlteredSsnPolicy = JSON.parse(body).ssnModeApplied === true;
      }
      if (event && upstream.ok && lostEventId === null) {
        lostEventId = event.eventId;
        return response.writeHead(503).end();
      }
      response.writeHead(upstream.status, { 'Content-Type': 'application/json' }).end(output);
    } catch { response.writeHead(502).end(); }
  });
  proxy.listen(0, '127.0.0.1');
  await once(proxy, 'listening');
  t.after(async () => {
    await browser?.close();
    await new Promise((resolve) => { proxy.close(resolve); proxy.closeAllConnections(); });
    await rm(root, { recursive: true, force: true });
  });
  const extension = join(root, 'extension');
  execFileSync(process.execPath, ['build.mjs'], { cwd: fileURLToPath(new URL('..', import.meta.url)),
    env: { ...process.env, ZEKVAR_EXTENSION_OUTDIR: extension, ZEKVAR_CONTROL_PORT: String(proxy.address().port) } });
  browser = await chromium.launchPersistentContext(join(root, 'profile'), {
    channel: 'chromium', headless: process.env.ZEKVAR_DEMO_HEADED !== '1', viewport: { width: 1440, height: 960 },
    args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`],
  });
  browser.setDefaultTimeout(7000);
  const worker = browser.serviceWorkers()[0] ?? await browser.waitForEvent('serviceworker');
  const [dashboard, popup, chat, gemini, claude] = await Promise.all(Array.from({ length: 5 }, () => browser.newPage()));
  const [original] = await admin('policies');
  await dashboard.goto(web);
  await dashboard.getByLabel('Control token').fill(owner);
  await dashboard.getByRole('button', { name: 'Sign in', exact: true }).click();
  await dashboard.getByRole('link', { name: 'Configure organization identifiers', exact: true }).click();
  const mode = dashboard.getByLabel('Organization identifier detection', { exact: true });
  const formats = dashboard.getByLabel('Identifier formats', { exact: true });
  const run = dashboard.getByRole('button', { name: 'Run preview', exact: true });
  const publish = dashboard.getByRole('button', { name: 'Publish previewed policy', exact: true });
  await mode.selectOption('warn');
  await run.click();
  await dashboard.getByRole('alert').getByText(/Enter at least one identifier format/).waitFor();
  await formats.fill('CUST- 8\ncust- 6');
  await run.click();
  await dashboard.getByRole('alert').getByText(/Use distinct prefixes/).waitFor();
  assert.equal(await publish.count(), 0);
  await formats.fill('cust- 8\nCASE_ 6');
  await dashboard.getByLabel('Draft ChatGPT file content protection', { exact: true }).selectOption('block');
  await dashboard.getByLabel('Draft Gemini file content protection', { exact: true }).selectOption('monitor');
  await dashboard.getByLabel('Draft Claude prompt protection', { exact: true }).selectOption('on');
  const previewRequests = [];
  const capture = (request) => previewRequests.push([request.url(), request.postData()].join(' '));
  dashboard.on('request', capture);
  await dashboard.getByLabel('Custom prompt', { exact: true }).fill(`Controlled preview (${id})`);
  await run.click();
  const preview = dashboard.getByRole('table', { name: 'Preview results', exact: true });
  await preview.getByRole('row', { name: /Organization identifier CUST-.*Allow.*Warn/ }).waitFor();
  await preview.getByRole('row', { name: /ChatGPT identifier file CUST-.*Allow.*Block/ }).waitFor();
  await preview.getByRole('row', { name: /Gemini identifier file CASE_.*Allow.*Monitor/ }).waitFor();
  await dashboard.setViewportSize({ width: 390, height: 844 });
  assert.equal(await dashboard.evaluate(() => document.documentElement.scrollWidth === document.documentElement.clientWidth), true);
  await dashboard.setViewportSize({ width: 1440, height: 960 });
  if (artifacts) await dashboard.locator('#draft-identifiers').screenshot({ path: join(artifacts, '38-identifier-policy.png') });
  dashboard.once('dialog', (dialog) => dialog.accept());
  await publish.click();
  await dashboard.getByText(/Previewed policy published as version/).waitFor();
  dashboard.off('request', capture);
  assert.ok(previewRequests.every((request) => !request.includes(id)));
  const [current] = await admin('policies');
  assert.deepEqual(current.identifierProtection, { mode: 'warn', formats: [{ prefix: 'CASE_', digits: 6 }, { prefix: 'CUST-', digits: 8 }] });

  await popup.goto(new URL('popup.html', worker.url()).href);
  const { grant } = await admin('enrollment-grants', {});
  await popup.getByLabel('Enrollment grant', { exact: true }).fill(grant);
  await popup.getByRole('button', { name: 'Enroll this browser', exact: true }).click();
  const sync = async (version) => {
    await popup.bringToFront();
    const prior = policyResponses;
    await popup.getByRole('button', { name: 'Sync now', exact: true }).click();
    await until(() => policyResponses > prior, 'The extension popup did not fetch the current policy.');
    if (version) {
      await popup.getByText(`Connected to Control · MONITOR v${version}`, { exact: true }).waitFor();
      await until(async () => (await admin('installations')).some(({ appliedPolicyVersion }) => appliedPolicyVersion === version),
        'Control did not acknowledge the Browser policy.');
    }
  };
  await popup.getByText(`Connected to Control · MONITOR v${current.version}`, { exact: true }).waitFor();
  async function open(page, url, fixture) {
    const html = await readFile(new URL(fixture, import.meta.url), 'utf8');
    await page.route(`${new URL(url).origin}/**`, (route) => route.fulfill({ contentType: 'text/html', body: html }));
    await page.goto(url);
    await page.getByText(/Organization identifiers warn/).waitFor();
  }
  await Promise.all([
    open(chat, 'https://chatgpt.com/uc/identifier-fixture', './guest-chatgpt-composer.html'),
    open(gemini, 'https://gemini.google.com/app', './gemini-composer.html'),
    open(claude, 'https://claude.ai/new', './claude-composer.html'),
  ]);
  const chatDraft = chat.getByPlaceholder('Ask ChatGPT', { exact: true });
  const chatSend = chat.getByRole('button', { name: 'Send message', exact: true });
  const chatCount = chat.locator('#fixture-sends');
  await chatDraft.fill(`Case ${id}`);
  await chatSend.click();
  await chat.getByRole('alert').filter({ hasText: 'organization identifier' }).waitFor();
  assert.equal(await chatCount.textContent(), '0');
  await chat.getByRole('button', { name: 'Continue anyway', exact: true }).click();
  assert.equal(await chatCount.getAttribute('data-last-draft'), `Case ${id}`);
  await chatDraft.fill(`Compare (${id}) and ${ticket}.`);
  await chatDraft.press('Enter');
  await chat.getByRole('button', { name: 'Redact detected values', exact: true }).click();
  assert.equal(await chatDraft.inputValue(), 'Compare ([REDACTED]) and [REDACTED].');
  assert.equal(await chatCount.textContent(), '1');
  await chatSend.click();
  assert.equal(await chatCount.getAttribute('data-last-draft'), 'Compare ([REDACTED]) and [REDACTED].');
  const geminiDraft = gemini.getByRole('textbox', { name: 'Enter a prompt for Gemini', exact: true });
  await geminiDraft.fill(ticket.toLowerCase());
  await geminiDraft.press('Enter');
  await gemini.getByRole('alert').filter({ hasText: 'organization identifier' }).waitFor();
  assert.equal(await gemini.locator('#fixture-sends').textContent(), '0');
  await geminiDraft.fill(`Example ${ticket}7`);
  await geminiDraft.press('Enter');
  assert.equal(await gemini.locator('#fixture-sends').textContent(), '1');

  const stronger = await admin('policies', { identifierProtection: { ...current.identifierProtection, mode: 'block' } });
  await sync(stronger.version);
  await claude.getByText(/Organization identifiers block/).waitFor();
  await claude.getByRole('textbox', { name: 'Fixture prompt', exact: true }).fill(ticket);
  await claude.locator('#composer button').click();
  await claude.getByRole('alert').filter({ hasText: 'Submission blocked' }).waitFor();
  assert.equal(await claude.locator('#submitted').textContent(), '0');

  const scratchFile = join(root, 'controlled-document.docx');
  const plainFile = join(root, 'controlled-note.txt');
  await Promise.all([
    writeFile(scratchFile, officeFile('docx', [['word/document.xml', textXml.word(`<w:p><w:r><w:t>${id}</w:t></w:r></w:p>`)]])),
    writeFile(plainFile, ticket),
  ]);
  for (const [app, url, file] of [
    ['chatgpt', 'https://chatgpt.com/c/file-identifier-fixture', scratchFile],
    ['gemini', 'https://gemini.google.com/app', plainFile],
  ]) {
    const page = await browser.newPage();
    const html = await readFile(new URL('./upload-composer.html', import.meta.url), 'utf8');
    await page.route(`${new URL(url).origin}/**`, (route) => route.fulfill({ contentType: 'text/html', body: html }));
    await page.route('**/fixture-upload', (route) => { uploads.push({ app, content: route.request().postData() }); return route.fulfill({ status: 204 }); });
    await page.goto(url);
    await page.evaluate(() => { window.captureUploads = true; });
    await page.getByText(/Organization identifiers block/).waitFor();
    const chooser = page.waitForEvent('filechooser');
    await page.getByLabel('Attach fixture files', { exact: true }).click();
    await (await chooser).setFiles(file);
    if (app === 'chatgpt') {
      await page.getByRole('alert').filter({ hasText: 'sensitive content' }).waitFor();
      assert.deepEqual(await page.evaluate(() => window.fileEvents), []);
    } else await until(() => uploads.length, 'The monitor-only attachment did not reach the site fixture.');
    await until(async () => (await admin('events')).some((event) => event.appId === app && event.uploadMethod === 'picker' &&
      event.ruleId === 'organization-identifier'), 'The attachment decision did not reach Control.');
    await page.close();
  }
  assert.deepEqual(uploads, [{ app: 'gemini', content: ticket }]);

  await chat.getByText(/Organization identifiers block/).waitFor();
  responseMode = 'changed';
  await sync();
  await until(() => checkedAlteredPolicy, 'The altered version replaced its cached mode.');
  responseMode = 'invalid';
  await sync();
  await chat.getByText(/Offline policy/).waitFor();
  await chatDraft.fill(id);
  await chatSend.click();
  await chat.getByRole('alert').filter({ hasText: 'Submission blocked' }).waitFor();
  assert.equal(await chatCount.textContent(), '2');
  responseMode = undefined;
  await sync(stronger.version);
  await until(async () => (await admin('events')).some(({ appId, policyVersion, decision, uploadMethod }) =>
    appId === 'chatgpt' && policyVersion === stronger.version && decision === 'block' && !uploadMethod), 'Queued offline decision was not delivered.');
  lostEventId = null;
  await chatDraft.fill(ticket);
  await chatDraft.press('Enter');
  await until(() => lostEventId, 'Control proxy did not suppress the event acknowledgment.');
  await sync(stronger.version);
  await until(() => posts.filter(({ eventId }) => eventId === lostEventId).length === 2, 'Browser did not retry with the same event ID.');

  const excepted = await admin('policies', { promptExceptions: [{ appId: 'chatgpt', ruleId: 'organization-identifier',
    expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(), reason: 'Synthetic approved transfer' }] });
  await sync(excepted.version);
  await chat.getByText(new RegExp(`v${excepted.version}.*Organization identifiers block`)).waitFor();
  await chatDraft.fill(id);
  await chatDraft.press('Enter');
  assert.equal(await chatCount.getAttribute('data-last-draft'), id);
  await until(async () => (await admin('events')).some(({ policyVersion, decision }) => policyVersion === excepted.version && decision === 'exception_applied'),
    'The app-scoped identifier exception did not reach Control.');
  await gemini.getByText(new RegExp(`v${excepted.version}.*Organization identifiers block`)).waitFor();
  await geminiDraft.fill(id);
  await geminiDraft.press('Enter');
  await gemini.getByRole('alert').filter({ hasText: 'Submission blocked' }).waitFor();
  const monitored = await admin('policies', { identifierProtection: { ...current.identifierProtection, mode: 'monitor' } });
  await sync(monitored.version);
  await chat.getByText(/Organization identifiers monitor/).waitFor();
  await chatDraft.fill(ticket);
  await chatDraft.press('Enter');
  await until(async () => (await admin('events')).some(({ policyVersion, decision }) => policyVersion === monitored.version && decision === 'monitor'),
    'The monitor-only identifier decision did not reach Control.');

  await dashboard.goto(`${web}/#events`);
  await dashboard.getByRole('table', { name: 'Security events', exact: true }).getByText('Organization identifier', { exact: true }).first().waitFor();
  const { entries } = await admin('events/export');
  const decisions = entries.filter(({ ruleId }) => ruleId === 'organization-identifier');
  assert.equal(decisions.filter(({ eventId }) => eventId === lostEventId).length, 1);
  assert.deepEqual(decisions.filter(({ uploadMethod }) => uploadMethod).map(({ appId, decision }) => `${appId}/${decision}`).sort(),
    ['chatgpt/block', 'gemini/monitor']);
  assert.equal(decisions.filter(({ decision }) => decision === 'warn_override').length, 1);
  assert.doesNotMatch(JSON.stringify([...posts, ...entries]), /CUST-|CASE_|07392468|463821|controlled-document/);

  const restored = await admin(`policies/${original.version}/restore`, {});
  await sync(restored.version);
  await chatDraft.fill(id);
  await chat.getByText(`Zekvar · MONITOR v${restored.version}`, { exact: true }).waitFor();
  await chatDraft.press('Enter');
  assert.equal(await chatCount.getAttribute('data-last-draft'), id);

  await t.test('protects possible U.S. Social Security numbers in prompts and files', async () => {
    const synthetic = '899-97-4321';
    const compact = synthetic.replaceAll('-', '');
    const ruleId = 'us-social-security-number';
    await chatDraft.fill(synthetic);
    await chatDraft.press('Enter');
    assert.equal(await chatCount.getAttribute('data-last-draft'), synthetic);
    assert.ok(!(await admin('events')).some((event) => event.ruleId === ruleId));
    const previewRequests = [];
    const capture = (request) => previewRequests.push(request.postData() ?? '');
    await dashboard.goto(`${web}/preview`);
    await dashboard.getByLabel('Draft U.S. Social Security number', { exact: true }).selectOption('warn');
    await dashboard.getByLabel('Draft ChatGPT file content protection', { exact: true }).selectOption('block');
    await dashboard.getByLabel('Draft Gemini file content protection', { exact: true }).selectOption('monitor');
    await dashboard.getByLabel('Draft Claude prompt protection', { exact: true }).selectOption('on');
    await dashboard.getByLabel('Custom prompt', { exact: true }).fill(`Contains SSN: ${compact}`);
    dashboard.on('request', capture);
    await run.click();
    const preview = dashboard.getByRole('table', { name: 'Preview results', exact: true });
    await preview.getByRole('row', { name: /Synthetic U.S. SSN.*Allow.*Warn/ }).waitFor();
    await preview.getByRole('row', { name: /ChatGPT synthetic SSN file.*Allow.*Block/ }).waitFor();
    await preview.getByRole('row', { name: /Gemini synthetic SSN file.*Allow.*Monitor/ }).waitFor();
    if (artifacts) await preview.getByRole('row', { name: /Synthetic U.S. SSN.*Allow.*Warn/ })
      .screenshot({ path: join(artifacts, 'ssn-policy-preview.png') });
    dashboard.once('dialog', (dialog) => dialog.accept());
    await publish.click();
    await dashboard.getByText(/Previewed policy published as version/).waitFor();
    dashboard.off('request', capture);
    assert.ok(previewRequests.every((request) => !request.includes(compact) && !request.includes(synthetic)));

    const [warn] = await admin('policies');
    assert.equal(warn.ssnMode, 'warn');
    await sync(warn.version);
    await chat.getByText(/U.S. SSN warn/).waitFor();
    await chatDraft.fill(`SSN: ${compact}`);
    await chatSend.click();
    await chat.getByRole('alert').filter({ hasText: 'possible U.S. Social Security number' }).waitFor();
    const beforeSend = Number(await chatCount.textContent());
    await chat.getByRole('button', { name: 'Continue anyway', exact: true }).click();
    assert.equal(await chatCount.getAttribute('data-last-draft'), `SSN: ${compact}`);
    await chatDraft.fill(`Compare "${synthetic}" and SSN: ${compact}.`);
    await chatDraft.press('Enter');
    await chat.getByRole('button', { name: 'Redact detected values', exact: true }).click();
    assert.equal(await chatDraft.inputValue(), 'Compare "[REDACTED]" and SSN: [REDACTED].');
    assert.equal(Number(await chatCount.textContent()), beforeSend + 1);
    await chatSend.click();
    assert.equal(Number(await chatCount.textContent()), beforeSend + 2);

    const blocked = await admin('policies', { ssnMode: 'block' });
    await sync(blocked.version);
    await gemini.getByText(/U.S. SSN block/).waitFor();
    await geminiDraft.fill(synthetic);
    await geminiDraft.press('Enter');
    await gemini.getByRole('alert').filter({ hasText: 'Submission blocked' }).waitFor();
    const geminiCount = Number(await gemini.locator('#fixture-sends').textContent());
    await geminiDraft.fill(`Order number ${compact}`);
    await geminiDraft.press('Enter');
    assert.equal(Number(await gemini.locator('#fixture-sends').textContent()), geminiCount + 1);
    await claude.getByText(/U.S. SSN block/).waitFor();
    await claude.getByRole('textbox', { name: 'Fixture prompt', exact: true }).fill(`SSN: ${compact}`);
    await claude.locator('#composer button').click();
    await claude.getByRole('alert').filter({ hasText: 'Submission blocked' }).waitFor();
    assert.equal(await claude.locator('#submitted').textContent(), '0');

    const reachedSites = [];
    const wordFile = join(root, 'controlled-ssn.docx');
    const textFile = join(root, 'controlled-ssn.txt');
    const text = `SSN: ${compact}`;
    await Promise.all([
      writeFile(wordFile, officeFile('docx', [['word/document.xml', textXml.word(`<w:p><w:r><w:t>${text}</w:t></w:r></w:p>`)]])),
      writeFile(textFile, text),
    ]);
    for (const [app, url, file, decision] of [
      ['chatgpt', 'https://chatgpt.com/c/ssn-file-fixture', wordFile, 'block'],
      ['gemini', 'https://gemini.google.com/app', textFile, 'monitor'],
    ]) {
      const page = await browser.newPage();
      await page.route(`${new URL(url).origin}/**`, (route) => route.fulfill({ contentType: 'text/html',
        body: '<h1>Controlled fixture resource</h1>' }));
      const html = await readFile(new URL('./upload-composer.html', import.meta.url), 'utf8');
      await page.route(url, (route) => route.fulfill({ contentType: 'text/html', body: html }));
      await page.route('**/fixture-upload', (route) => {
        reachedSites.push({ app, content: route.request().postData() });
        return route.fulfill({ status: 204 });
      });
      await page.goto(url);
      await page.evaluate(() => { window.captureUploads = true; });
      await page.getByText(/U.S. SSN block/).waitFor();
      const chooser = page.waitForEvent('filechooser');
      await page.getByLabel('Attach fixture files', { exact: true }).click();
      await (await chooser).setFiles(file);
      if (decision === 'block') {
        await page.getByRole('alert').filter({ hasText: 'sensitive content' }).waitFor();
        assert.deepEqual(await page.evaluate(() => window.fileEvents), []);
      } else {
        await until(() => reachedSites.some((row) => row.app === app), 'The monitored SSN file did not reach Gemini.');
      }
      await until(async () => (await admin('events')).some((event) => event.appId === app && event.uploadMethod === 'picker' &&
        event.ruleId === ruleId && event.decision === decision), 'The SSN attachment decision did not reach Control.');
      await page.close();
    }
    assert.deepEqual(reachedSites, [{ app: 'gemini', content: text }]);

    responseMode = 'ssnChanged';
    await sync();
    await until(() => checkedAlteredSsnPolicy, 'Browser did not retain the acknowledged SSN mode after the altered response.');
    await chat.getByText(new RegExp(`v${blocked.version}.*U.S. SSN block`)).waitFor();
    await chatDraft.fill(synthetic);
    await chatSend.click();
    await chat.getByRole('alert').filter({ hasText: 'Submission blocked' }).waitFor();
    responseMode = undefined;
    await sync(blocked.version);
    const monitored = await admin('policies', { ssnMode: 'monitor' });
    await sync(monitored.version);
    await chat.getByText(/U.S. SSN monitor/).waitFor();
    await chatDraft.fill(synthetic);
    await chatDraft.press('Enter');
    assert.equal(await chatCount.getAttribute('data-last-draft'), synthetic);
    await until(async () => (await admin('events')).some((event) =>
      event.ruleId === ruleId && event.policyVersion === monitored.version && event.decision === 'monitor'),
    'The monitored SSN prompt did not reach Control.');
    await dashboard.goto(`${web}/#events`);
    await dashboard.getByRole('table', { name: 'Security events', exact: true }).getByText('U.S. Social Security number', { exact: true }).first().waitFor();
    const { entries } = await admin('events/export');
    const decisions = entries.filter((event) => event.ruleId === ruleId);
    assert.ok(decisions.some((event) => event.decision === 'warn_override'));
    assert.ok(decisions.some((event) => event.appId === 'claude' && event.decision === 'block'));
    assert.ok(decisions.every((event) => event.detectorCategory === 'government-identifier'));
    const report = await admin('reports/ai-enforcement?days=7');
    assert.ok(report.byRule.some(({ id }) => id === ruleId));
    assert.doesNotMatch(JSON.stringify([...posts, ...entries, report]), /899-97-4321|899974321|controlled-ssn/);
  });
});
