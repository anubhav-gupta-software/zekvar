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
import { generator, npiComplete } from './detection-corpus.mjs';

const { ZEKVAR_DEMO_API: api, ZEKVAR_DEMO_WEB: web, ZEKVAR_DEMO_TOKEN: owner, ZEKVAR_DEMO_ARTIFACTS: artifacts } = process.env;
assert.match(api ?? '', /^http:\/\/127\.0\.0\.1:\d+$/);
assert.match(web ?? '', /^http:\/\/(?:localhost|127\.0\.0\.1):\d+$/);
assert.match(owner ?? '', /^[a-f0-9]{64}$/);
// Synthetic NPI computed at runtime with a valid check digit. It is not assigned to any provider.
const { pick } = generator(0x4ea1c);
const npi = npiComplete('1' + pick('0123456789', 8));

async function admin(path, body, expect = 200) {
  const response = await fetch(`${api}/v1/admin/${path}`, {
    method: body === undefined ? 'GET' : 'POST', headers: { Authorization: `Bearer ${owner}`, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(5000),
  });
  assert.equal(response.status, expect, path);
  return expect === 200 ? response.json() : undefined;
}

async function until(check, failure) {
  for (let attempt = 0; attempt < 200; attempt++) {
    const result = await check();
    if (result) return result;
    await delay(100);
  }
  assert.fail(failure);
}

test('blocks an NPI in a prompt and a text attachment end to end and Control keeps only metadata', { timeout: 90_000 }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'zekvar-health-browser-'));
  const posts = [];
  const uploads = [];
  let browser;
  let policyResponses = 0;
  const proxy = createServer(async (request, response) => {
    try {
      if (request.url !== '/v1/enroll' && !request.url?.startsWith('/v1/browser/')) return response.writeHead(404).end();
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      if (body.length) posts.push(body.toString());
      const headers = Object.fromEntries(Object.entries(request.headers).filter(([name]) =>
        name === 'authorization' || name === 'content-type' || name.startsWith('x-zekvar-')));
      const upstream = await fetch(api + request.url, { method: request.method, headers,
        body: body.length ? body : undefined, signal: AbortSignal.timeout(5000) });
      if (request.url === '/v1/browser/policy' && upstream.ok) policyResponses++;
      response.writeHead(upstream.status, { 'Content-Type': 'application/json' }).end(await upstream.text());
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
  const [dashboard, popup, chat] = await Promise.all(Array.from({ length: 3 }, () => browser.newPage()));
  const [original] = await admin('policies');
  assert.deepEqual(original.healthProtection, { mode: 'off', recordFormats: [] });
  await admin('policies', { healthProtection: { mode: 'block', recordFormats: [{ prefix: 'MRN', digits: 8 }] } }, 400);
  await admin('policies', { healthProtection: { mode: 'on', recordFormats: [] } }, 400);

  await dashboard.goto(web);
  await dashboard.getByLabel('Control token').fill(owner);
  await dashboard.getByRole('button', { name: 'Sign in', exact: true }).click();
  await dashboard.getByRole('link', { name: 'Configure health identifiers', exact: true }).click();
  const run = dashboard.getByRole('button', { name: 'Run preview', exact: true });
  const formats = dashboard.getByLabel('Medical record number formats', { exact: true });
  await dashboard.getByLabel('Health identifiers', { exact: true }).selectOption('block');
  await formats.fill('MRN 8');
  await run.click();
  await dashboard.getByRole('alert').getByText(/Use distinct prefixes/).waitFor();
  await formats.fill('MRN- 8');
  await dashboard.getByLabel('Draft ChatGPT file content protection', { exact: true }).selectOption('block');
  const previewRequests = [];
  const capture = (request) => previewRequests.push([request.url(), request.postData()].join(' '));
  dashboard.on('request', capture);
  await dashboard.getByLabel('Custom prompt', { exact: true }).fill(`Referral for NPI ${npi}`);
  await run.click();
  const preview = dashboard.getByRole('table', { name: 'Preview results', exact: true });
  await preview.getByRole('row', { name: /^Custom prompt .*Allow.*Block/ }).waitFor();
  await preview.getByRole('row', { name: /^Synthetic NPI with label .*Allow.*Block/ }).waitFor();
  await preview.getByRole('row', { name: /^NPI-like number failing the check digit .*Allow.*Allow/ }).waitFor();
  await preview.getByRole('row', { name: /^Unlabeled 10-digit number .*Allow.*Allow/ }).waitFor();
  await preview.getByRole('row', { name: /^Synthetic DEA number with label .*Allow.*Block/ }).waitFor();
  await preview.getByRole('row', { name: /^Synthetic Medicare Beneficiary Identifier .*Allow.*Block/ }).waitFor();
  await preview.getByRole('row', { name: /^Medical record number · MRN- 8 .*Allow.*Block/ }).waitFor();
  await preview.getByRole('row', { name: /^ChatGPT synthetic NPI file .*Allow.*Block/ }).waitFor();
  if (artifacts) await dashboard.locator('#draft-health').screenshot({ path: join(artifacts, '43-health-identifiers.png') });
  dashboard.once('dialog', (dialog) => dialog.accept());
  await dashboard.getByRole('button', { name: 'Publish previewed policy', exact: true }).click();
  await dashboard.getByText(/Previewed policy published as version/).waitFor();
  dashboard.off('request', capture);
  assert.ok(previewRequests.every((request) => !request.includes(npi)), 'Preview sent the custom prompt to Control.');
  const [current] = await admin('policies');
  assert.deepEqual(current.healthProtection, { mode: 'block', recordFormats: [{ prefix: 'MRN-', digits: 8 }] });

  await popup.goto(new URL('popup.html', worker.url()).href);
  const { grant } = await admin('enrollment-grants', {});
  await popup.getByLabel('Enrollment grant', { exact: true }).fill(grant);
  await popup.getByRole('button', { name: 'Enroll this browser', exact: true }).click();
  await popup.getByText(`Connected to Control · MONITOR v${current.version}`, { exact: true }).waitFor();
  await until(async () => (await admin('installations')).some(({ appliedPolicyVersion }) => appliedPolicyVersion === current.version),
    'Control did not acknowledge the health identifier policy.');
  const html = await readFile(new URL('./guest-chatgpt-composer.html', import.meta.url), 'utf8');
  await chat.route('https://chatgpt.com/**', (route) => route.fulfill({ contentType: 'text/html', body: html }));
  await chat.goto('https://chatgpt.com/uc/health-fixture');
  await chat.getByText(/Health identifiers block/).waitFor();
  const draft = chat.getByPlaceholder('Ask ChatGPT', { exact: true });
  const sends = chat.locator('#fixture-sends');
  await draft.fill(`Draft a referral letter. Referring provider NPI: ${npi}`);
  await draft.press('Enter');
  await chat.getByRole('alert').filter({ hasText: 'National Provider Identifier' }).waitFor();
  assert.equal(await sends.textContent(), '0');
  assert.equal(await chat.getByRole('button', { name: 'Request policy review', exact: true }).isHidden(), true);
  await chat.getByRole('button', { name: 'Redact detected values', exact: true }).click();
  assert.equal(await draft.inputValue(), 'Draft a referral letter. Referring provider NPI: [REDACTED]');
  await draft.press('Enter');
  assert.equal(await sends.textContent(), '1');
  await draft.fill(`Call the office at ${npi.slice(0, 3)}-555-${npi.slice(6)} about invoice ${npi}`);
  await draft.press('Enter');
  assert.equal(await sends.textContent(), '2', 'An unlabeled number and a phone number are not NPIs.');
  if (artifacts) await chat.screenshot({ path: join(artifacts, '44-health-identifier-block.png') });

  const upload = await browser.newPage();
  const uploadHtml = await readFile(new URL('./upload-composer.html', import.meta.url), 'utf8');
  await upload.route('https://chatgpt.com/**', (route) => route.fulfill({ contentType: 'text/html', body: uploadHtml }));
  await upload.route('**/fixture-upload', (route) => { uploads.push(route.request().postData()); return route.fulfill({ status: 204 }); });
  await upload.goto('https://chatgpt.com/c/health-file-fixture');
  await upload.evaluate(() => { window.captureUploads = true; });
  await upload.getByText(/Health identifiers block/).waitFor();
  const file = join(root, 'referral-roster.txt');
  await writeFile(file, `Provider roster\nRoe, Jane — NPI ${npi}\n`, { mode: 0o600 });
  const chooser = upload.waitForEvent('filechooser');
  await upload.getByLabel('Attach fixture files', { exact: true }).click();
  await (await chooser).setFiles(file);
  await upload.getByRole('alert').filter({ hasText: 'sensitive content' }).waitFor();
  assert.deepEqual(uploads, []);

  const decisions = await until(async () => {
    const entries = (await admin('events')).filter(({ policyVersion }) => policyVersion === current.version);
    return entries.length >= 2 && entries;
  }, 'The block decisions did not reach Control.');
  assert.deepEqual(decisions.map(({ ruleId, detectorCategory, decision, uploadMethod }) =>
    `${ruleId}/${detectorCategory}/${decision}/${uploadMethod ?? 'prompt'}`).sort(), [
    'us-national-provider-identifier/health/block/picker',
    'us-national-provider-identifier/health/block/prompt',
  ]);
  const stored = JSON.stringify(await admin('events/export'));
  for (const sample of [npi, npi.slice(0, 6), 'referral', 'Roe, Jane', 'roster']) {
    assert.ok(!stored.toLowerCase().includes(sample.toLowerCase()), `Control stored ${sample.slice(0, 3)}…`);
    assert.ok(!posts.join('\n').toLowerCase().includes(sample.toLowerCase()), `Browser sent ${sample.slice(0, 3)}… to Control`);
  }

  const restored = await admin(`policies/${original.version}/restore`, {});
  assert.deepEqual(restored.healthProtection, { mode: 'off', recordFormats: [] });
  await popup.bringToFront();
  const prior = policyResponses;
  await popup.getByRole('button', { name: 'Sync now', exact: true }).click();
  await until(() => policyResponses > prior, 'The popup did not fetch the restored policy.');
  // The fixture shows its Send control only while the draft has text, so fill the draft before reading the panel.
  await draft.fill(`Referring provider NPI: ${npi}`);
  await chat.getByText(`Zekvar · MONITOR v${restored.version}`, { exact: true }).waitFor();
  await draft.press('Enter');
  assert.equal(await sends.textContent(), '3');
});
