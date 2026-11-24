import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const { ZEKVAR_DEMO_API: api, ZEKVAR_DEMO_WEB: web, ZEKVAR_DEMO_TOKEN: owner, ZEKVAR_DEMO_ARTIFACTS: artifacts } = process.env;
assert.match(api ?? '', /^http:\/\/127\.0\.0\.1:\d+$/);
assert.match(web ?? '', /^http:\/\/localhost:\d+$/);
assert.match(owner ?? '', /^[a-f0-9]{64}$/);

async function admin(path, body, status = 200) {
  const response = await fetch(`${api}/v1/admin/${path}`, {
    method: body ? 'POST' : 'GET', headers: { Authorization: `Bearer ${owner}`, 'Content-Type': 'application/json' },
    body: body && JSON.stringify(body), signal: AbortSignal.timeout(5000),
  });
  assert.equal(response.status, status, path);
  return status === 204 ? undefined : response.json();
}

test('employees request review of an actual blocked prompt and administrators resolve it through existing policy', { timeout: 90_000 }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'zekvar-prompt-request-test-'));
  const dist = join(root, 'extension');
  const recorded = [];
  let loseReply = true;
  let profile;
  const proxy = createServer(async (request, reply) => {
    try {
      if (!request.url?.startsWith('/v1/browser/') && request.url !== '/v1/enroll') return reply.writeHead(404).end();
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      const isRequest = request.url === '/v1/browser/prompt-exception-requests';
      if (isRequest) recorded.push(JSON.parse(body));
      const headers = Object.fromEntries(Object.entries(request.headers).filter(([name]) =>
        name === 'authorization' || name === 'content-type' || name.startsWith('x-zekvar-')));
      const upstream = await fetch(api + request.url, { method: request.method, headers,
        body: body.length ? body : undefined, signal: AbortSignal.timeout(5000) });
      const text = await upstream.text();
      if (isRequest && upstream.ok && loseReply) {
        loseReply = false;
        return reply.writeHead(503).end();
      }
      reply.writeHead(upstream.status, { 'Content-Type': 'application/json' }).end(text);
    } catch {
      reply.writeHead(502).end();
    }
  }).listen(0, '127.0.0.1');
  t.after(async () => {
    await profile?.close();
    proxy.closeAllConnections();
    await new Promise((resolve) => proxy.close(resolve));
    await rm(root, { recursive: true, force: true });
  });
  await once(proxy, 'listening');
  const env = { ...process.env, ZEKVAR_CONTROL_PORT: String(proxy.address().port), ZEKVAR_EXTENSION_OUTDIR: dist };
  delete env.ZEKVAR_CONTROL_ORIGIN;
  execFileSync(process.execPath, ['build.mjs'], { cwd: fileURLToPath(new URL('..', import.meta.url)), env });
  profile = await chromium.launchPersistentContext(join(root, 'profile'), {
    channel: 'chromium', headless: process.env.ZEKVAR_DEMO_HEADED !== '1',
    args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`],
  });
  profile.setDefaultTimeout(7000);
  const baseline = await admin('policies', { mode: 'block' });
  const group = await admin('policy-groups', { name: 'Employee review pilot' });
  const worker = profile.serviceWorkers()[0] ?? await profile.waitForEvent('serviceworker');
  const popup = await profile.newPage();
  await popup.goto(new URL('popup.html', worker.url()).href);
  await popup.getByLabel('Enrollment grant').fill((await admin('enrollment-grants', {})).grant);
  await popup.getByRole('button', { name: 'Enroll this browser', exact: true }).click();
  await popup.getByText(`Connected to Control · BLOCK v${baseline.version}`, { exact: true }).waitFor();
  const [browser] = await admin('installations');
  await admin(`installations/${browser.installationId}/policy-group`, { groupId: group.id }, 204);
  await popup.getByRole('button', { name: 'Sync now', exact: true }).click();
  await popup.waitForFunction(() => !document.querySelector('#sync').disabled);
  const privateSample = 'private synthetic request ZEKVAR_TEST_SECRET';
  async function open(address, filename, selector) {
    const tab = await profile.newPage();
    const fixture = await readFile(new URL(filename, import.meta.url), 'utf8');
    await tab.route(`${new URL(address).origin}/**`, (route) => route.fulfill({ contentType: 'text/html', body: fixture }));
    await tab.goto(address);
    await tab.getByText(new RegExp(`^Zekvar · BLOCK v${baseline.version}`)).waitFor();
    return { tab, editor: tab.locator(selector), request: tab.getByRole('button', { name: 'Request policy review', exact: true }) };
  }
  const chat = await open('https://chatgpt.com/c/prompt-request-lab', './chatgpt-composer.html', '#prompt-textarea');
  const gemini = await open('https://gemini.google.com/app/prompt-request-lab', './gemini-composer.html', '.ql-editor');
  await chat.editor.fill(privateSample);
  await chat.editor.press('Enter');
  await chat.request.click();
  await chat.tab.getByText('Control could not confirm the request. Try again.', { exact: true }).waitFor();
  await chat.request.click();
  await chat.tab.getByText('Review requested. The current policy still applies.', { exact: true }).waitFor();
  assert.equal(await chat.tab.locator('#fixture-sends').textContent(), '0');
  assert.equal(recorded.length, 2);
  assert.deepEqual(recorded[0], recorded[1]);
  const [pending] = await admin('prompt-exception-requests');
  assert.equal(pending.eventId, recorded[0].eventId);
  assert.equal(pending.groupId, group.id);
  assert.deepEqual(Object.keys(recorded[0]).sort(), ['appId', 'eventId']);
  assert.equal((await admin(`policy-groups/${group.id}/policies`)).length, 0);

  const dashboard = await profile.newPage();
  await dashboard.goto(web);
  await dashboard.getByLabel('Control token').fill(owner);
  await dashboard.getByRole('button', { name: 'Sign in', exact: true }).click();
  const inbox = dashboard.getByRole('link', { name: 'Prompt exception requests', exact: true });
  await inbox.click();
  const requester = dashboard.getByRole('table', { name: 'Pending requests', exact: true }).getByRole('row', { name: /ChatGPT · Test marker/ });
  await requester.getByText(new RegExp(group.name)).waitFor();
  const desktop = dashboard.viewportSize();
  await dashboard.setViewportSize({ width: 390, height: 844 });
  await dashboard.waitForFunction(() => window.innerWidth === 390);
  assert.ok(await dashboard.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth));
  if (desktop) await dashboard.setViewportSize(desktop);
  if (artifacts) await dashboard.screenshot({ path: join(artifacts, 'prompt-exception-inbox.png') });
  dashboard.once('dialog', (dialog) => dialog.accept());
  await requester.getByRole('button', { name: 'Record published exception' }).click();
  await dashboard.getByRole('alert').filter({ hasText: 'Publish a matching active exception' }).waitFor();
  await requester.getByRole('link', { name: 'Open scoped policy preview' }).click();
  assert.equal(new URL(dashboard.url()).searchParams.get('group'), group.id);
  await dashboard.getByRole('button', { name: 'Add prompt exception' }).click();
  await dashboard.getByLabel('Expires (UTC)').fill(new Date(Date.now() + 600_000).toISOString().slice(0, -1));
  await dashboard.getByLabel('Reason', { exact: true }).fill('Reviewed synthetic workflow');
  await dashboard.getByRole('button', { name: 'Run preview', exact: true }).click();
  dashboard.once('dialog', (dialog) => dialog.accept());
  await dashboard.getByRole('button', { name: 'Publish previewed policy', exact: true }).click();
  await dashboard.getByText(/Previewed policy published as version/).waitFor();
  const [effective] = await admin(`policy-groups/${group.id}/policies`);
  assert.equal(effective.promptExceptions[0].appId, 'chatgpt');
  await inbox.click();
  dashboard.once('dialog', (dialog) => dialog.accept());
  await requester.getByRole('button', { name: 'Record published exception' }).click();
  await dashboard.getByText('No pending prompt exception requests.', { exact: true }).waitFor();
  await dashboard.getByRole('link', { name: 'Decided', exact: true }).click();
  await dashboard.getByRole('table', { name: 'Decided requests', exact: true }).getByText('Exception published', { exact: true }).waitFor();

  await popup.getByRole('button', { name: 'Sync now', exact: true }).click();
  await chat.tab.getByText(new RegExp(`^Zekvar · BLOCK v${effective.version}`)).waitFor();
  await chat.editor.press('Enter');
  assert.equal(await chat.tab.locator('#fixture-sends').textContent(), '1');
  await chat.tab.getByText('Temporary policy exception applied.', { exact: true }).waitFor();
  await gemini.tab.getByText(new RegExp(`^Zekvar · BLOCK v${effective.version}`)).waitFor();
  await gemini.editor.fill(privateSample);
  await gemini.editor.press('Enter');
  await gemini.request.click();
  await gemini.tab.getByText('Review requested. The current policy still applies.', { exact: true }).waitFor();
  await dashboard.getByRole('link', { name: 'Pending', exact: true }).click();
  dashboard.once('dialog', (dialog) => dialog.accept());
  await dashboard.getByRole('button', { name: 'Decline request', exact: true }).click();
  await dashboard.getByText('No pending prompt exception requests.', { exact: true }).waitFor();
  await gemini.editor.press('Enter');
  await gemini.request.click();
  await gemini.tab.getByText('An administrator declined this request.', { exact: true }).waitFor();
  assert.equal(await gemini.tab.locator('#fixture-sends').textContent(), '0');
  const decided = await admin('prompt-exception-requests?status=decided');
  assert.equal(decided.length, 2);

  const warning = await admin(`policy-groups/${group.id}/policies`, { mode: 'warn', promptExceptions: [] });
  await popup.getByRole('button', { name: 'Sync now', exact: true }).click();
  await gemini.tab.getByText(new RegExp(`^Zekvar · WARN v${warning.version}`)).waitFor();
  await gemini.editor.press('Enter');
  await gemini.request.click();
  await gemini.tab.getByText('Review requested. The current policy still applies.', { exact: true }).waitFor();
  assert.equal(await gemini.tab.locator('#fixture-sends').textContent(), '0');
  const queued = await admin('prompt-exception-requests');
  assert.equal(queued.length, 1);
  assert.equal(queued[0].decision, 'warn');
  assert.equal(queued[0].policyVersion, warning.version);
  await gemini.tab.getByRole('button', { name: 'Continue anyway', exact: true }).click();
  assert.equal(await gemini.tab.locator('#fixture-sends').textContent(), '1');
  assert.ok(!JSON.stringify({ recorded, decided, queued }).includes(privateSample));
  assert.ok(!recorded.some((post) => Object.keys(post).length !== 2));
});
