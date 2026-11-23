import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
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

async function admin(path, body, expected = 200) {
  const response = await fetch(`${api}/v1/admin/${path}`, {
    method: body ? 'POST' : 'GET',
    headers: { Authorization: `Bearer ${owner}`, 'Content-Type': 'application/json' },
    body: body && JSON.stringify(body), signal: AbortSignal.timeout(5_000),
  });
  assert.equal(response.status, expected, path);
  return expected === 204 ? undefined : response.json();
}

async function until(check, message) {
  for (let attempt = 0; attempt < 40; attempt++) {
    const result = await check();
    if (result) return result;
    await delay(125);
  }
  assert.fail(message);
}

async function listen(server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return server.address().port;
}

test('publishes AI app access in Control and enforces scoped navigation in Chrome', { timeout: 50_000 }, async (t) => {
  const scratch = await mkdtemp(join(tmpdir(), 'zekvar-ai-access-browser-'));
  const customHost = 'workspace.access.test';
  const traffic = [];
  const wire = [];
  let offline = false;
  let invalidPolicy = false;
  let browser;
  const key = join(scratch, 'site.key');
  const cert = join(scratch, 'site.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=Zekvar AI access fixture',
    '-keyout', key, '-out', cert], { stdio: 'ignore' });
  const tls = await readFile(cert);
  const pin = createHash('sha256').update(new X509Certificate(tls).publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
  const destination = (request, response) => {
    const address = new URL(request.url, `http://${request.headers.host}`);
    traffic.push({ host: address.hostname, path: address.pathname, query: address.search });
    if (address.hostname === 'redirect.access.test') {
      address.hostname = customHost;
      response.writeHead(302, { Location: address.href }).end();
      return;
    }
    response.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-store' }).end('<h1>AI navigation fixture</h1>');
  };
  const http = createServer(destination);
  const https = createHttpsServer({ cert: tls, key: await readFile(key) }, destination);
  const proxy = createServer(async (request, response) => {
    try {
      if (offline) return response.writeHead(503).end();
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      wire.push(body.toString());
      const headers = Object.fromEntries(Object.entries(request.headers).filter(([name]) =>
        name === 'content-type' || name === 'authorization' || name.startsWith('x-zekvar-')));
      const upstream = await fetch(api + request.url, { method: request.method, headers,
        body: body.length ? body : undefined, signal: AbortSignal.timeout(4_000) });
      let output = await upstream.text();
      if (invalidPolicy && request.url === '/v1/browser/policy' && upstream.ok) {
        output = JSON.stringify({ ...JSON.parse(output), blockedAiAppHosts: ['https://invalid.access.test/'] });
      }
      response.writeHead(upstream.status, { 'Content-Type': 'application/json' }).end(output);
    } catch {
      response.writeHead(502).end();
    }
  });
  const [httpPort, httpsPort, controlPort] = await Promise.all([listen(http), listen(https), listen(proxy)]);
  t.after(async () => {
    await browser?.close();
    await Promise.all([http, https, proxy].map((server) => new Promise((resolve) => {
      server.close(resolve);
      server.closeAllConnections();
    })));
    await rm(scratch, { recursive: true, force: true });
  });
  const dist = join(scratch, 'extension');
  execFileSync(process.execPath, ['build.mjs'], { cwd: fileURLToPath(new URL('..', import.meta.url)),
    env: { ...process.env, ZEKVAR_CONTROL_PORT: String(controlPort), ZEKVAR_EXTENSION_OUTDIR: dist } });
  browser = await chromium.launchPersistentContext(join(scratch, 'profile'), {
    channel: 'chromium', headless: process.env.ZEKVAR_DEMO_HEADED !== '1', viewport: { width: 1440, height: 960 },
    args: [`--load-extension=${dist}`, `--disable-extensions-except=${dist}`, '--no-proxy-server',
      `--ignore-certificate-errors-spki-list=${pin}`,
      '--host-resolver-rules=MAP *.access.test 127.0.0.1, MAP *.access.test. 127.0.0.1, MAP chatgpt.com 127.0.0.1, MAP grok.com 127.0.0.1, MAP claude.ai 127.0.0.1, MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1'],
  });
  browser.setDefaultTimeout(7_000);
  const worker = browser.serviceWorkers()[0] ?? await browser.waitForEvent('serviceworker');
  const [popup, dashboard] = await Promise.all([browser.newPage(), browser.newPage()]);
  await popup.goto(new URL('popup.html', worker.url()).href);
  const sync = () => popup.getByRole('button', { name: 'Sync now', exact: true }).click();
  const badge = (text) => popup.getByText(text, { exact: true });
  const baseline = await admin('policies', {
    pathRules: { allow: [`${customHost}/allowed`], block: [] }, domainRules: { allow: [customHost], block: [] },
    customApps: [{ host: customHost, name: 'Workspace fixture' }],
  });
  const group = await admin('policy-groups', { name: 'AI access canary' });
  const groupPath = `policy-groups/${group.id}/policies`;
  const { grant } = await admin('enrollment-grants', {});
  await popup.getByLabel('Enrollment grant').fill(grant);
  await popup.getByRole('button', { name: 'Enroll this browser', exact: true }).click();
  await badge(`Connected to Control · MONITOR v${baseline.version}`).waitFor();
  const [{ installationId }] = await admin('installations');
  const applied = async (version) => (await admin('installations')).find((row) =>
    row.installationId === installationId && row.appliedPolicyVersion === version);
  await admin(`installations/${installationId}/policy-group`, { groupId: group.id }, 204);
  await sync();
  await until(() => applied(baseline.version), 'The browser did not acknowledge the inherited policy.');

  const secret = 'private-navigation-sample';
  async function visit(host, blocked, path = '/allowed', secure = false) {
    const address = new URL(`${secure ? 'https' : 'http'}://${host}:${secure ? httpsPort : httpPort}${path}`);
    address.searchParams.set(secret, String(traffic.length));
    const start = traffic.length;
    const page = await browser.newPage();
    try {
      if (blocked) {
        await assert.rejects(page.goto(address.href), /ERR_BLOCKED_BY_CLIENT/);
        assert.ok(traffic.slice(start).every(({ host, query }) => query !== address.search || host === 'redirect.access.test'),
          'The blocked destination received a request.');
        if (host === 'redirect.access.test') assert.ok(traffic.slice(start).some((row) => row.host === host && row.query === address.search));
      } else {
        assert.equal((await page.goto(address.href)).status(), 200);
        await page.getByRole('heading', { name: 'AI navigation fixture' }).waitFor();
        assert.ok(traffic.slice(start).some(({ host, query }) => host === address.hostname && query === address.search));
      }
    } finally { await page.close(); }
  }
  await visit(customHost, false);
  await visit('chatgpt.com', false, '/before', true);

  await dashboard.goto(web);
  await dashboard.getByLabel('Control token').fill(owner);
  await dashboard.getByRole('button', { name: 'Sign in' }).click();
  await dashboard.getByRole('link', { name: 'Manage AI app access', exact: true }).click();
  await dashboard.getByLabel('Scope', { exact: true }).selectOption(group.id);
  await dashboard.getByRole('button', { name: 'Open scope', exact: true }).click();
  const checkHost = (host) => dashboard.getByRole('checkbox', { name: `Block ${host}`, exact: true });
  for (const host of [customHost, 'chatgpt.com', 'grok.com']) await checkHost(host).check();
  await dashboard.getByLabel('Custom navigation URL').fill(`http://${customHost}/allowed`);
  const run = dashboard.getByRole('button', { name: 'Run preview', exact: true });
  await run.click();
  await dashboard.getByRole('row', { name: /Custom navigation.*Allow.*Block/ }).getByText(`AI app access · ${customHost}`, { exact: true }).waitFor();
  await dashboard.getByLabel('Custom app catalog').fill('');
  await run.click();
  await dashboard.getByRole('alert').getByText(/Keep each blocked AI app/).waitFor();
  assert.equal(await dashboard.getByRole('button', { name: 'Publish previewed policy' }).count(), 0);
  await dashboard.getByLabel('Custom app catalog').fill(`${customHost}, Workspace fixture`);
  await run.click();
  if (process.env.ZEKVAR_TEST_AI_ACCESS_SCREENSHOT) {
    await dashboard.locator('#draft-ai-app-access').screenshot({ path: process.env.ZEKVAR_TEST_AI_ACCESS_SCREENSHOT });
  }
  await dashboard.setViewportSize({ width: 390, height: 820 });
  assert.ok(await dashboard.evaluate(() => document.documentElement.scrollWidth === document.documentElement.clientWidth));
  await dashboard.setViewportSize({ width: 1440, height: 960 });
  dashboard.once('dialog', (dialog) => dialog.accept());
  await dashboard.getByRole('button', { name: 'Publish previewed policy', exact: true }).click();
  await dashboard.getByRole('status').getByText(/Previewed policy published/).waitFor();
  const [scoped] = await admin(groupPath);
  assert.deepEqual(scoped.blockedAiAppHosts, ['chatgpt.com', 'grok.com', customHost]);
  assert.deepEqual((await admin('policies'))[0].blockedAiAppHosts, []);
  await sync();
  await badge('Blocked AI app hosts: 3').waitFor();
  await until(() => applied(scoped.version), 'Control did not observe the applied AI access policy.');
  await visit(customHost, true);
  await visit(`${customHost}.`, true);
  await visit('redirect.access.test', true);
  await visit(`dev.${customHost}`, false);
  await visit(`${customHost}.other.access.test`, false);
  await visit('chatgpt.com', true, '/protected', true);
  await visit('grok.com', true, '/protected', true);
  await visit('claude.ai', false, '/unlisted', true);

  await admin(`installations/${installationId}/policy-group`, { groupId: null }, 204);
  await sync();
  await until(() => applied(baseline.version), 'Moving the browser to the baseline did not clear the group rule.');
  await visit(customHost, false);
  await admin(`installations/${installationId}/policy-group`, { groupId: group.id }, 204);
  await sync();
  await until(() => applied(scoped.version), 'Returning the browser to the group did not restore the group rule.');
  await visit(customHost, true);

  offline = true;
  await sync();
  await badge(`Control offline · MONITOR v${scoped.version}`).waitFor();
  await visit(customHost, true);
  offline = false;
  const restored = await admin(groupPath, { blockedAiAppHosts: [], expectedVersion: scoped.version });
  invalidPolicy = true;
  await sync();
  await badge(`Control offline · MONITOR v${scoped.version}`).waitFor();
  assert.equal(await applied(restored.version), undefined);
  await visit(customHost, true);
  invalidPolicy = false;
  await sync();
  await badge(`Connected to Control · MONITOR v${restored.version}`).waitFor();
  await until(() => applied(restored.version), 'Control did not observe the reverted access policy.');
  await visit(customHost, false);
  await visit('chatgpt.com', false, '/restored', true);

  const restoredBlock = await admin(`${groupPath}/${scoped.version}/restore`, {});
  const spareRules = Array.from({ length: 45 }, (_, index) => `extra-${index}.access.test`);
  const blockedAgain = await admin(groupPath, {
    expectedVersion: restoredBlock.version, domainRules: { allow: [customHost, ...spareRules], block: [] },
  });
  await sync();
  await badge(`Connected to Control · MONITOR v${blockedAgain.version}`).waitFor();
  assert.equal(await worker.evaluate(async () => (await chrome.declarativeNetRequest.getDynamicRules()).length), 50);
  await visit(customHost, true);
  await admin(`installations/${installationId}/revoke`, {}, 204);
  await sync();
  await badge(/Control access revoked/).waitFor();
  await visit(customHost, false);
  assert.equal(await worker.evaluate(async () => (await chrome.declarativeNetRequest.getDynamicRules()).length), 0);
  assert.equal((await admin('events')).length, 0);
  assert.equal(wire.some((body) => body.includes(secret)), false);
});
