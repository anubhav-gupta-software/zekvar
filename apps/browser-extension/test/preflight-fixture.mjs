import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { once } from 'node:events';
import { readFile, writeFile } from 'node:fs/promises';
import { createServer } from 'node:https';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { chromium } from 'playwright';

const exec = promisify(execFile);
const preflight = fileURLToPath(new URL('../../../deploy/pilot/preflight.mjs', import.meta.url));
const packer = fileURLToPath(new URL('../package-pilot.mjs', import.meta.url));

export async function preparePreflight(t, { scratch, key, cert, ca, dashboardOrigin, browserOrigin, httpPort, updatesHost }) {
  const channel = 'pilot';
  const seen = [];
  const files = new Map();
  const updater = createServer({ key: await readFile(key), cert: await readFile(cert) }, (request, response) => {
    seen.push({ method: request.method, authorization: request.headers.authorization, cookie: request.headers.cookie });
    const file = files.get(request.url);
    response.writeHead(file?.status ?? (file ? 200 : 404), file?.headers ?? {});
    response.end(file?.body);
  }).listen(0, '127.0.0.1');
  t.after(() => new Promise((done) => updater.close(done)));
  await once(updater, 'listening');
  const updatesOrigin = `https://${updatesHost}:${updater.address().port}`;

  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' } });
  const signingKey = join(scratch, 'test-signing.pem');
  await writeFile(signingKey, privateKey, { mode: 0o600 });
  const releaseDir = join(scratch, 'trusted-release');
  const pack = (args) => exec(process.execPath, [packer, '--key', signingKey, ...args], { timeout: 45_000 });
  const { stdout: identity } = await pack(['--print-id']);
  const extensionId = identity.trim();
  await pack(['--id', extensionId, '--chrome', chromium.executablePath(), '--control-origin', browserOrigin,
    '--update-origin', updatesOrigin, '--channel', channel, '--first', '--output', releaseDir]);
  const receiptPath = join(releaseDir, 'release.json');
  const record = await readFile(receiptPath, 'utf8');
  const release = JSON.parse(record);
  const manifestUrl = new URL(release.updateUrl);
  const crxUrl = new URL(release.packageUrl);
  const manifestPath = join(releaseDir, 'public', manifestUrl.pathname);
  const xml = { headers: { 'Content-Type': 'application/xml; charset=UTF-8', 'Cache-Control': 'no-cache' }, body: await readFile(manifestPath) };
  const crx = { headers: { 'Content-Type': 'application/x-chrome-extension' }, body: await readFile(join(releaseDir, 'public', crxUrl.pathname)) };
  files.set(manifestUrl.pathname, xml);
  files.set(crxUrl.pathname, crx);

  const hosts = [new URL(dashboardOrigin).hostname, new URL(browserOrigin).hostname, updatesHost];
  const resolver = join(scratch, 'preflight-dns.cjs');
  await writeFile(resolver, `
    const dns = require('node:dns');
    const lookup = dns.lookup;
    const hosts = new Set(${JSON.stringify(hosts)});
    dns.lookup = (host, ...args) => lookup(hosts.has(host) ? '127.0.0.1' : host, ...args);
  `);
  async function invoke(network, { trusted = true, args = [] } = {}) {
    return exec(process.execPath, ['--require', resolver, preflight, '--dashboard', dashboardOrigin, '--browser', browserOrigin,
      '--admin-network', network, '--release-dir', releaseDir, '--http-port', String(httpPort), ...args], {
      env: { ...process.env, NODE_EXTRA_CA_CERTS: trusted ? ca : '', NODE_TLS_REJECT_UNAUTHORIZED: trusted ? '1' : '0' }, timeout: 18_000,
    }).then(({ stdout }) => ({ status: 0, stdout }), (error) => {
      assert.equal(error.code, 1, error.message);
      return { status: 1, stdout: error.stdout, stderr: error.stderr };
    });
  }

  async function verify(network) {
    const result = await invoke(network);
    assert.equal(result.status, 0, result.stdout || result.stderr);
    const evidence = JSON.parse(result.stdout);
    assert.equal(evidence.passed, true);
    assert.equal(evidence.adminNetwork, network);
    assert.equal(evidence.release.extensionId, extensionId);
    assert.equal(evidence.release.version, release.version);
    assert.equal(evidence.release.sha256, release.sha256);
    assert.ok(evidence.checks.length >= 12 && evidence.checks.every(({ passed }) => passed));
    assert.deepEqual(seen.slice(-2), Array(2).fill({ method: 'GET', authorization: undefined, cookie: undefined }));
    return evidence;
  }

  async function failures() {
    const wrongNetwork = await invoke('denied');
    assert.equal(wrongNetwork.status, 1);
    assert.deepEqual(JSON.parse(wrongNetwork.stdout).checks.filter(({ passed }) => !passed).map(({ name }) => name),
      ['Event feed requires a trusted network and key', 'Dashboard denies this network', 'Report download denies this network']);

    const untrusted = await invoke('allowed', { trusted: false });
    assert.equal(untrusted.status, 1);
    const checks = JSON.parse(untrusted.stdout).checks;
    assert.equal(checks.filter(({ passed }) => passed).length, 2);
    assert.ok(checks.filter(({ passed }) => !passed).every(({ detail }) => /Network or TLS failure/.test(detail)));

    files.set(manifestUrl.pathname, { ...xml, body: Buffer.from(xml.body.toString().replace(`version="${release.version}"`, 'version="0.1.0"')) });
    files.set(crxUrl.pathname, { ...crx, body: Buffer.concat([crx.body, Buffer.from([0x00])]) });
    const wrongContent = await invoke('allowed');
    assert.equal(wrongContent.status, 1);
    const difference = JSON.parse(wrongContent.stdout).checks.filter(({ passed }) => !passed);
    assert.equal(difference.length, 2);
    assert.match(difference[0].detail, /manifest differs/);
    assert.match(difference[1].detail, /SHA-256 differs/);

    files.set(manifestUrl.pathname, { ...xml, headers: { ...xml.headers, 'Cache-Control': 'public, max-age=86400' } });
    files.set(crxUrl.pathname, { status: 302, headers: { Location: manifestUrl.href }, body: '' });
    const distribution = await invoke('allowed');
    assert.equal(distribution.status, 1);
    const delivery = JSON.parse(distribution.stdout).checks.filter(({ passed }) => !passed);
    assert.equal(delivery.length, 2);
    assert.match(delivery[0].detail, /must revalidate/);
    assert.match(delivery[1].detail, /received 302/);

    files.set(manifestUrl.pathname, { ...xml, body: Buffer.alloc(65 * 1024, 0x41) });
    files.set(crxUrl.pathname, { ...crx, headers: { 'Content-Type': 'text/plain' } });
    const invalid = await invoke('allowed');
    assert.equal(invalid.status, 1);
    const formats = JSON.parse(invalid.stdout).checks.filter(({ passed }) => !passed);
    assert.match(formats[0].detail, /size limit/);
    assert.match(formats[1].detail, /must use application\/x-chrome-extension/);

    files.set(manifestUrl.pathname, xml);
    files.set(crxUrl.pathname, crx);
    const before = seen.length;
    const credential = 'synthetic-url-credential';
    const unauthorizedInput = await invoke('allowed', {
      args: ['--dashboard', dashboardOrigin.replace('https://', `https://${credential}@`)],
    });
    assert.equal(unauthorizedInput.status, 1);
    assert.match(unauthorizedInput.stderr, /without a path, query, or credentials/);
    assert.ok(!`${unauthorizedInput.stdout}${unauthorizedInput.stderr}`.includes(credential));
    await writeFile(receiptPath, JSON.stringify({ ...release, controlOrigin: updatesOrigin }));
    const wrongReceipt = await invoke('allowed');
    assert.equal(wrongReceipt.status, 1);
    assert.match(wrongReceipt.stderr, /different browser API origin/);
    await writeFile(receiptPath, record);
    await writeFile(manifestPath, xml.body.toString().replace(`appid="${extensionId}"`, `appid="${'p'.repeat(32)}"`));
    const wrongManifest = await invoke('allowed');
    assert.equal(wrongManifest.status, 1);
    assert.match(wrongManifest.stderr, /trusted update manifest does not match/);
    assert.equal(seen.length, before);
    await writeFile(manifestPath, xml.body);
    return verify('allowed');
  }
  return { verify, failures };
}
