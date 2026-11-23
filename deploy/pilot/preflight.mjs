import { createHash } from 'node:crypto';
import { open } from 'node:fs/promises';
import { get as httpGet } from 'node:http';
import { get as httpsGet } from 'node:https';
import { join } from 'node:path';
import { parseArgs } from 'node:util';

const timeout = 15_000;
const manifestLimit = 64 * 1024;
const packageLimit = 64 * 1024 * 1024;
const redirectStatuses = new Set([301, 302, 307, 308]);

class CheckFailure extends Error {}

function expect(condition, message) {
  if (!condition) throw new CheckFailure(message);
}

function origin(value, label) {
  expect(typeof value === 'string' && /^https:\/\/[a-z\d.-]+(?::[1-9]\d{0,4})?\/?$/i.test(value),
    `Use an HTTPS origin without a path, query, or credentials for ${label}.`);
  const url = URL.parse(value);
  expect(url && !url.hostname.endsWith('.'), `Use a valid canonical hostname for ${label}.`);
  return url.origin;
}

function chromeVersion(version) {
  return typeof version === 'string' && /^(?:0|[1-9]\d{0,4})(?:\.(?:0|[1-9]\d{0,4})){0,3}$/.test(version) &&
    version.split('.').every((part) => Number(part) <= 65535) && version.split('.').some((part) => Number(part) > 0);
}

async function boundedFile(path) {
  const file = await open(path, 'r');
  try {
    const info = await file.stat();
    expect(info.isFile() && info.size > 0 && info.size <= manifestLimit, 'Release input must be a nonempty regular file of at most 64 KiB.');
    const result = Buffer.alloc(manifestLimit + 1);
    let offset = 0;
    while (offset < result.length) {
      const { bytesRead } = await file.read(result, offset, result.length - offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    expect(offset > 0 && offset <= manifestLimit, 'Release input must contain at most 64 KiB.');
    return result.subarray(0, offset);
  } finally {
    await file.close();
  }
}

function json(bytes, error) {
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new CheckFailure(error);
  }
}

async function releaseInputs(directory, browserOrigin) {
  const release = json(await boundedFile(join(directory, 'release.json')), 'The trusted release record is invalid JSON.');
  const { extensionId, version, channel, controlOrigin, updateUrl, packageUrl, sha256 } = release ?? {};
  expect(typeof extensionId === 'string' && /^[a-p]{32}$/.test(extensionId) && chromeVersion(version) &&
    typeof channel === 'string' && /^[a-z0-9][a-z0-9-]{0,39}$/.test(channel) && typeof sha256 === 'string' && /^[a-f0-9]{64}$/.test(sha256),
    'The trusted release record has an invalid ID, version, channel, or checksum.');
  expect(controlOrigin === browserOrigin, 'The release belongs to a different browser API origin.');
  const updateOrigin = origin(URL.parse(updateUrl ?? '')?.origin, 'the update host');
  expect(updateUrl === `${updateOrigin}/${channel}/updates.xml` &&
    packageUrl === `${updateOrigin}/${channel}/zekvar-browser-${version}.crx`, 'The release URLs do not match the signed channel.');

  const xml = await boundedFile(join(directory, 'public', channel, 'updates.xml'));
  const entries = xml.toString('utf8').match(/^<\?xml version="1\.0" encoding="UTF-8"\?>\s*<gupdate xmlns="http:\/\/www\.google\.com\/update2\/response" protocol="2\.0">\s*<app appid="([a-p]{32})">\s*<updatecheck codebase="([^"]+)" version="([^"]+)" prodversionmin="([^"]+)"\s*\/>\s*<\/app>\s*<\/gupdate>\s*$/);
  expect(entries?.[1] === extensionId && entries[2] === packageUrl && entries[3] === version && chromeVersion(entries[4]),
    'The trusted update manifest does not match the release record.');
  return { extensionId, version, channel, updateUrl, packageUrl, sha256, xml };
}

async function request(address, inspect) {
  const url = new URL(address);
  const get = url.protocol === 'https:' ? httpsGet : httpGet;
  const response = await new Promise((resolve, reject) => {
    get(url, { agent: false, rejectUnauthorized: true, signal: AbortSignal.timeout(timeout) }, resolve).once('error', reject);
  });
  try {
    await inspect(response);
  } finally {
    response.destroy();
  }
}

async function readLimited(response, limit, useChunk) {
  let bytes = 0;
  for await (const chunk of response) {
    bytes += chunk.length;
    expect(bytes <= limit, 'Response exceeded the size limit.');
    useChunk(chunk);
  }
  expect(bytes > 0 && response.complete, 'Response body was empty or incomplete.');
}

async function body(response, limit) {
  const parts = [];
  await readLimited(response, limit, (chunk) => parts.push(chunk));
  return Buffer.concat(parts);
}

function directives(response) {
  return new Set((response.headers['cache-control'] ?? '').toLowerCase().split(',').map((part) => part.trim()));
}

function contentType(response) {
  return response.headers['content-type']?.split(';')[0].trim().toLowerCase();
}

function edgeResponse(check, host, path, status, inspect = () => {}) {
  return [check, () => request(host + path, async (response) => {
    expect(response.statusCode === status, `Expected HTTP ${status}, received ${response.statusCode}.`);
    expect(directives(response).has('no-store'), 'Missing Cache-Control no-store.');
    const maxAge = /(?:^|;)\s*max-age=(\d+)\s*(?:;|$)/i.exec(response.headers['strict-transport-security'] ?? '');
    expect(Number(maxAge?.[1]) > 0, 'Missing an active Strict-Transport-Security header.');
    await inspect(response);
  })];
}

function requireRedirect(response, from, to) {
  expect(typeof response.headers.location === 'string' && URL.parse(response.headers.location, from)?.href === to,
    'Redirect points to an unexpected destination.');
}

function httpRedirect(check, host, path, httpPort) {
  const cleartext = new URL(host);
  cleartext.protocol = 'http:';
  cleartext.port = httpPort;
  const from = new URL(path, cleartext).href;
  return [check, () => request(from, (response) => {
    expect(redirectStatuses.has(response.statusCode), `Expected a redirect to HTTPS, received HTTP ${response.statusCode}.`);
    requireRedirect(response, from, host + path);
  })];
}

function deploymentChecks(dashboard, browser, access, httpPort) {
  const checks = [
    httpRedirect('Dashboard HTTP redirect', dashboard, '/', httpPort),
    httpRedirect('Browser API HTTP redirect', browser, '/health', httpPort),
    edgeResponse('Browser API readiness', browser, '/health', 200, async (response) => {
      expect(contentType(response) === 'application/json', 'Readiness response did not use application/json.');
      expect(json(await body(response, 4096), 'Readiness response was not valid JSON.')?.status === 'ready', 'Browser API is unavailable.');
    }),
    edgeResponse('Browser policy requires enrollment', browser, '/v1/browser/policy', 401),
    edgeResponse('Dashboard origin excludes browser API', dashboard, '/v1/browser/policy', 404),
    edgeResponse('Browser origin excludes dashboard', browser, '/reports/export', 404),
    edgeResponse('Browser origin excludes event feed', browser, '/v1/integrations/events', 404),
    edgeResponse('Event feed requires a trusted network and key', dashboard, '/v1/integrations/events', access === 'allowed' ? 401 : 404),
  ];
  for (const [label, host] of [['Dashboard origin', dashboard], ['Browser origin', browser]]) {
    checks.push(edgeResponse(`${label} excludes administrative API`, host, '/v1/admin/session', 404));
  }
  if (access === 'allowed') {
    checks.push(edgeResponse('Dashboard sign-in', dashboard, '/', 200, async (response) => {
      expect(contentType(response) === 'text/html' && (await body(response, 1024 * 1024)).includes('Sign in to Control'),
        'Response was not the Control sign-in page.');
    }));
    checks.push(edgeResponse('Dashboard requires a session', dashboard, '/reports', 307,
      (response) => requireRedirect(response, dashboard + '/reports', dashboard + '/')));
    checks.push(edgeResponse('Report download requires a session', dashboard, '/reports/export', 401));
  } else {
    checks.push(edgeResponse('Dashboard denies this network', dashboard, '/', 403));
    checks.push(edgeResponse('Report download denies this network', dashboard, '/reports/export', 403));
  }
  return checks;
}

function distributionChecks(release) {
  return [
    ['Public update manifest', () => request(release.updateUrl, async (response) => {
      expect(response.statusCode === 200, `Expected HTTP 200, received ${response.statusCode}.`);
      expect(contentType(response) === 'application/xml', 'Update manifest must use application/xml.');
      const cache = directives(response);
      expect(cache.has('no-cache') || cache.has('no-store') || (cache.has('max-age=0') && cache.has('must-revalidate')),
        'Update manifest must revalidate on each request.');
      expect((await body(response, manifestLimit)).equals(release.xml), 'Public update manifest differs from the trusted release.');
    })],
    ['Public signed package', () => request(release.packageUrl, async (response) => {
      expect(response.statusCode === 200, `Expected HTTP 200, received ${response.statusCode}.`);
      expect(contentType(response) === 'application/x-chrome-extension', 'Signed package must use application/x-chrome-extension.');
      const digest = createHash('sha256');
      await readLimited(response, packageLimit, (chunk) => digest.update(chunk));
      expect(digest.digest('hex') === release.sha256, 'Public package SHA-256 differs from the trusted release.');
    })],
  ];
}

async function run() {
  const { values } = parseArgs({ options: {
    dashboard: { type: 'string' }, browser: { type: 'string' }, 'admin-network': { type: 'string' },
    'release-dir': { type: 'string' }, 'http-port': { type: 'string', default: '80' }, help: { type: 'boolean' },
  } });
  if (values.help) {
    console.log('Usage: node deploy/pilot/preflight.mjs --dashboard HTTPS_ORIGIN --browser HTTPS_ORIGIN --admin-network allowed|denied --release-dir DIRECTORY [--http-port 80]');
    return;
  }
  const dashboard = origin(values.dashboard, '--dashboard');
  const browser = origin(values.browser, '--browser');
  const access = values['admin-network'];
  const httpPort = values['http-port'];
  expect(new URL(dashboard).hostname !== new URL(browser).hostname, 'Use distinct dashboard and browser API hostnames.');
  expect(access === 'allowed' || access === 'denied', 'Specify --admin-network allowed or denied for the network running the check.');
  expect(/^[1-9]\d{0,4}$/.test(httpPort) && Number(httpPort) <= 65535, 'Use a valid --http-port.');
  expect(values['release-dir'], 'Specify --release-dir with the trusted packager output.');
  const release = await releaseInputs(values['release-dir'], browser);

  const beganAt = new Date().toISOString();
  const checks = await Promise.all([...deploymentChecks(dashboard, browser, access, httpPort), ...distributionChecks(release)]
    .map(async ([name, verify]) => {
      try {
        await verify();
        return { name, passed: true };
      } catch (error) {
        const detail = error instanceof CheckFailure ? error.message : `Network or TLS failure (${error.code ?? error.name}).`;
        return { name, passed: false, detail };
      }
    }));
  const passed = checks.every((check) => check.passed);
  const { xml, ...verifiedRelease } = release;
  console.log(JSON.stringify({ beganAt, dashboard, browser, adminNetwork: access, release: verifiedRelease, passed, checks }, null, 2));
  if (!passed) process.exitCode = 1;
}

try {
  await run();
} catch (error) {
  console.error(error instanceof CheckFailure ? error.message : `Could not start the preflight (${error.code ?? error.name}). Use --help for usage.`);
  process.exitCode = 1;
}
