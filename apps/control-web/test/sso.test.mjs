import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash, randomBytes, X509Certificate } from 'node:crypto';
import { once } from 'node:events';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { request } from 'node:https';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from 'playwright';
import { startIdentityProvider } from './sso-provider.mjs';

const { ZEKVAR_SSO_TEST_API: apiDll, ZEKVAR_SSO_TEST_WEB: webDir, ZEKVAR_SSO_TEST_DATABASE: database,
  ZEKVAR_CADDY: caddy = 'caddy', ZEKVAR_DEMO_ARTIFACTS: artifacts, ZEKVAR_DEMO_HEADED: headed } = process.env;
const secret = () => randomBytes(32).toString('hex');
const cookieNames = { session: '__Host-zekvar_control_session', transaction: '__Host-zekvar_control_sso' };

async function port() {
  const net = createServer().listen(0, '127.0.0.1');
  await once(net, 'listening');
  const available = net.address().port;
  await new Promise((resolve) => net.close(resolve));
  return available;
}

async function until(check, message) {
  for (let attempt = 0; attempt < 90; attempt++) {
    const result = await check();
    if (result) return result;
    await delay(100);
  }
  assert.fail(message);
}

for (const organizationMode of [false, true]) test(
  `hosted Control verifies ${organizationMode ? 'organization-scoped' : 'single-provider legacy'} OpenID Connect sessions and roles`,
  { timeout: 130_000 }, async (t) => {
  assert.ok(apiDll && webDir && database, 'Use the SSO demo verifier to prepare the standalone stack');
  const work = await mkdtemp(join(tmpdir(), 'zekvar-sso-test-'));
  const [httpPort, tlsPort, apiPort, webPort] = await Promise.all([port(), port(), port(), port()]);
  const dashboardHost = 'control.zekvar.test';
  const browserHost = 'browser.zekvar.test';
  const dashboard = `https://${dashboardHost}:${tlsPort}`;
  const browserApi = `https://${browserHost}:${tlsPort}`;
  const loopback = `http://127.0.0.1:${apiPort}`;
  const callback = `${dashboard}/auth/sso/callback`;
  const [owner, otherOwner, clientSecret, bridge, secondOwner, secondClientSecret, secondBridge] = Array.from({ length: 7 }, secret);
  const clientId = 'zekvar-test-client';
  const suffix = secret().slice(0, 10);
  const slug = `sso-${suffix}`;
  const secondSlug = slug + '-second';
  const processes = [];
  let browser;
  let provider;
  let secondProvider;
  t.after(async () => {
    await browser?.close();
    await Promise.all(processes.map(stop));
    await provider?.close();
    await secondProvider?.close();
    await rm(work, { recursive: true, force: true });
  });

  const openssl = (...args) => execFileSync('openssl', args, { cwd: work, stdio: 'pipe' });
  openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=Zekvar SSO Fixture CA',
    '-keyout', 'ca.key', '-out', 'ca.pem');
  openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=' + dashboardHost, '-keyout', 'site.key', '-out', 'site.csr');
  await writeFile(join(work, 'ext.cnf'), `subjectAltName=DNS:${dashboardHost},DNS:${browserHost},IP:127.0.0.1\nextendedKeyUsage=serverAuth\n`);
  openssl('x509', '-req', '-in', 'site.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial',
    '-days', '2', '-extfile', 'ext.cnf', '-out', 'site.pem');
  const cert = join(work, 'site.pem');
  const key = join(work, 'site.key');
  const ca = join(work, 'ca.pem');
  const publicKey = new X509Certificate(await readFile(cert)).publicKey.export({ type: 'spki', format: 'der' });
  const pin = createHash('sha256').update(publicKey).digest('base64');
  const tls = { key: await readFile(key), cert: await readFile(cert) };
  provider = await startIdentityProvider(tls, clientId, clientSecret, organizationMode ? `${callback}/${slug}` : callback);
  if (organizationMode) secondProvider = await startIdentityProvider(tls, clientId + '-second', secondClientSecret, `${callback}/${secondSlug}`);

  function launch(program, args, cwd, overrides) {
    const child = spawn(program, args, { cwd, env: { ...process.env, ...overrides }, stdio: ['ignore', 'pipe', 'pipe'] });
    const done = once(child, 'close');
    const service = { child, done, output: '' };
    for (const stream of [child.stdout, child.stderr]) stream.on('data', (chunk) => { service.output = (service.output + chunk).slice(-2500); });
    processes.push(service);
    return service;
  }
  async function stop(process) {
    if (process.child.exitCode === null) process.child.kill('SIGTERM');
    await process.done;
  }
  function callEdge(url, method = 'GET') {
    return new Promise((resolve, reject) => {
      const call = request(url, { method, ca: trust, agent: false, timeout: 3000,
        lookup: (_host, options, done) => options.all ? done(null, [{ address: '127.0.0.1', family: 4 }]) : done(null, '127.0.0.1', 4),
      }, (response) => { response.resume(); resolve(response.statusCode); });
      call.on('error', reject);
      call.on('timeout', () => call.destroy(new Error('TLS fixture request timed out')));
      call.end();
    });
  }
  const trust = await readFile(ca);
  const configured = await readFile(new URL('../../../deploy/pilot/Caddyfile', import.meta.url), 'utf8');
  await writeFile(join(work, 'Caddyfile'), configured.replace('{\n', `{\n\tdefault_bind 127.0.0.1\n\thttp_port ${httpPort}\n\thttps_port ${tlsPort}\n`)
    .replaceAll(/(\{\$ZEKVAR_(?:DASHBOARD|BROWSER)_HOST\} \{)/g, `$1\n\ttls "${cert}" "${key}"`));
  const edge = launch(caddy, ['run', '--config', join(work, 'Caddyfile')], work, {
    XDG_DATA_HOME: join(work, 'data'), XDG_CONFIG_HOME: join(work, 'config'), ZEKVAR_ADMIN_NETWORKS: '127.0.0.1/32',
    ZEKVAR_DASHBOARD_HOST: dashboardHost, ZEKVAR_BROWSER_HOST: browserHost, ZEKVAR_ACME_EMAIL: 'fixture@example.test',
    ZEKVAR_API_PORT: String(apiPort), ZEKVAR_WEB_PORT: String(webPort),
  });
  const startApi = (exchangeToken, explicit = organizationMode) => launch('dotnet', [apiDll], work, {
    DOTNET_ENVIRONMENT: 'Production', ASPNETCORE_ENVIRONMENT: 'Production', Control__HostedPilot: 'true',
    Control__Port: String(apiPort), ConnectionStrings__Control: database,
    Control__Organizations__0__Slug: slug, Control__Organizations__0__AdminToken: owner,
    Control__Organizations__1__Slug: slug + '-other', Control__Organizations__1__AdminToken: otherOwner,
    ...(explicit ? {
      Control__OidcOrganizations__0__Issuer: provider.issuer, Control__OidcOrganizations__0__OrganizationSlug: slug,
      Control__OidcOrganizations__0__ExchangeToken: exchangeToken,
      ...(secondProvider && {
        Control__Organizations__2__Slug: secondSlug, Control__Organizations__2__AdminToken: secondOwner,
        Control__OidcOrganizations__1__Issuer: secondProvider.issuer, Control__OidcOrganizations__1__OrganizationSlug: secondSlug,
        Control__OidcOrganizations__1__ExchangeToken: secondBridge,
      }),
    } : { Control__Oidc__Issuer: provider.issuer, Control__Oidc__OrganizationSlug: slug, Control__Oidc__ExchangeToken: exchangeToken }),
  });
  const startWeb = (authMethod) => launch(process.execPath, ['server.js'], webDir, {
    HOSTNAME: '127.0.0.1', PORT: String(webPort), NODE_ENV: 'production', ZEKVAR_HOSTED_PILOT: '1',
    ZEKVAR_CONTROL_PORT: String(apiPort), NODE_EXTRA_CA_CERTS: ca, ZEKVAR_OIDC_DASHBOARD_ORIGIN: dashboard,
    ...(secondProvider ? { ZEKVAR_OIDC_ORGANIZATIONS: JSON.stringify([
      { organizationSlug: slug, issuer: provider.issuer, clientId, clientSecret, exchangeToken: bridge, authMethod },
      { organizationSlug: secondSlug, issuer: secondProvider.issuer, clientId: clientId + '-second',
        clientSecret: secondClientSecret, exchangeToken: secondBridge, authMethod: 'post' },
    ]) } : { ZEKVAR_OIDC_ISSUER: provider.issuer, ZEKVAR_OIDC_CLIENT_ID: clientId, ZEKVAR_OIDC_CLIENT_SECRET: clientSecret,
      ZEKVAR_OIDC_EXCHANGE_TOKEN: bridge, ZEKVAR_OIDC_CLIENT_AUTH: authMethod }),
  });
  const api = startApi(bridge);
  const web = startWeb('basic');
  await until(async () => await callEdge(dashboard).catch(() => false) === 200 &&
    await callEdge(`${browserApi}/health`).catch(() => false) === 200, 'The HTTPS SSO lab did not start.');
  for (const service of [edge, api, web]) assert.equal(service.child.exitCode, null, service.output);
  for (const origin of [dashboard, browserApi]) assert.equal(await callEdge(`${origin}/v1/internal/sso/session`, 'POST'), 404);
  assert.equal(await callEdge(`${browserApi}/auth/sso/start`), 404);

  async function call(path, token, body, status = 200, method = body === undefined ? 'GET' : 'POST') {
    const response = await fetch(`${loopback}/v1/${path}`, {
      method, headers: { Authorization: `Bearer ${token}`, ...(body && { 'Content-Type': 'application/json' }) },
      body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(5000),
    });
    assert.equal(response.status, status, path);
    if (status === 200) return response.json();
  }
  const exchange = (subject, token = bridge, status = 200, options = {}) => call('internal/sso/session', token,
    { subject, issuer: provider.issuer, organizationSlug: organizationMode ? slug : undefined,
      expiresAt: new Date(Date.now() + 8_000_000).toISOString(), ...options }, status);
  assert.deepEqual(await call('admin/access/sso', owner), { issuer: provider.issuer });
  await call('admin/access/sso', otherOwner, undefined, 204);
  await call('admin/access/sso', otherOwner, { name: 'Other tenant', role: 'administrator', subject: 'other' }, 404);
  await call('admin/access/sso', owner, { name: 'Owner request', role: 'owner', subject: 'owner' }, 400);
  await exchange('pilot-administrator', owner, 401);
  await exchange('pilot-administrator', bridge, 401);

  browser = await chromium.launch({ channel: 'chromium', headless: headed !== '1', args: ['--no-proxy-server',
    `--host-resolver-rules=MAP ${dashboardHost} 127.0.0.1, MAP ${browserHost} 127.0.0.1`, `--ignore-certificate-errors-spki-list=${pin}`] });
  async function page() {
    const context = await browser.newContext();
    context.setDefaultTimeout(9000);
    return context.newPage();
  }
  const provision = await page();
  await provision.goto(dashboard);
  await provision.getByLabel('Control token', { exact: true }).fill(owner);
  await provision.getByRole('button', { name: 'Sign in', exact: true }).click();
  await provision.getByRole('heading', { name: 'Security overview', exact: true }).waitFor();
  await provision.goto(`${dashboard}/access`);
  const table = provision.getByRole('table', { name: 'Delegated credentials' });
  async function add(name, subject, role, duplicate = false) {
    await provision.getByLabel('SSO name').fill(name);
    await provision.getByLabel('OIDC subject').fill(subject);
    await provision.getByLabel('SSO role').selectOption(role);
    await provision.getByRole('button', { name: 'Add SSO identity', exact: true }).click();
    if (duplicate) await provision.getByRole('alert').filter({ hasText: 'That identity already has Control access.' }).waitFor();
    else {
      try {
        await table.getByRole('row').filter({ hasText: name }).getByText('Until revoked', { exact: true }).waitFor();
      } catch (error) {
        throw new Error(`The identity was not listed. ${await provision.getByRole('alert').allTextContents()}\n${api.output}\n${web.output}`, { cause: error });
      }
    }
  }
  await add('Pilot administrator', 'pilot-administrator', 'administrator');
  await add('Pilot administrator', 'pilot-administrator', 'administrator', true);
  await add('Pilot reviewer', 'pilot-reviewer', 'administrator');
  await add('Pilot auditor', 'pilot-auditor', 'auditor');
  const provisioned = await call('admin/access', owner);
  assert.deepEqual(provisioned.map(({ subject }) => subject).sort(), ['pilot-administrator', 'pilot-auditor', 'pilot-reviewer']);
  assert.deepEqual(await call('admin/access', otherOwner), []);
  await exchange('pilot-administrator', bridge, 401, { issuer: provider.issuer + '/other' });
  await exchange('pilot-administrator', bridge, 401, { expiresAt: new Date(0).toISOString() });

  const login = await page();
  async function signIn(target, organization = slug) {
    if (organizationMode) await target.getByLabel('Organization slug').fill(organization);
    await target.getByRole(organizationMode ? 'button' : 'link', { name: 'Sign in with single sign-on', exact: true }).click();
  }
  const failed = (target) => target.getByRole('alert').filter({ hasText: 'Single sign-on could not complete' });
  async function begin(target, scenario, identityProvider = provider, organization = slug) {
    identityProvider.scenario = scenario;
    await target.goto(dashboard);
    await signIn(target, organization);
    await target.getByRole('heading', { name: 'Identity provider fixture' }).waitFor();
    const cookies = await target.context().cookies(dashboard);
    assert.ok(cookies.some((value) => value.name === cookieNames.transaction && value.httpOnly && value.secure && value.sameSite === 'Lax'));
    assert.deepEqual(await target.context().cookies(identityProvider.issuer), []);
    return identityProvider.attempts.at(-1);
  }
  const continueAtProvider = (target) => target.getByRole('link', { name: 'Continue as test account' }).click();
  async function finish(target, success) {
    await continueAtProvider(target);
    if (success) {
      try {
        await target.getByRole('heading', { name: 'Security overview', exact: true }).waitFor();
      } catch (error) {
        throw new Error(`Sign-in returned ${await target.title()} at ${new URL(target.url()).pathname}. IdP error: ${provider.error}\n${api.output}\n${web.output}`, { cause: error });
      }
    } else await failed(target).waitFor();
    return target.context().cookies(dashboard);
  }

  provider.discoveryUnavailable = true;
  await login.goto(dashboard);
  await signIn(login);
  await failed(login).waitFor();
  provider.discoveryUnavailable = false;
  const missingState = await begin(login, { subject: 'pilot-administrator' });
  const differentBrowser = await page();
  await differentBrowser.goto(missingState.redirect);
  await failed(differentBrowser).waitFor();
  await differentBrowser.context().close();
  for (const kind of ['wrong-state', 'duplicate-state', 'denied', 'wrong-nonce', 'wrong-audience', 'wrong-issuer', 'wrong-signature', 'expired']) {
    await begin(login, { subject: 'pilot-administrator', kind, ...(kind === 'expired' && { seconds: -35 }) });
    const cookies = await finish(login, false);
    assert.equal(cookies.some(({ name }) => name === cookieNames.session), false, kind);
  }
  await begin(login, { subject: 'not-on-the-access-list' });
  await finish(login, false);
  assert.deepEqual((await call('admin/audit?action=control_sso_signed_in', owner)).entries, []);

  if (secondProvider) await t.test('keeps organizations isolated through routing, token exchange, and account provisioning', async () => {
    const external = await page();
    await external.goto(dashboard);
    await signIn(external, 'unknown-organization');
    await failed(external).waitFor();
    await external.goto(`${dashboard}/auth/sso/start?organization=${slug}&organization=${secondSlug}`);
    await failed(external).waitFor();
    assert.equal(await callEdge(callback), 404);
    assert.equal(await callEdge(`${browserApi}/auth/sso/callback/${secondSlug}`), 404);
    assert.deepEqual(await call('admin/access/sso', secondOwner), { issuer: secondProvider.issuer });
    assert.deepEqual(await call('admin/access', secondOwner), []);

    const secondProvision = await page();
    await secondProvision.goto(dashboard);
    await secondProvision.getByLabel('Control token', { exact: true }).fill(secondOwner);
    await secondProvision.getByRole('button', { name: 'Sign in', exact: true }).click();
    await secondProvision.getByRole('heading', { name: 'Security overview', exact: true }).waitFor();
    await secondProvision.goto(`${dashboard}/access`);
    await secondProvision.getByLabel('SSO name').fill('Second tenant auditor');
    await secondProvision.getByLabel('OIDC subject').fill('pilot-administrator');
    await secondProvision.getByLabel('SSO role').selectOption('auditor');
    await secondProvision.getByRole('button', { name: 'Add SSO identity', exact: true }).click();
    await secondProvision.getByRole('row').filter({ hasText: 'Second tenant auditor' }).getByText('Until revoked', { exact: true }).waitFor();
    const [secondAccess] = await call('admin/access', secondOwner);
    assert.equal(secondAccess.issuer, secondProvider.issuer);
    assert.equal(secondAccess.subject, 'pilot-administrator');
    await call('admin/access/' + secondAccess.id + '/revoke', owner, {}, 404);
    await exchange('pilot-administrator', bridge, 401, { organizationSlug: undefined });
    await exchange('pilot-administrator', bridge, 401, { organizationSlug: secondSlug, issuer: secondProvider.issuer });
    await exchange('pilot-administrator', secondBridge, 401, { organizationSlug: secondSlug });

    const secondLogin = await page();
    const attempted = await begin(secondLogin, { subject: 'pilot-administrator' }, secondProvider, secondSlug);
    const wrongCallback = new URL(attempted.redirect);
    wrongCallback.pathname = `/auth/sso/callback/${slug}`;
    const before = [provider.tokenAttempts, secondProvider.tokenAttempts];
    await secondLogin.goto(wrongCallback.href);
    await failed(secondLogin).waitFor();
    assert.deepEqual([provider.tokenAttempts, secondProvider.tokenAttempts], before);
    assert.equal((await secondLogin.context().cookies(dashboard)).some(({ name }) => name === cookieNames.session), false);
    await secondLogin.goto(attempted.redirect);
    await secondLogin.getByText('Second tenant auditor · Auditor', { exact: true }).waitFor();
    assert.deepEqual([provider.tokenAttempts, secondProvider.tokenAttempts], [before[0], before[1] + 1]);
    assert.equal(secondProvider.lastAuth, 'post');
    assert.equal((await call('admin/audit?action=control_sso_signed_in', owner)).entries.length, 0);
    const secondAudit = (await call('admin/audit?action=control_sso_signed_in', secondOwner)).entries;
    assert.deepEqual(secondAudit.map(({ actorAccess }) => actorAccess.name), ['Second tenant auditor']);
    assert.doesNotMatch(JSON.stringify(secondAudit), /synthetic-idp-claim|opaque-fixture-provider-token|pilot-administrator/);
    if (artifacts) {
      await mkdir(artifacts, { recursive: true });
      await external.goto(dashboard);
      await external.locator('.auth-card').screenshot({ path: join(artifacts, 'organization-sso-sign-in.png') });
    }
    await Promise.all([external, secondProvision, secondLogin].map((target) => target.context().close()));
  });

  const first = await begin(login, { subject: 'pilot-administrator', seconds: 75 });
  const cookies = await finish(login, true);
  assert.equal(provider.lastAuth, 'basic');
  const sessionCookie = cookies.find(({ name }) => name === cookieNames.session);
  assert.ok(sessionCookie?.secure && sessionCookie.httpOnly && sessionCookie.sameSite === 'Strict' && sessionCookie.path === '/');
  assert.ok(sessionCookie.expires <= Math.floor(Date.now() / 1000) + 75);
  assert.equal(cookies.some(({ name }) => name === cookieNames.transaction), false);
  assert.deepEqual(await login.context().cookies(browserApi), []);
  await login.getByText('Pilot administrator · Administrator', { exact: true }).waitFor();
  await login.goto(first.redirect);
  await login.getByRole('heading', { name: 'Security overview', exact: true }).waitFor();
  assert.equal((await call('admin/audit?action=control_sso_signed_in', owner)).entries.length, 1);
  assert.equal(new Set(provider.attempts.map(({ state }) => state)).size, provider.attempts.length);
  assert.equal(new Set(provider.attempts.map(({ nonce }) => nonce)).size, provider.attempts.length);

  await call('admin/policy-reviews/setting', owner, { required: true }, 204);
  await login.reload();
  await login.getByLabel('Test marker', { exact: true }).selectOption('block');
  await login.getByRole('button', { name: 'Request policy review', exact: true }).click();
  await login.getByRole('link', { name: 'Open review request', exact: true }).waitFor();
  const reviewer = await page();
  await begin(reviewer, { subject: 'pilot-reviewer' });
  await finish(reviewer, true);
  await reviewer.goto(`${dashboard}/reviews`);
  reviewer.once('dialog', (dialog) => dialog.accept());
  await reviewer.getByRole('button', { name: 'Approve and publish', exact: true }).click();
  await reviewer.getByText('Approved by Pilot reviewer', { exact: true }).waitFor();
  assert.equal((await call('admin/policies', owner))[0].mode, 'block');

  const auditor = await page();
  await begin(auditor, { subject: 'pilot-auditor' });
  await finish(auditor, true);
  await auditor.getByText('Pilot auditor · Auditor', { exact: true }).waitFor();
  assert.equal(await auditor.getByRole('button', { name: 'Create enrollment grant' }).count(), 0);
  await auditor.goto(`${dashboard}/access`);
  await auditor.getByRole('alert').filter({ hasText: 'Only the organization owner' }).waitFor();
  const apiAuditor = await exchange('pilot-auditor');
  assert.ok(Date.parse(apiAuditor.expiresAt) <= Date.now() + 3_600_000);
  await call('admin/enrollment-grants', apiAuditor.token, {}, 403);
  await call('browser/policy', apiAuditor.token, undefined, 401);
  await call('internal/sso/session', apiAuditor.token, undefined, 204, 'DELETE');
  await call('admin/session', apiAuditor.token, undefined, 401);

  await auditor.goto(`${dashboard}/audit?action=control_sso_signed_in`);
  await auditor.getByRole('table').getByText('Single sign-on completed', { exact: true }).first().waitFor();
  const audit = await call('admin/audit?action=control_sso_signed_in', owner);
  assert.deepEqual(new Set(audit.entries.map(({ actorAccess }) => actorAccess.name)), new Set(['Pilot administrator', 'Pilot reviewer', 'Pilot auditor']));
  assert.doesNotMatch(JSON.stringify(audit), /synthetic-idp-claim|opaque-fixture-provider-token|pilot-auditor/);
  assert.deepEqual((await call('admin/audit?action=control_sso_signed_in', otherOwner)).entries, []);
  if (artifacts) {
    await mkdir(artifacts, { recursive: true });
    await auditor.getByRole('table').screenshot({ path: join(artifacts, organizationMode ? 'organization-sso-audit.png' : '30-control-sso-audit.png') });
  }

  await reviewer.getByRole('button', { name: 'Sign out', exact: true }).click();
  await reviewer.getByRole('heading', { name: 'Sign in to Control', exact: true }).waitFor();
  assert.equal((await reviewer.context().cookies(dashboard)).some(({ name }) => name === cookieNames.session), false);
  provision.once('dialog', (dialog) => dialog.accept());
  await provision.getByRole('button', { name: 'Revoke SSO access for Pilot auditor', exact: true }).click();
  await table.getByRole('row').filter({ hasText: 'Pilot auditor' }).getByText('Revoked', { exact: true }).waitFor();
  await auditor.goto(dashboard);
  await auditor.getByRole('heading', { name: 'Sign in to Control', exact: true }).waitFor();
  await begin(auditor, { subject: 'pilot-auditor' });
  await finish(auditor, false);

  await stop(web);
  startWeb('post');
  await until(async () => await callEdge(dashboard).catch(() => false) === 200, 'The dashboard did not restart.');
  await begin(reviewer, { subject: 'pilot-reviewer' });
  await finish(reviewer, true);
  assert.equal(provider.lastAuth, 'post');
  const beforeRotation = await exchange('pilot-administrator');
  const secondary = secondProvider && await exchange('pilot-administrator', secondBridge, 200,
    { organizationSlug: secondSlug, issuer: secondProvider.issuer });
  await stop(api);
  const rotated = secret();
  const rotatedApi = startApi(rotated);
  await until(async () => await callEdge(`${browserApi}/health`).catch(() => false) === 200, 'The API did not restart.');
  await call('admin/session', beforeRotation.token, undefined, 401);
  await exchange('pilot-administrator', bridge, 401);
  const rotatedSession = await exchange('pilot-administrator', rotated);
  assert.equal(rotatedSession.token.length, 64);
  if (secondary) {
    assert.equal((await call('admin/session', secondary.token)).organization, secondSlug);
    await call('admin/enrollment-grants', secondary.token, {}, 403);
    await call('internal/sso/session', secondary.token, undefined, 204, 'DELETE');
    await call('admin/session', secondary.token, undefined, 401);
    assert.equal(secondProvider.error, undefined);
  }
  if (!organizationMode) await t.test('retains named sessions when the same provider moves to indexed configuration', async () => {
    await stop(rotatedApi);
    startApi(rotated, true);
    await until(async () => await callEdge(`${browserApi}/health`).catch(() => false) === 200, 'The indexed API did not start.');
    const identity = await call('admin/session', rotatedSession.token);
    assert.deepEqual([identity.organization, identity.access.name], [slug, 'Pilot administrator']);
    await exchange('pilot-administrator', rotated, 401);
    const migrated = await exchange('pilot-administrator', rotated, 200, { organizationSlug: slug });
    assert.equal((await call('admin/session', migrated.token)).organization, slug);
  });
  assert.equal(provider.error, undefined);
});
