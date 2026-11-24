import { execFile, spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { cp, mkdir, mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const args = process.argv.slice(2);
const flags = new Set();
let artifacts;
for (let index = 0; index < args.length; index++) {
  const arg = args[index];
  if (['--headed', '--live', '--pilot', '--hosted', '--sso'].includes(arg)) flags.add(arg);
  else if (arg === '--artifacts' && args[index + 1] && !args[index + 1].startsWith('--')) artifacts = resolve(args[++index]);
  else throw new Error('Usage: node scripts/verify-demo.mjs [--headed] [--live] [--pilot] [--hosted] [--sso] [--artifacts DIRECTORY]');
}

const runFile = promisify(execFile);
const root = fileURLToPath(new URL('../', import.meta.url));
const temp = await mkdtemp(join(tmpdir(), 'zekvar-verify-'));
const postgres = `zekvar-demo-${randomBytes(5).toString('hex')}`;
const password = randomBytes(24).toString('hex');
const token = randomBytes(32).toString('hex');
const children = new Map();
const scratch = join(temp, 'scratch');
await mkdir(scratch);
const env = { ...process.env, NEXT_TELEMETRY_DISABLED: '1', TMPDIR: scratch };
const excluded = new Set(['node_modules', '.next', 'bin', 'obj', 'dist', 'next-env.d.ts']);
let databaseStarted = false;
let interrupted = false;

function launch(program, parameters, cwd, overrides = {}, stdio = 'inherit') {
  if (interrupted) throw new Error('Verification interrupted.');
  const child = spawn(program, parameters, { cwd, env: { ...env, ...overrides }, stdio });
  const finished = new Promise((settle, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => settle({ code, signal }));
  });
  children.set(child, finished);
  void finished.then(() => children.delete(child), () => children.delete(child));
  return { child, finished };
}

async function run(program, parameters, cwd, overrides) {
  const { code, signal } = await launch(program, parameters, cwd, overrides).finished;
  if (code !== 0) throw new Error(`${program} ${parameters.join(' ')} exited with ${signal ?? code}.`);
}

async function availablePort(host) {
  const server = createServer();
  await new Promise((done, fail) => {
    server.once('error', fail);
    server.listen(0, host, done);
  });
  const { port } = server.address();
  await new Promise((done, fail) => server.close((error) => error ? fail(error) : done()));
  return port;
}

async function ready(url, service, log) {
  for (let attempt = 0; attempt < 100 && children.has(service.child) && !interrupted; attempt++) {
    const response = await fetch(url, { signal: AbortSignal.timeout(1000) }).catch(() => undefined);
    if (response?.ok) return;
    await delay(150);
  }
  throw new Error(`Service did not become ready at ${url}.\n${log()}`);
}

function startService(program, parameters, cwd, overrides) {
  const service = launch(program, parameters, cwd, overrides, ['ignore', 'pipe', 'pipe']);
  let log = '';
  for (const stream of [service.child.stdout, service.child.stderr]) {
    stream.on('data', (chunk) => { log = (log + chunk).slice(-4000); });
  }
  // Readiness reports the service log if a process exits at startup.
  void service.finished.catch((error) => { log += String(error); });
  return { ...service, log: () => log };
}

function stopOnSignal() {
  interrupted = true;
  for (const child of children.keys()) child.kill('SIGTERM');
}
process.once('SIGINT', stopOnSignal);
process.once('SIGTERM', stopOnSignal);

try {
  if (artifacts) await mkdir(artifacts, { recursive: true });
  for (const directory of ['apps/browser-extension', 'apps/control-api', 'apps/control-web', 'contracts', 'deploy/pilot']) {
    await mkdir(join(temp, directory), { recursive: true });
    await cp(join(root, directory), join(temp, directory), {
      recursive: true,
      filter: (path) => !excluded.has(basename(path)) && !basename(path).startsWith('.env'),
    });
  }
  const extension = join(temp, 'apps/browser-extension');
  const api = join(temp, 'apps/control-api');
  const web = join(temp, 'apps/control-web');

  console.log('Building in an isolated checkout.');
  await run('docker', ['version', '--format', '{{.Server.Version}}'], root);
  const builds = await Promise.allSettled([
    run('npm', ['ci'], extension),
    run('npm', ['ci'], web),
    run('dotnet', ['build', 'Control.Api.csproj'], api),
  ]);
  for (const build of builds) if (build.status === 'rejected') throw build.reason;
  await run('npm', ['exec', '--', 'playwright', 'install', 'chromium', '--no-shell'], extension);
  await run('npm', ['run', 'build'], web);
  await run('npm', ['run', 'typecheck'], web);

  await run('docker', ['run', '-d', '--rm', '--name', postgres, '-p', '127.0.0.1::5432',
    '-e', 'POSTGRES_PASSWORD', '-e', 'POSTGRES_DB=zekvar', 'postgres:18'], root, { POSTGRES_PASSWORD: password });
  databaseStarted = true;
  const { stdout } = await runFile('docker', ['port', postgres, '5432/tcp']);
  const dbPort = stdout.trim().match(/^127\.0\.0\.1:(\d+)$/)?.[1];
  if (!dbPort) throw new Error('Docker did not publish PostgreSQL on loopback.');
  let dbReady = false;
  for (let attempt = 0; attempt < 60 && !interrupted; attempt++) {
    dbReady = await runFile('docker', ['exec', postgres, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres', '-d', 'zekvar'])
      .then(() => true, () => false);
    if (dbReady) break;
    await delay(250);
  }
  if (!dbReady) throw new Error('PostgreSQL did not become ready.');
  const db = `Host=127.0.0.1;Port=${dbPort};Database=zekvar;Username=postgres;Password=${password}`;
  const apiPort = await availablePort('127.0.0.1');
  const webPort = await availablePort('localhost');
  const apiOrigin = `http://127.0.0.1:${apiPort}`;
  const webOrigin = `http://localhost:${webPort}`;

  await run(process.execPath, ['--test', 'test/control.test.mjs'], api, {
    ZEKVAR_TEST_DATABASE: db, ZEKVAR_TEST_API_PORT: String(apiPort), ZEKVAR_TEST_POSTGRES_CONTAINER: postgres,
  });
  const dashboardAdmin = randomBytes(32).toString('hex');
  const extensionAdmin = randomBytes(32).toString('hex');
  const pilotAdmin = randomBytes(32).toString('hex');
  const reviewAdmin = randomBytes(32).toString('hex');
  const inventoryAdmin = randomBytes(32).toString('hex');
  const appCatalogAdmin = randomBytes(32).toString('hex');
  const exceptionsAdmin = randomBytes(32).toString('hex');
  const claudeAdmin = randomBytes(32).toString('hex');
  const officeAdmin = randomBytes(32).toString('hex');
  const deploymentAdmin = randomBytes(32).toString('hex');
  const hardeningAdmin = randomBytes(32).toString('hex');
  const aiAccessAdmin = randomBytes(32).toString('hex');
  const identifiersAdmin = randomBytes(32).toString('hex');
  const clipboardAdmin = randomBytes(32).toString('hex');
  const fleetAdmin = randomBytes(32).toString('hex');
  const templateAdmin = randomBytes(32).toString('hex');
  const promptRequestAdmin = randomBytes(32).toString('hex');
  const browserStateAdmin = randomBytes(32).toString('hex');
  const apiServer = startService('dotnet', ['bin/Debug/net10.0/Control.Api.dll'], api, {
    DOTNET_ENVIRONMENT: 'Development', ASPNETCORE_ENVIRONMENT: 'Development', Control__Port: String(apiPort), ConnectionStrings__Control: db,
    Control__Organizations__0__Slug: 'demo', Control__Organizations__0__AdminToken: token,
    Control__Organizations__1__Slug: 'dashboard-regression', Control__Organizations__1__AdminToken: dashboardAdmin,
    Control__Organizations__2__Slug: 'extension-regression', Control__Organizations__2__AdminToken: extensionAdmin,
    Control__Organizations__5__Slug: 'extension-inventory', Control__Organizations__5__AdminToken: inventoryAdmin,
    Control__Organizations__6__Slug: 'app-catalog', Control__Organizations__6__AdminToken: appCatalogAdmin,
    Control__Organizations__7__Slug: 'prompt-exceptions', Control__Organizations__7__AdminToken: exceptionsAdmin,
    Control__Organizations__8__Slug: 'claude-pilot', Control__Organizations__8__AdminToken: claudeAdmin,
    Control__Organizations__9__Slug: 'office-uploads', Control__Organizations__9__AdminToken: officeAdmin,
    Control__Organizations__10__Slug: 'extension-deployment', Control__Organizations__10__AdminToken: deploymentAdmin,
    Control__Organizations__11__Slug: 'ai-app-access', Control__Organizations__11__AdminToken: aiAccessAdmin,
    Control__Organizations__12__Slug: 'organization-identifiers', Control__Organizations__12__AdminToken: identifiersAdmin,
    Control__Organizations__13__Slug: 'chrome-hardening', Control__Organizations__13__AdminToken: hardeningAdmin,
    Control__Organizations__14__Slug: 'clipboard-paste', Control__Organizations__14__AdminToken: clipboardAdmin,
    Control__Organizations__15__Slug: 'browser-fleet', Control__Organizations__15__AdminToken: fleetAdmin,
    Control__Organizations__16__Slug: 'policy-templates', Control__Organizations__16__AdminToken: templateAdmin,
    Control__Organizations__17__Slug: 'prompt-exception-requests', Control__Organizations__17__AdminToken: promptRequestAdmin,
    Control__Organizations__18__Slug: 'browser-state', Control__Organizations__18__AdminToken: browserStateAdmin,
    ...(flags.has('--pilot') ? {
      Control__Organizations__3__Slug: 'managed-pilot', Control__Organizations__3__AdminToken: pilotAdmin,
      Control__Organizations__4__Slug: 'review-pilot', Control__Organizations__4__AdminToken: reviewAdmin,
    } : {}),
  });
  await ready(`${apiOrigin}/health`, apiServer, apiServer.log);
  const webServer = startService(process.execPath, ['node_modules/next/dist/bin/next', 'start', '--hostname', 'localhost', '--port', String(webPort)], web, {
    ZEKVAR_CONTROL_PORT: String(apiPort),
  });
  await ready(webOrigin, webServer, webServer.log);

  await run(process.execPath, ['--test', 'test/claude.test.mjs'], extension, {
    ZEKVAR_DEMO_API: apiOrigin, ZEKVAR_DEMO_WEB: webOrigin, ZEKVAR_DEMO_TOKEN: claudeAdmin,
    ZEKVAR_DEMO_HEADED: flags.has('--headed') ? '1' : '0', ZEKVAR_DEMO_ARTIFACTS: artifacts ?? '',
  });
  await run('npm', ['test'], extension);
  await run(process.execPath, ['--test', 'test/state-storage.test.mjs'], extension, {
    ZEKVAR_EXTENSION_TEST_API: apiOrigin, ZEKVAR_EXTENSION_TEST_ADMIN_TOKEN: browserStateAdmin,
    ZEKVAR_DEMO_HEADED: flags.has('--headed') ? '1' : '0',
  });
  await run(process.execPath, ['--test', 'test/demo.test.mjs'], extension, {
    ZEKVAR_DEMO_API: apiOrigin, ZEKVAR_DEMO_WEB: webOrigin, ZEKVAR_DEMO_TOKEN: token,
    ZEKVAR_DEMO_HEADED: flags.has('--headed') ? '1' : '0', ZEKVAR_DEMO_LIVE: flags.has('--live') ? '1' : '0',
    ZEKVAR_DEMO_ARTIFACTS: artifacts ?? '',
  });
  await run('npm', ['run', 'test:browser'], web, {
    ZEKVAR_TEST_WEB_ORIGIN: webOrigin, ZEKVAR_TEST_API_ORIGIN: apiOrigin, ZEKVAR_TEST_ADMIN_TOKEN: dashboardAdmin,
    ZEKVAR_DEMO_HEADED: flags.has('--headed') ? '1' : '0',
    ZEKVAR_TEST_RELEASE_SCREENSHOT: artifacts ? join(artifacts, '31-control-browser-releases.png') : '',
    ZEKVAR_TEST_BROWSER_GROUP_SCREENSHOT: artifacts ? join(artifacts, '32-control-browser-rollout-group.png') : '',
    ZEKVAR_TEST_COVERAGE_SCREENSHOT: artifacts ? join(artifacts, '33-control-composer-readiness.png') : '',
    ZEKVAR_TEST_AUDIT_SCREENSHOT: artifacts ? join(artifacts, '13-control-audit-log.png') : '',
    ZEKVAR_TEST_RETENTION_SCREENSHOT: artifacts ? join(artifacts, '14-control-data-retention.png') : '',
    ZEKVAR_TEST_PREVIEW_SCREENSHOT: artifacts ? join(artifacts, '16-control-policy-preview.png') : '',
    ZEKVAR_TEST_EVENTS_SCREENSHOT: artifacts ? join(artifacts, '17-control-event-history.png') : '',
    ZEKVAR_TEST_ACCESS_SCREENSHOT: artifacts ? join(artifacts, '22-control-access.png') : '',
    ZEKVAR_TEST_REVIEW_SCREENSHOT: artifacts ? join(artifacts, '23-control-policy-review.png') : '',
  });
  await run(process.execPath, ['--test', 'test/extension-deployment.test.mjs'], web, {
    ZEKVAR_TEST_WEB_ORIGIN: webOrigin, ZEKVAR_TEST_API_ORIGIN: apiOrigin, ZEKVAR_TEST_ADMIN_TOKEN: deploymentAdmin,
    ZEKVAR_DEMO_HEADED: flags.has('--headed') ? '1' : '0',
    ZEKVAR_TEST_DEPLOYMENT_SCREENSHOT: artifacts ? join(artifacts, '35-chrome-extension-deployment.png') : '',
  });
  await run(process.execPath, ['--test', 'test/browser-hardening.test.mjs'], web, {
    ZEKVAR_TEST_WEB_ORIGIN: webOrigin, ZEKVAR_TEST_API_ORIGIN: apiOrigin, ZEKVAR_TEST_ADMIN_TOKEN: hardeningAdmin,
    ZEKVAR_DEMO_HEADED: flags.has('--headed') ? '1' : '0',
    ZEKVAR_TEST_HARDENING_SCREENSHOT: artifacts ? join(artifacts, '40-chrome-hardening.png') : '',
  });
  await run(process.execPath, ['--test', 'test/clipboard-paste.test.mjs'], extension, {
    ZEKVAR_DEMO_API: apiOrigin, ZEKVAR_DEMO_WEB: webOrigin, ZEKVAR_DEMO_TOKEN: clipboardAdmin,
    ZEKVAR_DEMO_HEADED: flags.has('--headed') ? '1' : '0', ZEKVAR_DEMO_ARTIFACTS: artifacts ?? '',
  });
  await run(process.execPath, ['--test', 'test/fleet.test.mjs'], extension, {
    ZEKVAR_DEMO_API: apiOrigin, ZEKVAR_DEMO_WEB: webOrigin, ZEKVAR_DEMO_TOKEN: fleetAdmin,
    ZEKVAR_DEMO_HEADED: flags.has('--headed') ? '1' : '0', ZEKVAR_DEMO_ARTIFACTS: artifacts ?? '',
  });
  await run(process.execPath, ['--test', 'test/policy-templates.test.mjs'], extension, {
    ZEKVAR_DEMO_API: apiOrigin, ZEKVAR_DEMO_WEB: webOrigin, ZEKVAR_DEMO_TOKEN: templateAdmin,
    ZEKVAR_DEMO_HEADED: flags.has('--headed') ? '1' : '0', ZEKVAR_DEMO_ARTIFACTS: artifacts ?? '',
  });
  await run(process.execPath, ['--test', 'test/prompt-requests.test.mjs'], extension, {
    ZEKVAR_DEMO_API: apiOrigin, ZEKVAR_DEMO_WEB: webOrigin, ZEKVAR_DEMO_TOKEN: promptRequestAdmin,
    ZEKVAR_DEMO_HEADED: flags.has('--headed') ? '1' : '0', ZEKVAR_DEMO_LIVE: flags.has('--live') ? '1' : '0',
    ZEKVAR_DEMO_ARTIFACTS: artifacts ?? '',
  });
  await run(process.execPath, ['--test', 'test/ai-app-access.test.mjs'], extension, {
    ZEKVAR_DEMO_API: apiOrigin, ZEKVAR_DEMO_WEB: webOrigin, ZEKVAR_DEMO_TOKEN: aiAccessAdmin,
    ZEKVAR_DEMO_HEADED: flags.has('--headed') ? '1' : '0',
    ZEKVAR_TEST_AI_ACCESS_SCREENSHOT: artifacts ? join(artifacts, '36-ai-app-access.png') : '',
  });
  await run(process.execPath, ['--test', 'test/office-upload.test.mjs'], extension, {
    ZEKVAR_EXTENSION_TEST_API: apiOrigin, ZEKVAR_EXTENSION_TEST_ADMIN_TOKEN: officeAdmin,
    ZEKVAR_DEMO_HEADED: flags.has('--headed') ? '1' : '0',
    ZEKVAR_DEMO_ARTIFACTS: artifacts ?? '',
    ZEKVAR_TEST_FILE_BLOCK_SCREENSHOT: artifacts ? join(artifacts, '37-file-content-block.png') : '',
  });
  await run(process.execPath, ['--test', 'test/identifier-protection.test.mjs'], extension, {
    ZEKVAR_DEMO_API: apiOrigin, ZEKVAR_DEMO_WEB: webOrigin, ZEKVAR_DEMO_TOKEN: identifiersAdmin,
    ZEKVAR_DEMO_HEADED: flags.has('--headed') ? '1' : '0', ZEKVAR_DEMO_ARTIFACTS: artifacts ?? '',
  });
  await run('npm', ['run', 'test:control'], extension, {
    ZEKVAR_EXTENSION_TEST_API: apiOrigin, ZEKVAR_EXTENSION_TEST_ADMIN_TOKEN: extensionAdmin,
    ZEKVAR_DEMO_HEADED: flags.has('--headed') ? '1' : '0',
  });
  await run(process.execPath, ['--test', 'test/extension-inventory.test.mjs'], extension, {
    ZEKVAR_DEMO_API: apiOrigin, ZEKVAR_DEMO_WEB: webOrigin, ZEKVAR_DEMO_TOKEN: inventoryAdmin,
    ZEKVAR_DEMO_HEADED: flags.has('--headed') ? '1' : '0', ZEKVAR_DEMO_ARTIFACTS: artifacts ?? '',
  });
  await run(process.execPath, ['--test', 'test/app-catalog.test.mjs'], extension, {
    ZEKVAR_DEMO_API: apiOrigin, ZEKVAR_DEMO_WEB: webOrigin, ZEKVAR_DEMO_TOKEN: appCatalogAdmin,
    ZEKVAR_DEMO_HEADED: flags.has('--headed') ? '1' : '0', ZEKVAR_DEMO_LIVE: flags.has('--live') ? '1' : '0',
    ZEKVAR_DEMO_ARTIFACTS: artifacts ?? '',
  });
  await run(process.execPath, ['--test', 'test/prompt-exceptions.test.mjs'], extension, {
    ZEKVAR_DEMO_API: apiOrigin, ZEKVAR_DEMO_WEB: webOrigin, ZEKVAR_DEMO_TOKEN: exceptionsAdmin,
    ZEKVAR_DEMO_HEADED: flags.has('--headed') ? '1' : '0', ZEKVAR_DEMO_ARTIFACTS: artifacts ?? '',
  });
  if (flags.has('--pilot')) {
    await run(process.execPath, ['--test', 'test/review-pilot.test.mjs'], extension, {
      ZEKVAR_DEMO_API: apiOrigin, ZEKVAR_DEMO_WEB: webOrigin, ZEKVAR_DEMO_TOKEN: reviewAdmin,
      ZEKVAR_DEMO_HEADED: flags.has('--headed') ? '1' : '0',
    });
    console.log('Running the two-profile managed pilot. The stale-browser check takes about 90 seconds.');
    await run(process.execPath, ['--test', 'test/pilot.test.mjs'], extension, {
      ZEKVAR_DEMO_API: apiOrigin, ZEKVAR_DEMO_WEB: webOrigin, ZEKVAR_DEMO_TOKEN: pilotAdmin,
      ZEKVAR_DEMO_HEADED: flags.has('--headed') ? '1' : '0', ZEKVAR_DEMO_ARTIFACTS: artifacts ?? '',
    });
  }
  if (flags.has('--hosted') || flags.has('--sso')) {
    webServer.child.kill('SIGTERM');
    await webServer.finished;
    await run('npm', ['run', 'build'], web, { ZEKVAR_STANDALONE: '1' });
    const standalone = join(temp, 'hosted-web');
    const hostedDll = join(temp, 'hosted-api/Control.Api.dll');
    await cp(join(web, '.next/standalone'), standalone, { recursive: true });
    await cp(join(web, '.next/static'), join(standalone, '.next/static'), { recursive: true });
    await run('dotnet', ['publish', '--no-restore', '-c', 'Release', '-o', join(temp, 'hosted-api')], api);

    if (flags.has('--sso')) {
      console.log('Verifying Control single sign-on over TLS with an isolated identity provider.');
      await run(process.execPath, ['--test', 'test/sso.test.mjs'], web, {
        ZEKVAR_SSO_TEST_API: hostedDll, ZEKVAR_SSO_TEST_WEB: standalone, ZEKVAR_SSO_TEST_DATABASE: db,
        ZEKVAR_DEMO_HEADED: flags.has('--headed') ? '1' : '0', ZEKVAR_DEMO_ARTIFACTS: artifacts ?? '',
      });
    }

    if (flags.has('--hosted')) {
      console.log('Verifying the hosted pilot through a local TLS edge.');
      const hostedPort = await availablePort('127.0.0.1');
      const standalonePort = await availablePort('127.0.0.1');
      const owner = randomBytes(32).toString('hex');
      const hostedApi = startService('dotnet', [hostedDll], api, {
        DOTNET_ENVIRONMENT: 'Production', ASPNETCORE_ENVIRONMENT: 'Production', Control__HostedPilot: 'true',
        Control__Port: String(hostedPort), ConnectionStrings__Control: db,
        Control__Organizations__0__Slug: 'tls-pilot', Control__Organizations__0__AdminToken: owner,
      });
      await ready(`http://127.0.0.1:${hostedPort}/health`, hostedApi, hostedApi.log);
      const hostedWeb = startService(process.execPath, ['server.js'], standalone, {
        HOSTNAME: '127.0.0.1', PORT: String(standalonePort), NODE_ENV: 'production', ZEKVAR_HOSTED_PILOT: '1',
        ZEKVAR_CONTROL_PORT: String(hostedPort),
      });
      await ready(`http://127.0.0.1:${standalonePort}`, hostedWeb, hostedWeb.log);
      await run(process.execPath, ['--test', 'test/hosted-pilot.test.mjs'], extension, {
        ZEKVAR_HOSTED_TEST_API_PORT: String(hostedPort), ZEKVAR_HOSTED_TEST_WEB_PORT: String(standalonePort),
        ZEKVAR_DEMO_TOKEN: owner, ZEKVAR_DEMO_HEADED: flags.has('--headed') ? '1' : '0', ZEKVAR_DEMO_ARTIFACTS: artifacts ?? '',
      });
    }
  }
  if (artifacts) console.log(`Browser screenshots saved to ${artifacts}`);
} catch (error) {
  console.error(error.message);
  process.exitCode = interrupted ? 130 : 1;
} finally {
  const runs = [...children];
  for (const [child] of runs) child.kill('SIGTERM');
  await Promise.allSettled(runs.map(([, finished]) => finished));
  if (databaseStarted) {
    await runFile('docker', ['stop', postgres]).catch(() => {
      console.error(`Could not stop disposable container ${postgres}.`);
      process.exitCode ||= 1;
    });
  }
  await rm(temp, { recursive: true, force: true });
}
