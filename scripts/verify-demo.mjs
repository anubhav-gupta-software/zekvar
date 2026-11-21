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
  if (arg === '--headed' || arg === '--live' || arg === '--pilot') flags.add(arg);
  else if (arg === '--artifacts' && args[index + 1] && !args[index + 1].startsWith('--')) artifacts = resolve(args[++index]);
  else throw new Error('Usage: node scripts/verify-demo.mjs [--headed] [--live] [--pilot] [--artifacts DIRECTORY]');
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
  for (const directory of ['apps/browser-extension', 'apps/control-api', 'apps/control-web', 'contracts']) {
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
  const apiServer = startService('dotnet', ['bin/Debug/net10.0/Control.Api.dll'], api, {
    DOTNET_ENVIRONMENT: 'Development', ASPNETCORE_ENVIRONMENT: 'Development', Control__Port: String(apiPort), ConnectionStrings__Control: db,
    Control__Organizations__0__Slug: 'demo', Control__Organizations__0__AdminToken: token,
    Control__Organizations__1__Slug: 'dashboard-regression', Control__Organizations__1__AdminToken: dashboardAdmin,
    Control__Organizations__2__Slug: 'extension-regression', Control__Organizations__2__AdminToken: extensionAdmin,
    Control__Organizations__5__Slug: 'extension-inventory', Control__Organizations__5__AdminToken: inventoryAdmin,
    Control__Organizations__6__Slug: 'app-catalog', Control__Organizations__6__AdminToken: appCatalogAdmin,
    Control__Organizations__7__Slug: 'prompt-exceptions', Control__Organizations__7__AdminToken: exceptionsAdmin,
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

  await run('npm', ['test'], extension);
  await run(process.execPath, ['--test', 'test/demo.test.mjs'], extension, {
    ZEKVAR_DEMO_API: apiOrigin, ZEKVAR_DEMO_WEB: webOrigin, ZEKVAR_DEMO_TOKEN: token,
    ZEKVAR_DEMO_HEADED: flags.has('--headed') ? '1' : '0', ZEKVAR_DEMO_LIVE: flags.has('--live') ? '1' : '0',
    ZEKVAR_DEMO_ARTIFACTS: artifacts ?? '',
  });
  await run('npm', ['run', 'test:browser'], web, {
    ZEKVAR_TEST_WEB_ORIGIN: webOrigin, ZEKVAR_TEST_API_ORIGIN: apiOrigin, ZEKVAR_TEST_ADMIN_TOKEN: dashboardAdmin,
    ZEKVAR_TEST_AUDIT_SCREENSHOT: artifacts ? join(artifacts, '13-control-audit-log.png') : '',
    ZEKVAR_TEST_RETENTION_SCREENSHOT: artifacts ? join(artifacts, '14-control-data-retention.png') : '',
    ZEKVAR_TEST_PREVIEW_SCREENSHOT: artifacts ? join(artifacts, '16-control-policy-preview.png') : '',
    ZEKVAR_TEST_EVENTS_SCREENSHOT: artifacts ? join(artifacts, '17-control-event-history.png') : '',
    ZEKVAR_TEST_ACCESS_SCREENSHOT: artifacts ? join(artifacts, '22-control-access.png') : '',
    ZEKVAR_TEST_REVIEW_SCREENSHOT: artifacts ? join(artifacts, '23-control-policy-review.png') : '',
  });
  await run('npm', ['run', 'test:control'], extension, {
    ZEKVAR_EXTENSION_TEST_API: apiOrigin, ZEKVAR_EXTENSION_TEST_ADMIN_TOKEN: extensionAdmin,
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
