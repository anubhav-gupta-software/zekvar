import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { chromium } from 'playwright';
import { startBackupBucket } from './s3-backup-fixture.mjs';

const run = promisify(execFile);
const root = fileURLToPath(new URL('../../../', import.meta.url));
const pilot = join(root, 'deploy/pilot');
const secret = () => randomBytes(32).toString('hex');
const fixture = await readFile(new URL('./guest-chatgpt-composer.html', import.meta.url), 'utf8');
const draft = 'Backup recovery fixture ZEKVAR_TEST_SECRET';
const artifacts = process.env.ZEKVAR_BACKUP_TEST_ARTIFACTS;
const offsite = process.env.ZEKVAR_BACKUP_TEST_OFFSITE === '1';

async function until(check, message) {
  for (let attempt = 0; attempt < 100; attempt++) {
    const result = await check();
    if (result) return result;
    await delay(150);
  }
  assert.fail(message);
}

test(`Control recovers from an encrypted ${offsite ? 'off-host' : 'local'} PostgreSQL backup and re-enrolls Chrome`, { timeout: 240_000 }, async (t) => {
  const work = await mkdtemp(join(tmpdir(), 'zekvar-backup-test-'));
  const override = join(work, 'compose.yaml');
  const publish = join(work, 'api');
  const id = randomBytes(5).toString('hex');
  const source = { name: `zekvar-backup-${id}`, password: secret(), owner: secret(), otherOwner: secret() };
  const target = { name: `zekvar-restore-${id}`, password: secret(), owner: secret(), otherOwner: secret() };
  const sso = { issuer: 'https://recovery-issuer.example.test', subject: 'recovery-auditor', bridge: secret() };
  const path = (name) => join(work, name);
  const runHere = (file, args, options) => run(file, args, { cwd: root, timeout: 90_000, ...options });
  const compose = (db, ...args) => runHere('docker', [
    'compose', '--project-name', db.name, '--env-file', db.env, '--file', join(pilot, 'compose.yaml'), '--file', override, ...args,
  ]);
  const postgres = (db, ...args) => compose(db, 'exec', '-T', 'postgres', ...args);
  const sql = (db, statement) => postgres(db, 'psql', '-XAt', '-U', 'postgres', '-d', 'zekvar', '-v', 'ON_ERROR_STOP=1', '-c', statement)
    .then(({ stdout }) => stdout.trim());
  const hasSchema = (db) => sql(db, "SELECT to_regclass('public.schema_migrations') IS NOT NULL");
  const archive = path('pilot snapshot.age');
  const identity = path('identity');
  const wrongIdentity = path('wrong-identity');
  const recipients = path('recipients');
  const operate = (operation, db, file, key) => runHere(join(pilot, 'database-backup.sh'), [operation, db.name, db.env, file, key]);
  const backup = (file = archive, key = recipients) => operate('backup', source, file, key);
  let recoveryArchive = archive;
  const restore = (file = recoveryArchive, key = identity, db = target) => operate('restore', db, file, key);
  let browser;
  let api;
  let projectStarted = false;

  async function stopApi() {
    if (!api) return;
    api.child.kill('SIGTERM');
    await api.finished;
    api = undefined;
  }

  t.after(async () => {
    try {
      await browser?.close();
      await stopApi();
      if (projectStarted) {
        const results = await Promise.allSettled([source, target].map((db) => compose(db, 'down', '--volumes', '--remove-orphans')));
        for (const result of results) if (result.status === 'rejected') throw result.reason;
      }
    } finally {
      await rm(work, { recursive: true, force: true });
    }
  });

  await writeFile(override, 'services:\n  postgres:\n    ports: ["127.0.0.1::5432"]\n    networks: [edge, database]\n');
  for (const database of [source, target]) {
    database.env = path(`${database.name}.env`);
    await writeFile(database.env, `ZEKVAR_DASHBOARD_HOST=control.example.test
ZEKVAR_BROWSER_HOST=browser.example.test
ZEKVAR_ACME_EMAIL=admin@example.test
ZEKVAR_ADMIN_NETWORKS=127.0.0.1/32
ZEKVAR_ORGANIZATION_SLUG=recovery-drill
ZEKVAR_OWNER_TOKEN=${database.owner}
ZEKVAR_POSTGRES_OPERATOR_PASSWORD=${secret()}
ZEKVAR_POSTGRES_APP_PASSWORD=${database.password}
`, { mode: 0o600 });
  }
  for (const file of [identity, wrongIdentity]) await runHere('age-keygen', ['-o', file]);
  await writeFile(recipients, (await runHere('age-keygen', ['-y', identity])).stdout);
  await runHere('dotnet', ['publish', 'apps/control-api/Control.Api.csproj', '-c', 'Release', '-o', publish]);
  projectStarted = true;
  for (const db of [source, target]) {
    await compose(db, 'up', '-d', '--wait', 'postgres');
    const { stdout } = await compose(db, 'port', 'postgres', '5432');
    db.port = stdout.trim().match(/^127\.0\.0\.1:(\d+)$/)?.[1];
    assert.ok(db.port, 'Fixture PostgreSQL must be published to loopback');
  }
  await assert.rejects(operate('backup', target, path('uninitialized.age'), recipients), /missing the Control schema/);

  const socket = createServer().listen(0, '127.0.0.1');
  await once(socket, 'listening');
  const { port } = socket.address();
  await new Promise((resolve) => socket.close(resolve));
  const origin = `http://127.0.0.1:${port}`;

  async function startApi(db) {
    const child = spawn('dotnet', [join(publish, 'Control.Api.dll')], {
      cwd: work, stdio: ['ignore', 'pipe', 'pipe'], env: {
        ...process.env, ASPNETCORE_ENVIRONMENT: 'Production', DOTNET_ENVIRONMENT: 'Production', Control__HostedPilot: 'true',
        Control__Port: String(port), ConnectionStrings__Control: `Host=127.0.0.1;Port=${db.port};Database=zekvar;Username=zekvar_app;Password=${db.password}`,
        Control__Organizations__0__Slug: 'recovery-drill', Control__Organizations__0__AdminToken: db.owner,
        Control__Organizations__1__Slug: 'other-recovery-tenant', Control__Organizations__1__AdminToken: db.otherOwner,
        Control__Oidc__Issuer: sso.issuer, Control__Oidc__OrganizationSlug: 'recovery-drill', Control__Oidc__ExchangeToken: sso.bridge,
      },
    });
    let log = '';
    for (const stream of [child.stdout, child.stderr]) stream.on('data', (chunk) => { log = (log + chunk).slice(-3000); });
    api = { child, finished: once(child, 'exit') };
    await until(async () => {
      assert.equal(child.exitCode, null, log);
      return (await fetch(`${origin}/health`, { signal: AbortSignal.timeout(1000) }).catch(() => undefined))?.ok;
    }, 'Control did not become ready with the recovered database.');
  }

  async function call(route, { body, token, expected = 200 } = {}) {
    const response = await fetch(`${origin}/v1/${route}`, {
      method: body === undefined ? 'GET' : 'POST', signal: AbortSignal.timeout(5000),
      headers: { ...(token && { Authorization: `Bearer ${token}` }), ...(body !== undefined && { 'Content-Type': 'application/json' }) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    assert.equal(response.status, expected, route);
    return response.ok && expected !== 204 ? response.json() : undefined;
  }
  const admin = (owner, route, body, expected) => call(`admin/${route}`, { token: owner, body, expected });

  await startApi(source);
  await admin(source.owner, 'access/sso', { name: 'Recovery SSO auditor', role: 'auditor', subject: sso.subject });
  const ssoExchange = (expected = 200) => call('internal/sso/session', { token: sso.bridge, expected,
    body: { issuer: sso.issuer, subject: sso.subject, expiresAt: new Date(Date.now() + 600_000).toISOString() } });
  const ssoSession = await ssoExchange();
  const retention = { securityEventDays: 30, aiObservationDays: 30, auditDays: 90 };
  await admin(source.owner, 'retention', retention, 204);
  const policy = await admin(source.owner, 'policies', { mode: 'block' });
  const pendingGrant = (await admin(source.owner, 'enrollment-grants', {})).grant;
  const usedGrant = (await admin(source.owner, 'enrollment-grants', {})).grant;
  const access = await admin(source.owner, 'access', { name: 'Recovery reviewer', role: 'administrator', hours: 1 });
  await admin(source.owner, 'policy-reviews/setting', { required: true }, 204);
  await admin(access.token, 'policies', { mode: 'warn' }, 202);

  const extension = path('extension');
  const env = { ...process.env, ZEKVAR_CONTROL_PORT: String(port), ZEKVAR_EXTENSION_OUTDIR: extension };
  delete env.ZEKVAR_CONTROL_ORIGIN;
  await runHere(process.execPath, ['build.mjs'], { cwd: join(root, 'apps/browser-extension'), env });
  browser = await chromium.launchPersistentContext(path('chrome'), {
    channel: 'chromium', headless: process.env.ZEKVAR_BACKUP_TEST_HEADED !== '1',
    args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`],
  });
  browser.setDefaultTimeout(9000);
  const worker = browser.serviceWorkers()[0] ?? await browser.waitForEvent('serviceworker');
  const popup = await browser.newPage();
  await popup.goto(new URL('popup.html', worker.url()).href);
  const enrolled = () => worker.evaluate(async () => (await chrome.storage.local.get('controlState')).controlState.enrollment);
  const sync = popup.getByRole('button', { name: 'Sync now', exact: true });
  async function enroll(grant) {
    await popup.getByLabel('Enrollment grant').fill(grant);
    await popup.getByRole('button', { name: 'Enroll this browser', exact: true }).click();
    await popup.getByText(`Connected to Control · BLOCK v${policy.version}`, { exact: true }).waitFor();
    return enrolled();
  }

  const previous = await enroll(usedGrant);
  const chat = await browser.newPage();
  await chat.route('https://chatgpt.com/**', (route) => route.fulfill({ contentType: 'text/html', body: fixture }));
  async function blockPrompt(owner, installationId) {
    await chat.goto('https://chatgpt.com/');
    await chat.getByText(new RegExp(`^Zekvar · BLOCK v${policy.version}`)).waitFor();
    await chat.getByPlaceholder('Ask ChatGPT').fill(draft);
    await chat.getByRole('button', { name: 'Send message' }).click();
    await chat.getByRole('alert').filter({ hasText: 'Submission blocked' }).waitFor();
    assert.equal(await chat.locator('#fixture-sends').textContent(), '0');
    return until(async () => (await admin(owner, 'events')).find((row) => row.installationId === installationId && row.decision === 'block'),
      'The blocked attempt did not appear in Control.');
  }
  const event = await blockPrompt(source.owner, previous.installationId);

  if (offsite) {
    const prefix = 'zekvar/pilot';
    const storage = await startBackupBucket(prefix);
    t.after(storage.close);
    const storageEnv = (role, overrides) => ({ ...process.env, ...storage.env(role), TMPDIR: work, ...overrides });
    const runStorage = (role, args, overrides) => runHere(join(pilot, 's3-backup.sh'), args, { env: storageEnv(role, overrides) });
    const publish = (key = recipients, overrides) => runStorage('WRITER', ['publish', source.name, source.env, key], overrides);
    const freshness = (role = 'MONITOR', hours = '30') => runStorage(role, ['check', hours]);
    const clockKey = (offset) => new Date(Date.now() + offset * 3600_000).toISOString().slice(0, 19).replace(/[-:]/g, '') + 'Z';
    const seeded = { body: Buffer.from('synthetic listing entry'), modified: new Date() };
    storage.objects.set(`${prefix}/${clockKey(-72)}-0000000000000000.age`, seeded);
    storage.objects.set(`${prefix}/${clockKey(72)}-0000000000000000.age`, seeded);
    storage.objects.set(`${prefix}/${clockKey(-1)}-0000000000000000.age`, { ...seeded, modified: new Date('2020-01-01') });
    storage.objects.set(`${prefix}/${clockKey(-2)}-0000000000000000.age`, { ...seeded, body: Buffer.alloc(0) });
    await assert.rejects(freshness(), /No off-host backup within the last 30 hours/);
    await assert.rejects(freshness('MONITOR', '0'), /between 1 and 168 hours/);
    await assert.rejects(freshness('WRITER'), /Could not check off-host backup freshness/);
    await assert.rejects(publish(recipients, { ZEKVAR_BACKUP_RELEASE: 'invalid,metadata' }), /deployed release ID/);
    await assert.rejects(publish(path('missing-recipients')), /age key file must be readable/);
    assert.equal(storage.uploads.length, 0);

    storage.denyUploads();
    await assert.rejects(publish(), /Off-host backup upload failed/);
    await assert.rejects(freshness(), /No off-host backup/);
    storage.allowUploads();
    storage.failNextUpload();
    const published = (await publish()).stdout;
    const [key, digest] = [published.match(/ key=(\S+)/)?.[1], published.match(/ sha256=(\S+)/)?.[1]];
    assert.deepEqual(storage.uploads, [key, key], 'The CLI retried the same upload key after a temporary 503');
    const object = storage.objects.get(key);
    assert.deepEqual(object.metadata, { release: 'test-release', keyId: 'test-recovery-key', started: key.slice(prefix.length + 1, -21) });
    assert.equal(object.checksum, digest);
    assert.equal(object.body.subarray(0, 22).toString(), 'age-encryption.org/v1\n');
    assert.ok((await freshness()).stdout.includes(`key=${key}`), 'The monitor selected a valid backup across paginated results');

    const duplicate = path('duplicate.age');
    await writeFile(duplicate, 'replacement payload');
    await assert.rejects(runHere('aws', ['s3api', 'put-object', '--bucket', storage.env('WRITER').ZEKVAR_BACKUP_BUCKET,
      '--expected-bucket-owner', storage.env('WRITER').ZEKVAR_BACKUP_BUCKET_OWNER, '--key', key, '--body', duplicate, '--if-none-match', '*'],
    { env: storageEnv('WRITER') }), /PreconditionFailed/);
    assert.equal(storage.objects.get(key), object);

    const download = path('downloaded snapshot.age');
    const fetchArchive = (role = 'READER', file = download, expected = digest, objectKey = key, overrides) =>
      runStorage(role, ['fetch', objectKey, file, expected], overrides);
    await assert.rejects(fetchArchive('WRITER'), /Off-host backup download failed/);
    await assert.rejects(fetchArchive('MONITOR'), /Off-host backup download failed/);
    await assert.rejects(fetchArchive('READER', download, digest, key, { ZEKVAR_BACKUP_BUCKET_OWNER: '000000000000' }), /Off-host backup download failed/);
    await assert.rejects(fetchArchive('READER', download, digest, key.replace(prefix, 'wrong/prefix')), /configured backup prefix/);
    assert.equal(storage.reads(), 0);
    const wrongDigest = createHash('sha256').update('wrong').digest('base64');
    await assert.rejects(fetchArchive('READER', download, wrongDigest), /did not match the recorded checksum/);
    storage.corruptDownloads(true);
    await assert.rejects(fetchArchive(), /No archive was published/);
    storage.corruptDownloads(false);
    await assert.rejects(stat(download), { code: 'ENOENT' });
    await symlink(path('missing.age'), path('symlink.age'));
    await assert.rejects(fetchArchive('READER', path('symlink.age')), /destination already exists/);
    const downloads = await Promise.allSettled([fetchArchive(), fetchArchive()]);
    assert.equal(downloads.filter((result) => result.status === 'fulfilled').length, 1);
    assert.deepEqual(await readFile(download), object.body);
    assert.equal((await stat(download)).mode & 0o777, 0o600);
    assert.ok(!(await readdir(work)).some((name) => /^\.zekvar-download\.|^zekvar-offsite\./.test(name)));
    recoveryArchive = download;
  }

  await writeFile(path('invalid-recipients'), 'invalid public encryption recipient\n');
  const unpublished = path('unpublished.age');
  await assert.rejects(backup(unpublished, path('invalid-recipients')), /No archive was published/);
  await assert.rejects(stat(unpublished), { code: 'ENOENT' });
  const backups = await Promise.allSettled([backup(), backup()]);
  assert.equal(backups.filter((result) => result.status === 'fulfilled').length, 1);
  const snapshot = await readFile(archive);
  assert.equal((await stat(archive)).mode & 0o777, 0o600);
  assert.equal(snapshot.subarray(0, 22).toString(), 'age-encryption.org/v1\n');
  await assert.rejects(backup(), /destination already exists/);
  assert.deepEqual(await readFile(archive), snapshot);
  await assert.rejects(restore(archive, identity, source), /already contains application objects/);

  await assert.rejects(restore(archive, wrongIdentity), /could not be decrypted and verified/);
  await writeFile(path('truncated.age'), snapshot.subarray(0, -5));
  await assert.rejects(restore(path('truncated.age')), /could not be decrypted and verified/);
  const invalidArchive = path('not-a-dump.age');
  await runHere('age', ['--encrypt', '-R', recipients, '-o', invalidArchive, path('invalid-recipients')]);
  await assert.rejects(restore(invalidArchive), /does not appear to be a valid archive/);
  assert.equal(await hasSchema(target), 'f');

  // Produce a readable archive with an invalid foreign key so failure occurs after schema and data SQL.
  await sql(source, `BEGIN;
    SET LOCAL ROLE zekvar_app;
    CREATE TABLE restore_parents (id integer PRIMARY KEY);
    CREATE TABLE restore_children (parent_id integer REFERENCES restore_parents (id));
    RESET ROLE;
    SET LOCAL session_replication_role = replica;
    INSERT INTO restore_children VALUES (1);
    COMMIT;`);
  await backup(path('late-failure.age'));
  await assert.rejects(restore(path('late-failure.age')), /foreign key constraint/);
  assert.equal(await hasSchema(target), 'f');
  assert.equal(await sql(target, "SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace"), '0');

  // A browser may already have a newer, less restrictive policy than the snapshot.
  await admin(source.owner, 'policy-reviews/setting', { required: false }, 204);
  const newer = await admin(source.owner, 'policies', { mode: 'monitor' });
  await sync.click();
  await popup.getByText(`Connected to Control · MONITOR v${newer.version}`, { exact: true }).waitFor();

  // These revocations were issued after the snapshot and would be lost without the recovery reset.
  await admin(source.owner, `installations/${previous.installationId}/revoke`, {}, 204);
  await admin(source.owner, `access/${access.access.id}/revoke`, {}, 204);
  await stopApi();
  const restores = await Promise.allSettled([restore(), restore()]);
  assert.equal(restores.filter((result) => result.status === 'fulfilled').length, 1);
  assert.match(restores.find((result) => result.status === 'rejected').reason.stderr, /already contains application objects/);
  assert.equal(await hasSchema(target), 't');
  assert.equal(await sql(target, 'SELECT count(*) FROM admin_memberships'), '0');
  assert.equal(await sql(target, 'SELECT count(*) FROM control_sso_sessions'), '0');
  await assert.rejects(restore(), /already contains application objects/);
  await startApi(target);

  await admin(source.owner, 'session', undefined, 401);
  await admin(ssoSession.token, 'session', undefined, 401);
  await ssoExchange(401);
  await admin(access.token, 'session', undefined, 401);
  await call('browser/policy', { token: previous.token, expected: 401 });
  for (const grant of [pendingGrant, usedGrant]) await call('enroll', { body: { grant }, expected: 401 });
  assert.deepEqual((await admin(target.owner, 'policies'))[0], policy);
  assert.deepEqual(await admin(target.owner, 'retention'), retention);
  assert.deepEqual(await admin(target.owner, 'events'), [event]);
  assert.deepEqual(await admin(target.otherOwner, 'events'), []);
  assert.equal((await admin(target.owner, 'policy-reviews')).entries[0].status, 'cancelled');
  const { entries } = await admin(target.owner, 'audit');
  const revoked = entries.filter((row) => row.action === 'access_revoked').map((row) => row.subjectAccess.name).sort();
  assert.deepEqual(revoked, ['Recovery SSO auditor', 'Recovery reviewer']);
  for (const action of ['browser_revoked', 'policy_review_decided']) {
    assert.equal(entries.filter((row) => row.action === action).length, 1, action);
  }

  if (await sync.isVisible()) await sync.click();
  await popup.getByText(/^Control access revoked/).waitFor();
  const replacement = await enroll((await admin(target.owner, 'enrollment-grants', {})).grant);
  assert.notEqual(replacement.installationId, previous.installationId);
  await blockPrompt(target.owner, replacement.installationId);
  const exportData = await admin(target.owner, 'events/export');
  assert.equal(exportData.entries.length, 2);
  assert.doesNotMatch(JSON.stringify(exportData), /Backup recovery fixture|ZEKVAR_TEST_SECRET/);
  if (artifacts) {
    await mkdir(artifacts, { recursive: true });
    await chat.screenshot({ path: join(artifacts, 'recovered-policy-block.png'), fullPage: true });
  }
});
