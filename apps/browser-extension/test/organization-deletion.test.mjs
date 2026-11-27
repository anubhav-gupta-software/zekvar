import assert from 'node:assert/strict';
import { execFile, execFileSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { chromium } from 'playwright';

// Connected check: Chrome enrolled in an organization that the owner deletes is rejected by Control and asks for a
// new enrollment grant. The disposable PostgreSQL container shortens the grace period so the deletion job runs now.
const { ZEKVAR_DEMO_API: api, ZEKVAR_DEMO_TOKEN: owner, ZEKVAR_DEMO_OTHER_TOKEN: other, ZEKVAR_TEST_POSTGRES_CONTAINER: postgres } = process.env;
assert.match(api ?? '', /^http:\/\/127\.0\.0\.1:\d+$/);
assert.match(owner ?? '', /^[a-f0-9]{64}$/, 'Set ZEKVAR_DEMO_TOKEN for a disposable organization that this test deletes.');
assert.match(other ?? '', /^[a-f0-9]{64}$/, 'Set ZEKVAR_DEMO_OTHER_TOKEN for a second organization that must survive.');
assert.match(postgres ?? '', /^zekvar-demo-[a-f0-9]{10}$/, 'Set ZEKVAR_TEST_POSTGRES_CONTAINER to the disposable database container.');
const sql = promisify(execFile);

async function call(path, { token = owner, body, method = body === undefined ? 'GET' : 'POST', expect = 200 } = {}) {
  const response = await fetch(`${api}${path}`, {
    method, headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
    body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(5000),
  });
  assert.equal(response.status, expect, `${method} ${path}`);
  const text = await response.text();
  return text ? JSON.parse(text) : undefined;
}

async function database(query) {
  const { stdout } = await sql('docker', ['exec', postgres, 'psql', '-XAtq', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'zekvar', '-c', query]);
  return stdout.trim();
}

test('Chrome enrolled in a deleted organization is rejected and asks to enroll again', { timeout: 90_000 }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'zekvar-organization-deletion-'));
  let context;
  t.after(async () => {
    await context?.close();
    await rm(root, { recursive: true, force: true });
  });
  const dist = join(root, 'extension');
  const env = { ...process.env, ZEKVAR_CONTROL_PORT: new URL(api).port, ZEKVAR_EXTENSION_OUTDIR: dist };
  delete env.ZEKVAR_CONTROL_ORIGIN;
  execFileSync(process.execPath, ['build.mjs'], { cwd: fileURLToPath(new URL('..', import.meta.url)), env });

  const { organization } = await call('/v1/admin/session');
  const [baseline] = await call('/v1/admin/policies');
  const otherPolicies = await call('/v1/admin/policies', { token: other });
  context = await chromium.launchPersistentContext(join(root, 'profile'), {
    channel: 'chromium', headless: process.env.ZEKVAR_DEMO_HEADED !== '1',
    args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`],
  });
  context.setDefaultTimeout(10_000);
  const worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker');
  const popup = await context.newPage();
  await popup.goto(new URL('popup.html', worker.url()).href);
  const { grant } = await call('/v1/admin/enrollment-grants', { body: {} });
  await popup.getByLabel('Enrollment grant', { exact: true }).fill(grant);
  await popup.getByRole('button', { name: 'Enroll this browser', exact: true }).click();
  await popup.getByText(`Connected to Control · ${baseline.mode.toUpperCase()} v${baseline.version}`, { exact: true }).waitFor();
  const [{ installationId }] = await call('/v1/admin/installations');
  const unused = await call('/v1/admin/enrollment-grants', { body: {} });

  const requested = await call('/v1/admin/organization/deletion', { body: { confirmSlug: organization }, expect: 202 });
  await database(`UPDATE organization_deletions SET purge_after = requested_at + interval '1 millisecond' WHERE id = '${requested.deletion.id}'`);
  for (let attempt = 0; attempt < 100; attempt++) {
    if (await database(`SELECT status FROM organization_deletions WHERE id = '${requested.deletion.id}'`) === 'completed') break;
    await delay(200);
  }
  assert.equal(await database(`SELECT status FROM organization_deletions WHERE id = '${requested.deletion.id}'`), 'completed');
  assert.equal(await database(`SELECT count(*) FROM installations WHERE id = '${installationId}'`), '0');
  await call('/v1/admin/session', { expect: 401 });

  await popup.getByRole('button', { name: 'Sync now' }).click();
  await popup.getByText(/Control access revoked/).waitFor();
  await popup.getByRole('button', { name: 'Enroll this browser' }).waitFor();
  // A grant issued before deletion no longer enrolls the browser.
  await popup.getByLabel('Enrollment grant', { exact: true }).fill(unused.grant);
  await popup.getByRole('button', { name: 'Enroll this browser', exact: true }).click();
  await popup.getByText(/invalid, expired, or already used/).waitFor();
  await popup.getByRole('button', { name: 'Enroll this browser' }).waitFor();
  if (process.env.ZEKVAR_DEMO_ARTIFACTS) await popup.screenshot({ path: join(process.env.ZEKVAR_DEMO_ARTIFACTS, '45-deleted-organization-browser.png') });

  const receipt = await fetch(`${api}/v1/organization-deletions/${requested.deletion.id}/receipt`, {
    headers: { Authorization: `Bearer ${requested.receiptToken}` }, signal: AbortSignal.timeout(5000) });
  assert.equal(receipt.status, 200);
  assert.equal((await receipt.json()).receipt.status, 'completed');
  assert.deepEqual(await call('/v1/admin/policies', { token: other }), otherPolicies);
});
