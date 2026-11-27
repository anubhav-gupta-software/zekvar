import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readdir, rm, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const pilot = fileURLToPath(new URL('../../../deploy/pilot/', import.meta.url));
const run = promisify(execFile);
const script = (name, args, env = {}) => run('bash', [join(pilot, name), ...args], { env: { PATH: process.env.PATH, ...env } });

test('database-backup.sh prunes only encrypted archives older than the retention period', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'zekvar-prune-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const old = new Date(Date.now() - 31 * 86_400_000);
  for (const [name, time] of [['old.age', old], ['recent.age', new Date()], ['old.txt', old]]) {
    await writeFile(join(directory, name), 'synthetic');
    await utimes(join(directory, name), time, time);
  }
  const { stdout } = await script('database-backup.sh', ['prune', directory, '30']);
  assert.match(stdout, /Pruned 1 encrypted backups older than 30 days/);
  assert.deepEqual((await readdir(directory)).sort(), ['old.txt', 'recent.age']);
  for (const days of ['0', '3651', 'x']) await assert.rejects(script('database-backup.sh', ['prune', directory, days]), /retention period/);
});

test('s3-backup.sh prints a lifecycle rule that expires archives under the prefix', async () => {
  const env = { ZEKVAR_BACKUP_BUCKET: 'zekvar-backups', ZEKVAR_BACKUP_BUCKET_OWNER: '123456789012', ZEKVAR_BACKUP_PREFIX: 'pilot/control' };
  const { stdout } = await script('s3-backup.sh', ['lifecycle', '35'], env);
  const [rule] = JSON.parse(stdout).Rules;
  assert.deepEqual(rule.Filter, { Prefix: 'pilot/control/' });
  assert.deepEqual(rule.Expiration, { Days: 35 });
  assert.equal(rule.Status, 'Enabled');
  await assert.rejects(script('s3-backup.sh', ['lifecycle', '0'], env), /retention period/);
});

test('organization-deletion.sh verifies a downloaded receipt signature and rejects an altered one', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'zekvar-receipt-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const key = randomBytes(32).toString('hex');
  const receipt = { version: 1, type: 'zekvar.organization_deletion_receipt', deletionId: randomUUID(), organizationId: randomUUID(),
    status: 'completed', tables: [{ table: 'security_events', rows: 3 }], totalRows: 3 };
  const value = createHmac('sha256', Buffer.from(key, 'hex')).update(JSON.stringify(receipt)).digest('hex');
  const file = join(directory, 'receipt.json');
  // Pretty-printing the file must not matter: the signature covers the compact form.
  await writeFile(file, JSON.stringify({ receipt, signature: { algorithm: 'HMAC-SHA256', keyId: 'x', value } }, null, 2));
  const { stdout } = await script('organization-deletion.sh', ['verify-file', file], { ZEKVAR_DELETION_RECEIPT_KEY: key });
  assert.match(stdout, new RegExp(`Receipt signature verified deletion=${receipt.deletionId}`));
  await writeFile(file, JSON.stringify({ receipt: { ...receipt, totalRows: 2 }, signature: { algorithm: 'HMAC-SHA256', value } }));
  await assert.rejects(script('organization-deletion.sh', ['verify-file', file], { ZEKVAR_DELETION_RECEIPT_KEY: key }), /altered/);
  await assert.rejects(script('organization-deletion.sh', ['verify-file', file], { ZEKVAR_DELETION_RECEIPT_KEY: 'short' }), /receipt key/);
});
