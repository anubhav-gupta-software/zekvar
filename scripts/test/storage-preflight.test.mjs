// Exercises deploy/pilot/storage-preflight.sh with stub uname, stat, docker, findmnt, and lsblk commands.
// A real Linux host check is still required; see deploy/pilot/README.md.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('../../deploy/pilot/storage-preflight.sh', import.meta.url));
const key = 'a'.repeat(64);

async function preflight({ os = 'Linux', mode = '600', env = `ZEKVAR_DATA_KEYS=k1=${key}\n`, volume = '/var/lib/docker/volumes/p_postgres_data/_data',
  source = '/dev/mapper/data', types = 'part\ncrypt\ndisk', args = [] } = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'zekvar-storage-'));
  try {
    const stub = async (name, body) => {
      await writeFile(join(directory, name), `#!/usr/bin/env bash\n${body}\n`);
      await chmod(join(directory, name), 0o755);
    };
    await stub('uname', `echo ${os}`);
    await stub('stat', `echo ${mode}`);
    await stub('docker', volume ? `echo '${volume}'` : 'exit 1');
    await stub('findmnt', `echo '${source}'`);
    await stub('lsblk', `printf '${types}\\n'`);
    const envFile = join(directory, 'pilot.env');
    await writeFile(envFile, env);
    return await new Promise((resolve) => execFile('bash', [script, 'p', envFile, ...args],
      { env: { PATH: `${directory}:/usr/bin:/bin` } }, (error, stdout) => resolve({ code: error?.code ?? 0, result: JSON.parse(stdout) })));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test('passes only when the PostgreSQL volume is on a dm-crypt device', async () => {
  const passed = await preflight();
  assert.deepEqual([passed.code, passed.result.status, passed.result.encryption, passed.result.device], [0, 'pass', 'dm-crypt', '/dev/mapper/data']);
  const btrfs = await preflight({ source: '/dev/mapper/data[/@docker]' });
  assert.equal(btrfs.result.device, '/dev/mapper/data');
  const plain = await preflight({ source: '/dev/nvme0n1p1', types: 'part\ndisk' });
  assert.deepEqual([plain.code, plain.result.check], [1, 'encryption']);
  const network = await preflight({ source: 'nfs.example:/export' });
  assert.deepEqual([network.code, network.result.check], [1, 'device']);
});

test('accepts provider encryption only as an explicit attestation', async () => {
  const attested = await preflight({ source: '/dev/nvme1n1', types: 'disk', args: ['--provider-encrypted', 'aws-ebs:vol-0abc/kms:alias/zekvar'] });
  assert.deepEqual([attested.code, attested.result.status, attested.result.reference], [0, 'attested', 'aws-ebs:vol-0abc/kms:alias/zekvar']);
  const unsafe = await preflight({ args: ['--provider-encrypted', 'bad"quote'] });
  assert.deepEqual([unsafe.code, unsafe.result.check], [1, 'usage']);
});

test('requires Linux, a private environment file, data keys, and an existing volume', async () => {
  for (const [options, check] of [[{ os: 'Darwin' }, 'platform'], [{ mode: '644' }, 'env_file'], [{ env: 'ZEKVAR_OWNER_TOKEN=x\n' }, 'data_keys'],
    [{ env: 'ZEKVAR_DATA_KEYS=k1=short\n' }, 'data_keys'], [{ volume: '' }, 'volume']]) {
    const { code, result } = await preflight(options);
    assert.deepEqual([code, result.status, result.check], [1, 'fail', check]);
  }
});
