import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const bundle = await build({ entryPoints: [fileURLToPath(new URL('../src/file-inspection.ts', import.meta.url))],
  bundle: true, format: 'esm', platform: 'node', write: false });
const { inspectFiles } = await import(`data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString('base64')}`);
const marker = 'ZEKVAR_TEST_SECRET';
const pat = `ghp_${'0'.repeat(36)}`;
const key = ['-----BEGIN PRIVATE KEY-----', 'A'.repeat(64), '-----END PRIVATE KEY-----'].join('\n');
const policy = { mode: 'block', githubPatMode: 'warn', paymentCardMode: 'off', privateKeyMode: 'block' };
const make = (content, name = 'synthetic.txt', type = 'text/plain') => new File([content], name, { type });

test('reads UTF-8 bytes independently of upload names and declared media types', async () => {
  assert.deepEqual(await inspectFiles([make(`\ufeffsample\n${marker}`, 'image.png', 'image/png')], policy),
    { ruleId: 'fixture-secret', detectorCategory: 'synthetic-secret' });
  assert.deepEqual(await inspectFiles([make(key, 'report.dat', '')], policy), { ruleId: 'pem-private-key', detectorCategory: 'credential' });
  assert.deepEqual(await inspectFiles([make(pat)], policy), { ruleId: 'github-classic-pat', detectorCategory: 'credential' });
  assert.equal(await inspectFiles([make('4242 4242 4242 4242')], policy), undefined);
  assert.equal(await inspectFiles([make(key)], { ...policy, privateKeyMode: 'off' }), undefined);
});

test('skips binary, empty, unreadable, malformed, and oversized files', async () => {
  class Unreadable extends File {
    async arrayBuffer() { throw new Error('Synthetic read error'); }
  }
  const files = [make(`%PDF-1.7\n${marker}`), make(`${marker}\u0000`), make(Buffer.concat([Buffer.from([0xff]), Buffer.from(marker)])),
    make(''), make(`${marker}${'A'.repeat(256 * 1024)}`), new Unreadable([marker], 'unreadable.txt')];
  assert.equal(await inspectFiles(files, policy), undefined);
  assert.equal((await inspectFiles([...files, make(marker)], policy)).ruleId, 'fixture-secret');
});

test('bounds each batch and chooses one strongest match across its inspected files', async () => {
  assert.equal((await inspectFiles([make(marker), make(pat), make(key)], policy)).ruleId, 'pem-private-key');
  const bigClean = make('X'.repeat(256 * 1024));
  assert.equal(await inspectFiles([...Array(4).fill(bigClean), make(marker)], policy), undefined);
  assert.equal(await inspectFiles([...Array(16).fill(make('clean')), make(marker)], policy), undefined);
  assert.equal((await inspectFiles([make('X'.repeat(256 * 1024 - marker.length) + marker)], policy)).ruleId, 'fixture-secret');
});
