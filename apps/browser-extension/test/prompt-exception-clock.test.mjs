import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const bundle = await build({
  entryPoints: [fileURLToPath(new URL('../src/prompt-exceptions.ts', import.meta.url))],
  bundle: true, format: 'esm', platform: 'node', write: false,
});
const { leaseTime, readExceptionLease } = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString('base64')}`);

const serverTimeMs = Date.parse('2026-11-21T07:00:00Z');
const clock = { wallMs: serverTimeMs - 120 * 60_000, monotonicMs: serverTimeMs + 100 };
const grant = { appId: 'chatgpt', ruleId: 'fixture-secret', expiresAtMs: serverTimeMs + 60_000 };
const raw = { serverTimeMs, grants: [grant] };

test('bounds prompt exceptions by elapsed time from the server sample even with a skewed device clock', () => {
  const lease = readExceptionLease(raw, clock);
  const at = (wallMs, monotonicMs) => leaseTime(lease, { wallMs: clock.wallMs + wallMs, monotonicMs: clock.monotonicMs + monotonicMs });
  assert.equal(at(800, 805), serverTimeMs + 805);
  assert.equal(at(44_999, 44_999), serverTimeMs + 44_999);
  assert.equal(at(45_000, 45_000), undefined);
  assert.equal(at(-10, 5000), undefined);
  assert.equal(at(5000, 1000), undefined);
  assert.equal(at(1000, 5000), undefined);
});

test('rejects malformed or overlong prompt exception leases', () => {
  assert.ok(readExceptionLease(raw, clock));
  for (const grants of [
    [], [null], [grant, grant], [{ ...grant, appId: 'local-prompt-fixture' }], [{ ...grant, ruleId: 'ai-file-upload' }],
    [{ ...grant, expiresAtMs: serverTimeMs }], [{ ...grant, expiresAtMs: serverTimeMs + 86_400_001 }],
  ]) assert.equal(readExceptionLease({ serverTimeMs, grants }, clock), undefined);
});
