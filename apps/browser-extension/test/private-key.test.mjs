import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const bundle = await build({
  entryPoints: [fileURLToPath(new URL('../../../contracts/policy/prompt-exceptions.ts', import.meta.url)),
    fileURLToPath(new URL('../../../contracts/policy/prompt.ts', import.meta.url))],
  bundle: true, format: 'esm', platform: 'node', write: false, outdir: 'test-bundle',
});
const load = (filename) => import(`data:text/javascript;base64,${Buffer.from(bundle.outputFiles
  .find(({ path }) => path.endsWith(`/${filename}.js`)).contents).toString('base64')}`);
const { evaluatePrompt, redactPrompt, privateKeyRule, testMarker } = await load('prompt');
const { evaluatePromptWithExceptions } = await load('prompt-exceptions');
const policy = { mode: 'monitor', privateKeyMode: 'block' };
const key = (label, separator = '\n', payload = 'A'.repeat(64)) =>
  [`-----BEGIN ${label}-----`, payload, `-----END ${label}-----`].join(separator);

test('recognizes private key boundaries with native and JSON-escaped line breaks', () => {
  for (const label of ['PRIVATE KEY', 'ENCRYPTED PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY', 'DSA PRIVATE KEY', 'OPENSSH PRIVATE KEY']) {
    for (const separator of ['\n', '\r\n', '\r', '\\n', '\\r\\n']) {
      const draft = `before "${key(label, separator, `  ${'A'.repeat(60)}${separator} AA==`)}" after`;
      assert.equal(evaluatePrompt(draft, policy).ruleId, privateKeyRule);
      assert.equal(redactPrompt(draft, policy), 'before "[REDACTED]" after');
    }
  }
  const encrypted = key('RSA PRIVATE KEY', '\n', `Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,${'A'.repeat(32)}\n\n${'B'.repeat(64)}`);
  assert.equal(evaluatePrompt(encrypted, policy).action, 'block');
  assert.equal(redactPrompt(encrypted, policy), '[REDACTED]');
  const json = JSON.stringify({ private_key: key('PRIVATE KEY'), text: 'Safe adjacent text' });
  assert.deepEqual(JSON.parse(redactPrompt(json, policy)), { private_key: '[REDACTED]', text: 'Safe adjacent text' });
});

test('leaves public material, placeholders, and damaged blocks alone', () => {
  for (const draft of [key('PUBLIC KEY'), key('CERTIFICATE'), key('PGP PRIVATE KEY BLOCK'), key('PRIVATE KEY', ' '),
    key('PRIVATE KEY', '\n', '<put key here>'), key('PRIVATE KEY', '\n', 'AA=='), key('PRIVATE KEY', '\n', 'A'.repeat(45)),
    key('PRIVATE KEY', '\n', 'A==AAAAA'.repeat(12)), key('PRIVATE KEY').replace('END PRIVATE KEY', 'END CERTIFICATE'),
    key('PRIVATE KEY').split('\n').slice(0, 2).join('\n'), 'Example text -----BEGIN PRIVATE KEY-----\n']) {
    assert.equal(evaluatePrompt(draft, policy).action, 'allow');
    assert.equal(redactPrompt(draft, policy), draft);
  }
});

test('applies independent modes, grants, precedence, and whole-block redaction', () => {
  const draft = key('PRIVATE KEY');
  for (const action of ['monitor', 'warn', 'block']) {
    assert.deepEqual(evaluatePrompt(draft, { ...policy, privateKeyMode: action }), {
      action, ruleId: privateKeyRule, detectorCategory: 'credential', reason: 'This prompt contains text that looks like a private key.',
    });
  }
  assert.equal(evaluatePrompt(draft, { ...policy, privateKeyMode: 'off' }).action, 'allow');
  assert.equal(redactPrompt(draft, { mode: 'monitor' }), draft);
  const mixed = `${testMarker}\n${draft}\nsecond ${key('OPENSSH PRIVATE KEY', '\\n')}`;
  assert.equal(evaluatePrompt(mixed, { ...policy, mode: 'warn' }).ruleId, privateKeyRule);
  const grants = new Set([privateKeyRule]);
  assert.equal(evaluatePromptWithExceptions(draft, policy, grants).exception?.ruleId, privateKeyRule);
  assert.equal(evaluatePromptWithExceptions(mixed, { ...policy, mode: 'warn' }, grants).match.action, 'warn');
  assert.equal(redactPrompt(mixed, policy), '[REDACTED]\n[REDACTED]\nsecond [REDACTED]');
});

test('recovers after many unmatched headers and preserves surrounding text', () => {
  const prefix = '-----BEGIN PRIVATE KEY-----\n'.repeat(10_000);
  assert.equal(redactPrompt(`${prefix}${key('EC PRIVATE KEY')}\nnotes`, policy), `${prefix}[REDACTED]\nnotes`);
});
