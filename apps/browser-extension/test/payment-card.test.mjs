import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const bundle = await build({
  entryPoints: [fileURLToPath(new URL('../../../contracts/policy/prompt.ts', import.meta.url))],
  bundle: true, format: 'esm', platform: 'node', write: false,
});
const { evaluatePrompt, redactPrompt, paymentCardRule, testMarker } = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString('base64')}`);
const policy = { mode: 'monitor', githubPatMode: 'warn', paymentCardMode: 'block' };
const testCard = '4242424242424242';
const token = 'ghp_' + '0'.repeat(36);

test('detects sandbox card shapes with a valid checksum and supported separators', () => {
  for (const sample of [
    testCard, '4222222222222', '4242 4242 4242 4242', '4242-4242-4242-4242',
    '4242\u00a04242\u00a04242\u00a04242', '4242\u202f4242\u202f4242\u202f4242',
    '5555555555554444', '2222420000001113', '3782 822463 10005', '3782 8224 6310 005',
    '6011111111111117', '3566111111111113', '3852-000002-3237',
  ]) {
    const draft = `Example (“${sample}”), preserve the rest.\nNext line.`;
    const match = evaluatePrompt(draft, policy);
    assert.equal(match.ruleId, paymentCardRule, 'Expected a sandbox card match');
    assert.equal(match.action, 'block');
    assert.equal(redactPrompt(draft, policy), 'Example (“[REDACTED]”), preserve the rest.\nNext line.');
  }
});

test('leaves incomplete, ambiguous, invalid, and embedded numeric tokens unchanged', () => {
  for (const sample of [
    '', '4242', '4242424242424243', '4242 4242 4242 4243', '4242 4242 4242 4242 0123',
    '4242-4242-4242-4242-0123', '4242-4242 4242-4242', '4242\n4242\n4242\n4242',
    '0000000000000000', '6759411100000008', '2026-11-21 03:14:15', '610-555-0123',
    `prefix_${testCard}`, `${testCard}_suffix`, `a${testCard}`, `é${testCard}`, `${testCard}𐐷`,
    `1${testCard}999`, `1-${testCard}`, `${testCard}-1`, '**** **** **** 4242',
  ]) {
    assert.equal(evaluatePrompt(sample, policy).action, 'allow');
    assert.equal(redactPrompt(sample, policy), sample);
  }
});

test('applies detector severity and redacts all enabled matches on a separate retry', () => {
  const draft = `First ${testMarker}, token ${token}, card ${testCard}, other 3782 822463 10005.`;
  for (const paymentCardMode of ['monitor', 'warn', 'block']) {
    const configured = { ...policy, mode: 'warn', paymentCardMode };
    const expectedRule = paymentCardMode === 'monitor' ? 'github-classic-pat' : paymentCardRule;
    assert.equal(evaluatePrompt(draft, configured).ruleId, expectedRule);
    const redacted = redactPrompt(draft, configured);
    assert.equal(redacted, 'First [REDACTED], token [REDACTED], card [REDACTED], other [REDACTED].');
    assert.equal(evaluatePrompt(redacted, configured).action, 'allow');
    assert.equal(redactPrompt(redacted, configured), redacted);
  }
  assert.equal(evaluatePrompt(testCard, { mode: 'block' }).action, 'allow');
  assert.equal(redactPrompt(testCard, { ...policy, paymentCardMode: 'off' }), testCard);
  assert.equal(redactPrompt(testCard + ' ' + testCard, policy), '[REDACTED] [REDACTED]');
});
