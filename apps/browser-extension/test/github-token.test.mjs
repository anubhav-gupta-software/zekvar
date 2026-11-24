import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const result = await build({
  stdin: {
    contents: "export * from './contracts/policy/prompt'; export * from './contracts/policy/file-inspection'; export * from './contracts/policy/clipboard';",
    resolveDir: fileURLToPath(new URL('../../..', import.meta.url)),
  },
  bundle: true, platform: 'node', format: 'esm', write: false,
});
const { evaluatePrompt, redactPrompt, evaluateFileInspection, fileInspectionDetectors, inspectClipboard, githubTokenRule, credentialDetector } =
  await import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0].contents).toString('base64')}`);

const fineGrained = `github_pat_${'F'.repeat(22)}_${'0'.repeat(59)}`;
const stateless = `ghs_900001_${'A'.repeat(30)}.${'a-_'.repeat(128)}.${'Z'.repeat(87)}`;
const opaque = ['gho', 'ghu', 'ghs', 'ghr'].map((prefix) => `${prefix}_${'0'.repeat(36)}`);
const classic = `ghp_${'0'.repeat(36)}`;
const policy = { mode: 'monitor', githubTokenMode: 'block' };
const metadata = { ruleId: githubTokenRule, detectorCategory: credentialDetector };

test('recognizes every supported nonclassic format and redacts complete matches with delimiters intact', () => {
  const tokens = [fineGrained, stateless, ...opaque, `ghr_${'T'.repeat(76)}`];
  for (const token of tokens) {
    const sample = `Start “${token}” and [${token}]. ${token}.`;
    const detected = evaluatePrompt(sample, policy);
    assert.equal(detected.action, 'block');
    assert.equal(detected.ruleId, githubTokenRule);
    assert.equal(detected.detectorCategory, credentialDetector);
    assert.equal(redactPrompt(sample, policy), 'Start “[REDACTED]” and [[REDACTED]]. [REDACTED].');
  }
});

test('ignores short, malformed, unprefixed and embedded candidates and leaves the classic rule independent', () => {
  const negatives = [
    classic, fineGrained.slice(0, -1), fineGrained.replace('_F', 'F'), fineGrained.toUpperCase(),
    opaque[0].slice(0, -1), `ghs_${'1'.repeat(37)}`, `ghu_${'1'.repeat(256)}`, stateless.slice(4),
    stateless.replace('.', ''), `${stateless}.extra`, `${stateless.slice(0, stateless.lastIndexOf('.'))}.A`,
    `embedded_${fineGrained}`, `${fineGrained}_suffix`, `字${opaque[0]}`, `${opaque[0]}\u0301`,
  ];
  for (const sample of negatives) {
    assert.equal(evaluatePrompt(sample, policy).action, 'allow');
    assert.equal(redactPrompt(sample, policy), sample);
  }
  assert.equal(evaluatePrompt(classic, { ...policy, githubPatMode: 'warn' }).ruleId, 'github-classic-pat');
});

test('applies each mode, redaction, prompt exceptions and independent clipboard and attachment action modes', () => {
  for (const mode of ['monitor', 'warn', 'block']) assert.equal(evaluatePrompt(fineGrained, { ...policy, githubTokenMode: mode }).action, mode);
  const off = { ...policy, githubTokenMode: 'off' };
  assert.equal(evaluatePrompt(fineGrained, off).action, 'allow');
  assert.equal(redactPrompt(fineGrained, off), fineGrained);
  assert.equal(evaluatePrompt(fineGrained, policy, new Set([githubTokenRule])).action, 'allow');
  assert.equal(evaluatePrompt(`${fineGrained} ${classic}`, { ...policy, githubPatMode: 'block' }, new Set([githubTokenRule])).ruleId, 'github-classic-pat');
  assert.deepEqual(evaluateFileInspection(stateless, fileInspectionDetectors(policy)), metadata);
  assert.equal(evaluateFileInspection(stateless, fileInspectionDetectors(off)), undefined);
  assert.deepEqual(inspectClipboard(fineGrained, { ...policy, githubTokenMode: 'warn' }, 'block'), { decision: 'block', ...metadata });
  assert.equal(inspectClipboard(fineGrained, off, 'block'), undefined);
});

test('scans a long draft with repeated malformed token prefixes', { timeout: 3000 }, () => {
  const draft = `ghs_01_AAAAAAAA.AAAAAAAAAAAAA.A; github_pat_0_0; `.repeat(10_000);
  assert.equal(evaluatePrompt(draft, policy).action, 'allow');
  assert.equal(evaluatePrompt(`${draft}${stateless}`, policy).ruleId, githubTokenRule);
  assert.equal(redactPrompt(`${draft}${stateless}`, policy), `${draft}[REDACTED]`);
});
