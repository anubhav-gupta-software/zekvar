import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { generator, prefixes } from './detection-corpus.mjs';

const result = await build({
  stdin: {
    contents: "export * from './contracts/policy/prompt'; export * from './contracts/policy/file-inspection'; " +
      "export * from './contracts/policy/clipboard'; export * from './contracts/policy/classification'; " +
      "export * from './contracts/policy/cloud-credentials'; export * from './contracts/policy/prompt-app-modes'; " +
      "export * from './contracts/policy/prompt-exceptions';",
    resolveDir: fileURLToPath(new URL('../../..', import.meta.url)),
  },
  bundle: true, platform: 'node', format: 'esm', write: false,
});
const {
  evaluatePrompt, redactPrompt, evaluateFileInspection, fileInspectionDetectors, inspectClipboard, promptPolicyForApp,
  readClassificationProtection, sameClassificationProtection, parseClassificationTerms, classificationRule, classificationDetector,
  credentialDetector, cloudCredentialRules, isExceptionTarget, readPromptExceptions, promptExceptionLimit, detectionRuleLabels,
} = await import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0].contents).toString('base64')}`);

const { pick } = generator(0xc10d);
const alnum = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const keys = {
  'aws-access-key-id': prefixes.aws + pick('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', 16),
  'slack-token': `${prefixes.slackBot}${pick('0123456789', 11)}-${pick('0123456789', 12)}-${pick(alnum, 24)}`,
  'stripe-live-secret-key': prefixes.stripeRestricted + pick(alnum, 40),
  'google-api-key': prefixes.google + pick(alnum + '_-', 35),
  'openai-api-key': prefixes.openAiProject + pick(alnum, 60) + prefixes.openAiMarker + pick(alnum, 60),
  'anthropic-api-key': prefixes.anthropic + pick(alnum + '_-', 93) + 'AA',
};
const cloud = (mode = 'block') => ({ mode: 'monitor', cloudCredentialMode: mode });
const terms = ['CONFIDENTIAL – INTERNAL', 'Project Bluebird', 'A&B/Q3 plan'];
const classified = (mode = 'block') => ({ mode: 'monitor', classificationProtection: readClassificationProtection({ mode, terms }) });

test('each cloud credential maps to its provider rule, redacts with delimiters intact, and stays Off by default', () => {
  assert.deepEqual(Object.keys(keys).sort(), [...cloudCredentialRules].sort());
  for (const [rule, key] of Object.entries(keys)) {
    const sample = `Use “${key}” or (${key}).`;
    assert.deepEqual(evaluatePrompt(sample, cloud()), { action: 'block', ruleId: rule, detectorCategory: credentialDetector,
      reason: `This prompt contains text that looks like ${/^[AEIOU]/.test(detectionRuleLabels[rule]) ? 'an' : 'a'} ${detectionRuleLabels[rule]}.` });
    assert.equal(redactPrompt(sample, cloud('warn')), 'Use “[REDACTED]” or ([REDACTED]).');
    assert.deepEqual(evaluatePrompt(sample, { mode: 'monitor' }), { action: 'allow' });
    assert.deepEqual(evaluatePrompt(sample, cloud('off')), { action: 'allow' });
    assert.equal(redactPrompt(sample, cloud('off')), sample);
    assert.deepEqual(evaluatePrompt(`é${key}`, cloud()), { action: 'allow' }, `${rule} embedded on the left`);
    assert.deepEqual(evaluatePrompt(`${key}é`, cloud()), { action: 'allow' }, `${rule} embedded on the right`);
  }
  const first = `${keys['google-api-key']} then ${keys['aws-access-key-id']}`;
  assert.equal(evaluatePrompt(first, cloud()).ruleId, 'google-api-key');
  assert.equal(redactPrompt(first, cloud()), '[REDACTED] then [REDACTED]');
});

test('placeholder and documentation keys are not credentials', () => {
  for (const sample of [prefixes.aws + 'X'.repeat(16), prefixes.aws + 'IOSFODNN7' + 'EXAMPLE', prefixes.stripeSecret + 'x'.repeat(24),
    prefixes.google + 'A'.repeat(35), `${prefixes.slackBot}${'1'.repeat(11)}-${'2'.repeat(12)}-${'ab'.repeat(12)}`,
    prefixes.stripeTest + pick(alnum, 40), prefixes.stripePublishable + pick(alnum, 40)]) {
    assert.deepEqual(evaluatePrompt(sample, cloud()), { action: 'allow' }, sample.slice(0, 8));
    assert.equal(redactPrompt(sample, cloud()), sample);
  }
});

test('classification terms normalize, reject unsafe or unbounded input, and compare canonically', () => {
  const settings = readClassificationProtection({ mode: 'warn', terms: ['  project   bluebird ', 'CONFIDENTIAL – INTERNAL'] });
  assert.deepEqual(settings, { mode: 'warn', terms: ['CONFIDENTIAL – INTERNAL', 'project bluebird'] });
  assert.deepEqual(parseClassificationTerms('Project Bluebird\r\n\r\nRestricted\tDistribution'), ['Project Bluebird', 'Restricted Distribution']);
  assert.equal(sameClassificationProtection(settings, readClassificationProtection({ mode: 'warn', terms: [...settings.terms].reverse() })), true);
  assert.equal(sameClassificationProtection(settings, readClassificationProtection({ mode: 'block', terms: settings.terms })), false);
  assert.deepEqual(readClassificationProtection({ mode: 'off', terms: [] }), { mode: 'off', terms: [] });
  for (const invalid of [
    null, {}, { mode: 'on', terms }, { mode: 'warn', terms: [] }, { mode: 'off', terms: [null] }, { mode: 'off', terms: 'Bluebird' },
    { mode: 'block', terms: ['ab'] }, { mode: 'block', terms: ['a-b'] }, { mode: 'block', terms: ['x'.repeat(65)] },
    { mode: 'block', terms: ['Bluebird', 'BLUEBIRD'] }, { mode: 'block', terms: ['(secret|.*)'] }, { mode: 'block', terms: ['Ünïcode label'] },
    { mode: 'block', terms: ['line\nbreak'] }, { mode: 'block', terms: Array.from({ length: 17 }, (_, index) => `Label ${index}`) },
    { mode: 'block', terms, extra: true },
  ]) assert.equal(readClassificationProtection(invalid), undefined, JSON.stringify(invalid));
  assert.equal(readClassificationProtection({ mode: 'block', terms: Array.from({ length: 16 }, (_, index) => `Label ${index}`) }).terms.length, 16);
});

test('classification rules match whole words and phrases without case, spacing, or dash sensitivity', () => {
  for (const sample of ['Header: CONFIDENTIAL – INTERNAL', 'confidential-internal memo', 'Confidential —\ninternal', 'see project  BLUEBIRD.',
    '“Project Bluebird”', 'the a&b/q3 plan draft']) {
    assert.deepEqual(evaluatePrompt(sample, classified()), { action: 'block', ruleId: classificationRule, detectorCategory: classificationDetector,
      reason: 'This prompt contains a label or phrase your organization classifies as sensitive.' }, sample);
  }
  for (const sample of ['confidential internal', 'Project Bluebirds', 'ProjectBluebird', 'bluebird project', 'xProject Bluebird',
    'CONFIDENTIAL', 'a&b/q3 planning']) {
    assert.deepEqual(evaluatePrompt(sample, classified()), { action: 'allow' }, sample);
  }
  assert.equal(redactPrompt('Re: Project Bluebird, CONFIDENTIAL-INTERNAL.', classified('warn')), 'Re: [REDACTED], [REDACTED].');
  assert.equal(redactPrompt('Re: Project Bluebird', classified('off')), 'Re: Project Bluebird');
});

test('file content, clipboard, and per-app prompt modes apply both new rules and return metadata only', () => {
  const policy = { mode: 'monitor', cloudCredentialMode: 'warn', classificationProtection: readClassificationProtection({ mode: 'block', terms }) };
  const detectors = fileInspectionDetectors(policy);
  assert.equal(detectors.cloudCredentialMode, 'monitor');
  assert.deepEqual(detectors.classificationProtection, { mode: 'monitor', terms: policy.classificationProtection.terms });
  assert.deepEqual(evaluateFileInspection(`notes\n${keys['slack-token']}\n`, detectors), { ruleId: 'slack-token', detectorCategory: credentialDetector });
  assert.deepEqual(evaluateFileInspection('Project Bluebird roadmap', detectors), { ruleId: classificationRule, detectorCategory: classificationDetector });
  assert.equal(evaluateFileInspection('Project Bluebird roadmap', fileInspectionDetectors({ mode: 'monitor' })), undefined);
  const paste = inspectClipboard(`key ${keys['anthropic-api-key']}`, policy, 'block');
  assert.deepEqual(paste, { decision: 'block', ruleId: 'anthropic-api-key', detectorCategory: credentialDetector });
  assert.equal(JSON.stringify(paste).includes(keys['anthropic-api-key'].slice(10)), false);
  const scoped = promptPolicyForApp(policy, { chatgpt: 'monitor' }, 'chatgpt');
  assert.equal(scoped.cloudCredentialMode, 'monitor');
  assert.equal(scoped.classificationProtection.mode, 'monitor');
  assert.equal(promptPolicyForApp({ mode: 'monitor', cloudCredentialMode: 'off' }, { gemini: 'block' }, 'gemini').cloudCredentialMode, 'off');
  const both = evaluatePrompt(`Project Bluebird ${keys['openai-api-key']}`, policy);
  assert.equal(both.ruleId, classificationRule, 'the stronger action wins');
});

test('temporary prompt exceptions keep the earlier rule set and limit', () => {
  assert.equal(promptExceptionLimit, 21);
  for (const rule of [...cloudCredentialRules, classificationRule]) {
    assert.equal(isExceptionTarget('chatgpt', rule), false);
    assert.equal(readPromptExceptions([{ appId: 'chatgpt', ruleId: rule, expiresAt: new Date().toISOString(), reason: 'pilot' }]), undefined);
  }
  assert.equal(isExceptionTarget('chatgpt', 'us-social-security-number'), true);
});
