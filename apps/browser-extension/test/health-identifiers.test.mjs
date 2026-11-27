import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { deaComplete, generator, mbi, npiComplete } from './detection-corpus.mjs';

const result = await build({
  stdin: {
    contents: "export * from './contracts/policy/prompt'; export * from './contracts/policy/file-inspection'; " +
      "export * from './contracts/policy/clipboard'; export * from './contracts/policy/health-identifiers'; " +
      "export * from './contracts/policy/prompt-app-modes'; export * from './contracts/policy/prompt-exceptions';",
    resolveDir: fileURLToPath(new URL('../../..', import.meta.url)),
  },
  bundle: true, platform: 'node', format: 'esm', write: false,
});
const {
  evaluatePrompt, redactPrompt, evaluateFileInspection, fileInspectionDetectors, inspectClipboard, promptPolicyForApp, readHealthProtection,
  sameHealthProtection, healthRules, healthDetector, healthLabels, isExceptionTarget, readPromptExceptions, promptExceptionLimit,
  detectionRuleLabels,
} = await import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0].contents).toString('base64')}`);

// Every identifier below is computed from a seeded generator. None belongs to a real provider, registrant, or patient.
const { pick } = generator(0x4ea1);
const digits = '0123456789';
const npi = npiComplete('1' + pick(digits, 8));
const dea = deaComplete('B' + 'R', pick(digits, 6));
const beneficiary = mbi(pick, true);
const record = pick(digits, 8);
const recordFormats = [{ prefix: 'MRN-', digits: 8 }];
const health = (mode = 'block', formats = recordFormats) => ({ mode: 'monitor', healthProtection: { mode, recordFormats: formats } });
const samples = {
  'us-national-provider-identifier': `Referring provider NPI: ${npi}`,
  'dea-registration-number': `Prescriber DEA # ${dea}`,
  'medicare-beneficiary-identifier': `Medicare ID ${beneficiary}`,
  'medical-record-number': `MRN: ${record}`,
};

test('each health identifier maps to its rule and category, redacts the value only, and stays Off by default', () => {
  assert.deepEqual(Object.keys(samples).sort(), [...healthRules].sort());
  for (const [rule, sample] of Object.entries(samples)) {
    assert.deepEqual(evaluatePrompt(sample, health()), { action: 'block', ruleId: rule, detectorCategory: healthDetector,
      reason: `This prompt contains a possible ${healthLabels[rule]}.` }, rule);
    assert.equal(detectionRuleLabels[rule], healthLabels[rule]);
    assert.equal(redactPrompt(sample, health('warn')).includes('[REDACTED]'), true, rule);
    assert.equal(redactPrompt(`${sample}.`, health('warn')).endsWith('[REDACTED].'), true, rule);
    assert.deepEqual(evaluatePrompt(sample, { mode: 'monitor' }), { action: 'allow' });
    assert.deepEqual(evaluatePrompt(sample, health('off')), { action: 'allow' });
    assert.equal(redactPrompt(sample, health('off')), sample);
  }
  assert.equal(redactPrompt(samples['us-national-provider-identifier'], health()), 'Referring provider NPI: [REDACTED]');
  assert.equal(redactPrompt(`MRN-${record} and MRN: ${record}`, health()), '[REDACTED] and MRN: [REDACTED]');
  const first = `${samples['medicare-beneficiary-identifier']} then ${samples['us-national-provider-identifier']}`;
  assert.equal(evaluatePrompt(first, health()).ruleId, 'medicare-beneficiary-identifier', 'the earliest identifier is reported');
});

test('NPI and DEA values require a label and a valid check digit', () => {
  const wrong = (value) => value.slice(0, -1) + ((Number(value.slice(-1)) + 1) % 10);
  for (const sample of [npi, `Order ${npi}`, `Call ${npi}`, `NPI: ${wrong(npi)}`, `NPI: 3${npi.slice(1)}`, `NPI: ${npi}0`, `xNPI ${npi}`,
    dea, `PO ${dea}`, `DEA: ${wrong(dea)}`, `DEA: ${'Z' + dea.slice(1)}`, `IDEA ${dea}`, `DEA: ${dea}1`,
    `NPI\n${npi}`, `NPI ${'x'.repeat(30)} ${npi}`]) {
    assert.deepEqual(evaluatePrompt(sample, health()), { action: 'allow' }, sample);
  }
  for (const sample of [`npi ${npi}`, `National Provider ID: ${npi}`, `NPI for Dr. Roe is ${npi}`, `"npi": "${npi}"`,
    `dea ${dea.toLowerCase()}`, `DEA registration no. ${dea}`]) {
    assert.notEqual(evaluatePrompt(sample, health()).action, 'allow', sample);
  }
});

test('MBI checks each position, rejects excluded letters and the CMS documentation sample, and needs consistent dashes', () => {
  const plain = beneficiary.replaceAll('-', '');
  assert.equal(evaluatePrompt(plain, health()).ruleId, 'medicare-beneficiary-identifier');
  for (const sample of [plain.toLowerCase(), '0' + plain.slice(1), plain.slice(0, 1) + 'S' + plain.slice(2), plain.slice(0, 4) + '-' + plain.slice(4),
    plain + '7', plain.slice(0, 10), 'x' + plain, '1EG4' + '-TE5-' + 'MK73', '1EG4' + 'TE5' + 'MK73']) {
    assert.deepEqual(evaluatePrompt(sample, health()), { action: 'allow' }, sample);
  }
});

test('health settings validate record formats with the organization identifier rules and compare canonically', () => {
  assert.deepEqual(readHealthProtection({ mode: 'warn', recordFormats: [{ prefix: ' mrn- ', digits: 8 }] }),
    { mode: 'warn', recordFormats: [{ prefix: 'MRN-', digits: 8 }] });
  assert.deepEqual(readHealthProtection({ mode: 'block', recordFormats: [] }), { mode: 'block', recordFormats: [] });
  assert.equal(sameHealthProtection(readHealthProtection({ mode: 'block', recordFormats: [{ prefix: 'B_', digits: 6 }, { prefix: 'MRN-', digits: 8 }] }),
    readHealthProtection({ mode: 'block', recordFormats: [{ prefix: 'MRN-', digits: 8 }, { prefix: 'b_', digits: 6 }] })), true);
  for (const invalid of [null, {}, { mode: 'on', recordFormats: [] }, { mode: 'block' }, { mode: 'block', recordFormats: [{ prefix: 'MRN', digits: 8 }] },
    { mode: 'block', recordFormats: [{ prefix: 'MRN-', digits: 3 }] }, { mode: 'block', recordFormats: [{ prefix: 'MRN-', digits: 8 }, { prefix: 'mrn-', digits: 6 }] },
    { mode: 'block', recordFormats: [], extra: true }]) {
    assert.equal(readHealthProtection(invalid), undefined, JSON.stringify(invalid));
  }
  assert.deepEqual(evaluatePrompt(`MRN: ${record}`, health('block', [])), { action: 'allow' }, 'no formats leaves the MRN rule inactive');
  assert.deepEqual(evaluatePrompt(`MRN: ${record.slice(1)}`, health()), { action: 'allow' }, 'digit count must match a format');
});

test('file content, clipboard, and per-app modes apply health rules with metadata only and no prompt exceptions', () => {
  const policy = health('warn');
  const detectors = fileInspectionDetectors(policy);
  assert.deepEqual(detectors.healthProtection, { mode: 'monitor', recordFormats });
  assert.deepEqual(evaluateFileInspection(`Patient list\n${samples['us-national-provider-identifier']}\n`, detectors),
    { ruleId: 'us-national-provider-identifier', detectorCategory: healthDetector });
  assert.equal(evaluateFileInspection(samples['dea-registration-number'], fileInspectionDetectors({ mode: 'monitor' })), undefined);
  const paste = inspectClipboard(samples['medicare-beneficiary-identifier'], policy, 'block');
  assert.deepEqual(paste, { decision: 'block', ruleId: 'medicare-beneficiary-identifier', detectorCategory: healthDetector });
  assert.equal(JSON.stringify(paste).includes(beneficiary), false);
  assert.equal(promptPolicyForApp(policy, { chatgpt: 'monitor' }, 'chatgpt').healthProtection.mode, 'monitor');
  assert.equal(promptPolicyForApp(health('off'), { gemini: 'block' }, 'gemini').healthProtection.mode, 'off');
  assert.equal(promptExceptionLimit, 21);
  for (const rule of healthRules) {
    assert.equal(isExceptionTarget('chatgpt', rule), false);
    assert.equal(readPromptExceptions([{ appId: 'chatgpt', ruleId: rule, expiresAt: new Date().toISOString(), reason: 'pilot' }]), undefined);
  }
});
