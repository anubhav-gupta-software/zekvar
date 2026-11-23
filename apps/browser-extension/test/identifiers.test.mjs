import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const result = await build({
  stdin: {
    contents: "export * from './contracts/policy/prompt'; export * from './contracts/policy/organization-identifiers'; export * from './contracts/policy/file-inspection';",
    resolveDir: fileURLToPath(new URL('../../..', import.meta.url)),
  },
  bundle: true, platform: 'node', format: 'esm', write: false,
});
const {
  evaluatePrompt, evaluateFileInspection, fileInspectionDetectors, identifierRule, parseIdentifierFormats,
  readIdentifierProtection, redactPrompt, sameIdentifierProtection,
} = await import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0].contents).toString('base64')}`);
const formats = [{ prefix: 'CUST-', digits: 8 }, { prefix: 'CASE_', digits: 6 }];
const policy = (mode = 'block') => ({ mode: 'monitor', identifierProtection: readIdentifierProtection({ mode, formats }) });

test('normalizes prefix formats and rejects malformed, duplicate, and unbounded rules', () => {
  const settings = readIdentifierProtection({ mode: 'warn', formats: [{ prefix: '  cust- ', digits: 8 }, formats[1]] });
  assert.deepEqual(settings, { mode: 'warn', formats: [...formats].reverse() });
  assert.deepEqual(parseIdentifierFormats(' cust- 8\r\n\r\nCASE_\t6'), settings.formats);
  assert.equal(sameIdentifierProtection(settings, readIdentifierProtection({ mode: 'warn', formats })), true);
  for (const invalid of [
    null, {}, { mode: 'on', formats }, { mode: 'warn', formats: [] }, { mode: 'off', formats: [null] },
    { mode: 'off', formats: [...formats, { prefix: 'cust-', digits: 6 }] },
    { mode: 'off', formats: ['CUST- 8'] }, { mode: 'block', formats: [{ prefix: 'A.*-', digits: 8 }] },
    { mode: 'block', formats: [{ prefix: 'B-', digits: 8 }] }, { mode: 'block', formats: [{ prefix: 'KEY-', digits: 8 }] },
    { mode: 'block', formats: [{ prefix: 'CUST-', digits: 3 }] }, { mode: 'block', formats: [{ prefix: 'CUST-', digits: 13 }] },
    { mode: 'block', formats: [{ prefix: 'CUST-', digits: 8, example: 'CUST-00000000' }] },
    { mode: 'block', formats: Array.from({ length: 17 }, (_, index) => ({ prefix: `R${index}-`, digits: 4 })) },
  ]) assert.equal(readIdentifierProtection(invalid), undefined);
});

test('matches exact ASCII digits and handles Unicode surrounding text and punctuation', () => {
  for (const match of ['(cust-01234567)', 'case_001234;', '客户 CUST-01234567。', 'case_001234\nCUST-01234567', 'CUST-00000000']) {
    assert.deepEqual(evaluatePrompt(match, policy()), { action: 'block', ruleId: identifierRule,
      detectorCategory: 'internal-identifier', reason: 'This prompt contains an organization identifier.' });
  }
  for (const near of ['CUST-1234567', 'CUST-123456789', 'CUST-01234567A', 'xCUST-01234567', '客户CUST-01234567',
    'CUST-01234567-archive', 'CUST-01234567_2', 'CUST-01234567\u0301', 'CUST-０１２３４５６７', 'CUſT-01234567', 'CASE-001234']) {
    assert.equal(evaluatePrompt(near, policy()).action, 'allow', near);
  }
  assert.equal(evaluatePrompt('CUST-01234567', policy('off')).action, 'allow');
});

test('applies severity and exception precedence and preserves the rest of a redacted draft', () => {
  const draft = 'Compare (CUST-01234567), CASE_001234 and CASE_001235. Keep CUST-123.';
  assert.equal(redactPrompt(draft, policy()),
    'Compare ([REDACTED]), [REDACTED] and [REDACTED]. Keep CUST-123.');
  const mixed = `CUST-01234567 ghp_${'A'.repeat(36)}`;
  assert.equal(evaluatePrompt(mixed, { ...policy('warn'), githubPatMode: 'block' }).ruleId, 'github-classic-pat');
  assert.equal(evaluatePrompt(mixed, { ...policy(), githubPatMode: 'monitor' }).ruleId, identifierRule);
  assert.equal(evaluatePrompt(mixed, { ...policy(), githubPatMode: 'warn' }, new Set([identifierRule])).ruleId, 'github-classic-pat');
  assert.equal(redactPrompt(draft, policy('off')), draft);
  assert.deepEqual(evaluateFileInspection('CUST-01234567', fileInspectionDetectors(policy('warn'))),
    { ruleId: identifierRule, detectorCategory: 'internal-identifier' });
  assert.equal(evaluateFileInspection('CUST-01234567', fileInspectionDetectors(policy('off'))), undefined);
});

test('keeps a full set of formats bounded on large drafts with repeated near matches', { timeout: 3000 }, () => {
  const protection = { mode: 'block', formats: Array.from({ length: 16 }, (_, index) => ({ prefix: `CASE${index}-`, digits: 12 })) };
  const text = 'CASE15-1234567890123 CASE10-12345678901 '.repeat(20_000);
  const current = { mode: 'monitor', identifierProtection: readIdentifierProtection(protection) };
  assert.equal(evaluatePrompt(text, current).action, 'allow');
  assert.equal(redactPrompt(text, current), text);
  assert.equal(evaluatePrompt(text + 'CASE15-123456789012', current).ruleId, identifierRule);
});
