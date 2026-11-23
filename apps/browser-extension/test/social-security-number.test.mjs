import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const result = await build({
  stdin: {
    contents: "export * from './contracts/policy/prompt'; export * from './contracts/policy/file-inspection';",
    resolveDir: fileURLToPath(new URL('../../..', import.meta.url)),
  },
  bundle: true, platform: 'node', format: 'esm', write: false,
});
const { evaluatePrompt, redactPrompt, evaluateFileInspection, fileInspectionDetectors, ssnRule, ssnDetector } =
  await import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0].contents).toString('base64')}`);
const grouped = '899-97-4321';
const spaced = grouped.replaceAll('-', ' ');
const compact = grouped.replaceAll('-', '');
const policy = (ssnMode = 'block') => ({ mode: 'monitor', ssnMode });

test('recognizes standalone hyphenated and explicitly labeled U.S. SSN candidates', () => {
  for (const candidate of [
    `(note: ${grouped}).`, `["${grouped}"]`, `记录 ${grouped}。`, `SSN: ${compact}`,
    `social security number = ${spaced}`, `"sSn": "${compact}"`, `Social Security # ${spaced}`, `Social Security No.\t${compact}`,
  ]) {
    const result = evaluatePrompt(candidate, policy());
    assert.equal(result.action, 'block', candidate);
    assert.equal(result.ruleId, ssnRule);
    assert.equal(result.detectorCategory, ssnDetector);
  }
  const draft = `Compare (${grouped}), "SSN": "${compact}", and Social Security # ${spaced}. Ticket ${compact}.`;
  assert.equal(redactPrompt(draft, policy()),
    `Compare ([REDACTED]), "SSN": "[REDACTED]", and Social Security # [REDACTED]. Ticket ${compact}.`);
});

test('rejects impossible ranges and ambiguous or embedded identifiers', () => {
  for (const candidate of [
    '000-97-4321', '666-97-4321', '900-97-4321', '999-97-4321', '899-00-4321', '899-97-0000',
    'SSN: 899000123', 'SSN: 899 97 0000', 'SSN: 899-97 4321', 'SSN: 899  97  4321',
    compact, spaced, `Account ${compact}`, `SSN\n${compact}`, `SSN${compact}`, `app_SSN: ${compact}`,
    `客户SSN: ${compact}`, `AA-${grouped}`, `${grouped}-01`, `1${grouped}`, `${grouped}0`,
    `é${grouped}`, `${grouped}\u0301`, `SSN: ${compact}A`, '８９９-９７-４３２１',
  ]) {
    assert.deepEqual(evaluatePrompt(candidate, policy()), { action: 'allow' }, candidate);
    assert.equal(redactPrompt(candidate, policy()), candidate);
  }
});

test('uses independent detector modes, honors a prompt exception, and classifies file matches', () => {
  for (const mode of ['monitor', 'warn', 'block']) assert.equal(evaluatePrompt(grouped, policy(mode)).action, mode);
  assert.deepEqual(evaluatePrompt(grouped, policy('off')), { action: 'allow' });
  assert.equal(redactPrompt(grouped, policy('off')), grouped);
  assert.deepEqual(evaluatePrompt(grouped, policy(), new Set([ssnRule])), { action: 'allow' });
  assert.equal(evaluatePrompt(`${grouped} ZEKVAR_TEST_SECRET`, { ...policy('monitor'), mode: 'block' }).ruleId, 'fixture-secret');
  assert.deepEqual(evaluateFileInspection(`SSN: ${compact}`, fileInspectionDetectors(policy('warn'))),
    { ruleId: ssnRule, detectorCategory: ssnDetector });
  assert.equal(evaluateFileInspection(grouped, fileInspectionDetectors(policy('off'))), undefined);
});

test('scans the end of a large draft after repeated near matches', { timeout: 3000 }, () => {
  const draft = `SSN${compact}; ${grouped}-00000. `.repeat(20_000);
  assert.equal(evaluatePrompt(draft, policy()).action, 'allow');
  assert.equal(redactPrompt(draft, policy()), draft);
  assert.equal(evaluatePrompt(`${draft}SSN: ${compact}`, policy()).ruleId, ssnRule);
});
