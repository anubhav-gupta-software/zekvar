import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { buildCorpus, classificationTerms, detectors, identifierFormats, prefixes, recordFormats } from './detection-corpus.mjs';

const result = await build({
  stdin: {
    contents: "export * from './contracts/policy/prompt'; export * from './contracts/policy/file-inspection';",
    resolveDir: fileURLToPath(new URL('../../..', import.meta.url)),
  },
  bundle: true, platform: 'node', format: 'esm', write: false,
});
const { evaluatePrompt, evaluateFileInspection, fileInspectionDetectors } =
  await import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0].contents).toString('base64')}`);

// Gates for enabling enforcement in a pilot. A drop below these values fails `npm test`.
const thresholds = { precision: 0.99, recall: 0.95 };
const corpus = buildCorpus();

function measure(detector, evaluate) {
  const counts = { tp: 0, fp: 0, fn: 0, tn: 0, falseBlocks: [] };
  for (const sample of corpus) {
    const expected = detector.rules.includes(sample.rule);
    const match = evaluate(sample.text, { mode: 'monitor', ...detector.policy });
    const found = match && match.action !== 'allow' && detector.rules.includes(match.ruleId) ? match.ruleId : undefined;
    // A cloud credential or health identifier reported under the wrong rule of its setting counts against both rows.
    const misattributed = detector.grouped && match && match.action !== 'allow' && !found && expected;
    if (expected && found) counts.tp++;
    else if (expected) counts.fn++;
    else if (found) {
      counts.fp++;
      counts.falseBlocks.push(sample.kind ?? sample.rule);
    } else counts.tn++;
    if (misattributed) counts.falseBlocks.push(`misattributed ${match.ruleId}`);
  }
  const precision = counts.tp + counts.fp ? counts.tp / (counts.tp + counts.fp) : 1;
  const recall = counts.tp + counts.fn ? counts.tp / (counts.tp + counts.fn) : 1;
  return { ...counts, precision, recall };
}

function report(t, label, rows) {
  t.diagnostic(`${label}: ${corpus.length} samples, ${corpus.filter((sample) => !sample.rule).length} unlabeled near misses`);
  t.diagnostic('detector | TP | FP | FN | TN | precision | recall');
  for (const [name, row] of rows) {
    t.diagnostic(`${name} | ${row.tp} | ${row.fp} | ${row.fn} | ${row.tn} | ${row.precision.toFixed(3)} | ${row.recall.toFixed(3)}`);
  }
}

test('labeled corpus covers every detector with positives and shared near-miss negatives', () => {
  for (const detector of detectors) {
    assert.ok(corpus.filter((sample) => detector.rules.includes(sample.rule)).length >= 7, detector.name);
  }
  assert.ok(corpus.filter((sample) => !sample.rule).length >= 80);
  assert.deepEqual(buildCorpus().map(({ text }) => text), corpus.map(({ text }) => text), 'the corpus is deterministic');
});

test('prompt detectors meet precision and recall gates in Block mode', (t) => {
  const rows = detectors.map((detector) => [detector.name, measure(detector, (text, policy) => evaluatePrompt(text, policy))]);
  report(t, 'Prompt and paste', rows);
  for (const [name, row] of rows) {
    assert.ok(row.precision >= thresholds.precision, `${name} precision ${row.precision} false blocks: ${row.falseBlocks.join(', ')}`);
    assert.ok(row.recall >= thresholds.recall, `${name} recall ${row.recall}`);
    assert.deepEqual(row.falseBlocks, [], `${name} false blocks`);
  }
});

test('file content inspection reaches the same results as prompts', (t) => {
  const rows = detectors.map((detector) => [detector.name, measure(detector, (text, policy) => {
    const match = evaluateFileInspection(text, fileInspectionDetectors(policy));
    return match ? { action: 'monitor', ...match } : { action: 'allow' };
  })]);
  report(t, 'File content', rows);
  for (const [name, row] of rows) {
    assert.ok(row.precision >= thresholds.precision && row.recall >= thresholds.recall, `${name} ${row.precision}/${row.recall}`);
  }
});

test('all detectors together stay within the local latency budget, including adversarial input', (t) => {
  const policy = { mode: 'monitor', githubPatMode: 'block', githubTokenMode: 'block', cloudCredentialMode: 'block', paymentCardMode: 'block',
    privateKeyMode: 'block', ssnMode: 'block', identifierProtection: { mode: 'block', formats: identifierFormats },
    classificationProtection: { mode: 'block', terms: classificationTerms }, healthProtection: { mode: 'block', recordFormats } };
  const negatives = corpus.filter((sample) => !sample.rule).map(({ text }) => text).join('\n');
  let document = '';
  while (document.length < 1024 * 1024) document += negatives + '\n';
  const timed = (text) => {
    const started = performance.now();
    const outcome = evaluatePrompt(text, policy);
    return { outcome, ms: performance.now() - started };
  };
  timed(negatives);
  const clean = timed(document);
  t.diagnostic(`1 MiB of near-miss text with every detector enabled: ${clean.ms.toFixed(1)} ms`);
  assert.equal(clean.outcome.action, 'allow');
  assert.ok(clean.ms < 4000, `clean scan took ${clean.ms} ms`);
  const adversarial = [
    prefixes.openAi + 'a'.repeat(200_000), (prefixes.aws).repeat(50_000), `${prefixes.slackBot}${'1-'.repeat(50_000)}`,
    prefixes.anthropic + 'A'.repeat(200_000), (prefixes.google + 'A'.repeat(34) + ' ').repeat(5000),
    'Project '.repeat(50_000), 'CONFIDENTIAL - '.repeat(30_000),
    'NPI '.repeat(50_000), 'NPI: 12'.repeat(40_000), 'DEA AB'.repeat(40_000), '1AC2-'.repeat(60_000), 'MRN: 1234'.repeat(30_000),
    'Medical record '.repeat(20_000),
  ];
  for (const text of adversarial) {
    const { ms } = timed(text);
    t.diagnostic(`adversarial ${text.slice(0, 12)}… (${text.length} chars): ${ms.toFixed(1)} ms`);
    assert.ok(ms < 1500, `adversarial input took ${ms} ms`);
  }
});
