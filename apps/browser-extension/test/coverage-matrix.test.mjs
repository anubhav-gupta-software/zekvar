import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { docUrl, matrixUrl, renderCoverage } from '../../../scripts/coverage-doc.mjs';

const root = new URL('../../../', import.meta.url);
const matrix = JSON.parse(await readFile(matrixUrl, 'utf8'));
const statuses = new Set(['supported', 'experimental', 'unsupported']);
const evidence = new Set(['fixture', 'unit', 'api', 'live-signed-out', 'live-signed-in']);
const sources = new Map();

async function source(file) {
  assert.match(file, /^apps\/[a-z-]+\/test\/[a-z-]+\.test\.mjs$/, `${file} is not a repository test file`);
  if (!sources.has(file)) sources.set(file, await readFile(new URL(file, root), 'utf8'));
  return sources.get(file);
}

function declared(text, name) {
  return ["'", '"', '`'].some((quote) => text.includes(`test(${quote}${name}${quote}`));
}

test('covers every app, action, and mode exactly once with a known status and version', () => {
  const apps = matrix.apps.map(({ id }) => id);
  assert.deepEqual(apps, ['chatgpt', 'gemini', 'claude']);
  const keys = matrix.cells.map(({ app, action, mode }) => `${app}/${action}/${mode}`);
  assert.equal(new Set(keys).size, keys.length, 'A matrix cell is listed twice.');
  assert.equal(keys.length, apps.length * matrix.actions.length * matrix.modes.length, 'A matrix cell is missing.');
  for (const cell of [...matrix.cells, ...matrix.controls]) {
    assert.ok(statuses.has(cell.status), `${cell.app}/${cell.action ?? cell.control} has an unknown status`);
    if (cell.status === 'unsupported') {
      assert.equal(cell.minBrowser, null);
      assert.deepEqual(cell.tests, []);
      continue;
    }
    assert.match(cell.minBrowser ?? '', /^\d+\.\d+\.\d+$/, `${cell.app}/${cell.action ?? cell.control} needs a minimum Browser version`);
    assert.ok(cell.tests.some(({ evidence: kind }) => kind === 'fixture' || kind === 'api'),
      `${cell.app}/${cell.action ?? cell.control}/${cell.mode ?? cell.fallback} needs controlled-fixture or API evidence`);
  }
  for (const cell of matrix.cells) {
    const action = matrix.actions.find(({ id }) => id === cell.action);
    if (!action.modes.includes(cell.mode)) assert.equal(cell.status, 'unsupported', `${cell.action} does not offer ${cell.mode}`);
  }
});

test('names only tests that exist in the repository test files', async () => {
  for (const cell of [...matrix.cells, ...matrix.controls]) {
    for (const { file, name, evidence: kind } of cell.tests) {
      assert.ok(evidence.has(kind), `${name} has unknown evidence ${kind}`);
      assert.ok(declared(await source(file), name), `${file} does not declare the test "${name}"`);
    }
  }
});

test('records no live signed-in evidence until it exists', () => {
  assert.ok([...matrix.cells, ...matrix.controls].every(({ tests }) => tests.every(({ evidence: kind }) => kind !== 'live-signed-in')));
});

test('keeps docs/coverage.md generated from the matrix', async () => {
  assert.equal(await readFile(docUrl, 'utf8'), renderCoverage(matrix),
    'docs/coverage.md is out of date. Run node scripts/coverage-doc.mjs.');
});
