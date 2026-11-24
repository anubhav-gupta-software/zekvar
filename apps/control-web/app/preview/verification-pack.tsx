'use client';

import { useRef, useState } from 'react';
import { decisionLabels, promptAppLabels } from '../../lib/control';
import type { PreviewDecision } from '../../lib/preview';
import { maxTestPackBytes, parseTestPack, starterTestPack, type TestPack, type TestPackReport } from '../../lib/test-pack';

const kinds = { prompt: 'Prompt', clipboard: 'Paste', navigation: 'Navigation', upload: 'File upload' };
const statuses = { pass: 'Pass', fixed: 'Fixed', regression: 'Regression', mismatch: 'Mismatch' };

function downloadJson(name: string, value: object) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2) + '\n'], { type: 'application/json' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

export function TestPackInput({ pack, onChange }: { pack?: TestPack; onChange: (pack?: TestPack) => void }) {
  const generation = useRef(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  function clear() {
    generation.current++;
    onChange();
    setError('');
    setLoading(false);
  }

  async function load(file: File) {
    clear();
    if (file.size > maxTestPackBytes) {
      setError('Choose a test pack of 256 KiB or less.');
      return;
    }
    const attempt = generation.current;
    setLoading(true);
    try {
      const result = parseTestPack(await file.text());
      if (attempt !== generation.current) return;
      if (result.pack) onChange(result.pack);
      else setError(result.error);
    } catch {
      if (attempt === generation.current) setError('The browser could not read this file. Choose it again.');
    } finally {
      if (attempt === generation.current) setLoading(false);
    }
  }

  return <div className="flex flex-col gap-2 mb-4">
    <h3>Reusable test pack</h3>
    <p id="test-pack-hint" className="muted">Import up to 100 synthetic cases with expected outcomes. Control evaluates them in this tab.
      The results include case IDs and decisions.</p>
    <div className="form-row">
      <input id="test-pack-file" type="file" accept=".json,application/json" aria-label="Import test pack"
        className="max-w-full" aria-describedby="test-pack-hint" onChange={(event) => {
          const file = event.currentTarget.files?.[0];
          event.currentTarget.value = '';
          if (file) void load(file);
        }} />
      <button type="button" className="button small" onClick={() => downloadJson('zekvar-test-pack.json', starterTestPack)}>Download starter pack</button>
      {(pack || loading) && <button type="button" className="button small" onClick={clear}>Clear test pack</button>}
    </div>
    {error && <p role="alert" className="feedback error">{error}</p>}
    {loading && <p role="status" className="muted">Reading test pack…</p>}
    {pack && <p role="status" className="feedback">Loaded {pack.cases.length} {pack.cases.length === 1 ? 'case' : 'cases'}.</p>}
  </div>;
}

export function TestPackResults({ report }: { report: TestPackReport }) {
  const { cases, summary } = report;
  return <section className="panel table-panel" aria-labelledby="test-pack-heading">
    <div className="panel-heading">
      <div><h2 id="test-pack-heading">Test pack results</h2>
        <p className="table-note" role="status">Draft passes {summary.draftPassed} of {cases.length} cases ·
          Current passes {summary.currentPassed} · {summary.fixes} fixed · {summary.regressions} regressions</p>
      </div>
      <button type="button" className="button small" onClick={() => downloadJson('zekvar-test-results.json', report)}>Download test results</button>
    </div>
    <div className="table-scroll" tabIndex={0} role="region" aria-labelledby="test-pack-heading">
      <table aria-labelledby="test-pack-heading">
        <thead><tr><th scope="col">Case</th><th scope="col">Expected</th><th scope="col">Current</th><th scope="col">Draft</th><th scope="col">Result</th></tr></thead>
        <tbody>{cases.map(({ id, kind, app, expect, current, draft, result }) => <tr key={id}>
          <th scope="row" className="test-case-id">{id}<span className="block table-note">{kinds[kind]}{app && ` · ${promptAppLabels[app]}`}</span></th>
          {[expect, current, draft].map((action, index) => <td key={index}><ActionBadge action={action} /></td>)}
          <td><span className={`badge ${result === 'regression' || result === 'mismatch' ? 'block' : 'current'}`}>{statuses[result]}</span></td>
        </tr>)}</tbody>
      </table>
    </div>
  </section>;
}

function ActionBadge({ action }: { action: PreviewDecision['action'] }) {
  return <span className={`badge ${action}`}>{action === 'allow' ? 'Allow' : decisionLabels[action]}</span>;
}
