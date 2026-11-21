'use client';

import { useState } from 'react';
import { canonicalizeDomainRules, domainLines } from '../../../../contracts/policy/domains';
import { detectorModes, modes, type DetectorMode, type PolicyMode } from '../../../../contracts/policy/prompt';
import { decisionLabels, detectorModeLabels } from '../../lib/control';
import { changedDecision, parseWebAddress, runComparison, samePolicy,
  type PreviewDecision, type PreviewPolicy, type PreviewResult, type PreviewSnapshot } from '../../lib/preview';
import { publishPreview } from '../actions';
import { MutationForm } from '../forms';

type Editor = Omit<PreviewPolicy, 'domainRules'> & { allow: string; block: string };

function editorFor(snapshot: PreviewSnapshot): Editor {
  return {
    mode: snapshot.mode, githubPatMode: snapshot.githubPatMode, paymentCardMode: snapshot.paymentCardMode,
    discoveryEnabled: snapshot.discoveryEnabled,
    allow: snapshot.domainRules.allow.join('\n'), block: snapshot.domainRules.block.join('\n'),
  };
}

export function PolicyPreview({ reference, snapshots, groupId, scopeName }: {
  reference: PreviewSnapshot; snapshots: PreviewSnapshot[]; groupId?: string; scopeName: string;
}) {
  const [source, setSource] = useState(reference.version);
  const [editor, setEditor] = useState(() => editorFor(reference));
  const [customPrompt, setCustomPrompt] = useState('');
  const [customUrl, setCustomUrl] = useState('');
  const [result, setResult] = useState<PreviewResult>();
  const [error, setError] = useState('');

  function invalidate() {
    setResult(undefined);
    setError('');
  }

  function load(version: number) {
    const snapshot = snapshots.find((item) => item.version === version);
    if (!snapshot) return;
    setSource(version);
    setEditor(editorFor(snapshot));
    invalidate();
  }

  function edit<K extends keyof Editor>(field: K, value: Editor[K]) {
    setEditor((previous) => ({ ...previous, [field]: value }));
    invalidate();
  }

  function run() {
    const domainRules = canonicalizeDomainRules({ allow: domainLines(editor.allow), block: domainLines(editor.block) });
    if (!domainRules) {
      setError('Enter up to 50 hostnames, one per line. A hostname can appear in only one list.');
      return;
    }
    const address = customUrl.trim() ? parseWebAddress(customUrl) : undefined;
    if (customUrl.trim() && !address) {
      setError('Enter a complete HTTP or HTTPS address for custom navigation.');
      return;
    }
    setError('');
    setResult(runComparison(reference, {
      mode: editor.mode, githubPatMode: editor.githubPatMode, paymentCardMode: editor.paymentCardMode,
      discoveryEnabled: editor.discoveryEnabled, domainRules,
    }, customPrompt, address));
  }

  return <>
    <section className="panel" aria-labelledby="draft-heading">
      <div className="panel-heading"><h2 id="draft-heading">Draft policy</h2><span className="badge">Current {reference.label}</span></div>
      <p className="muted">Compare an editable draft with the current policy for {scopeName}.</p>
      <div className="form-row preview-inputs">
        <div className="grid gap-1">
          <label htmlFor="draft-source">Load draft from</label>
          <select id="draft-source" value={source} onChange={(event) => load(Number(event.target.value))}>
            {snapshots.map((snapshot) => <option key={snapshot.version} value={snapshot.version}>{snapshot.label}</option>)}
          </select>
        </div>
        <div className="grid gap-1">
          <label htmlFor="draft-mode">Draft test marker</label>
          <select id="draft-mode" value={editor.mode} onChange={(event) => edit('mode', event.target.value as PolicyMode)}>
            {modes.map((mode) => <option key={mode} value={mode}>{decisionLabels[mode]}</option>)}
          </select>
        </div>
        <div className="grid gap-1">
          <label htmlFor="draft-github">Draft GitHub classic PAT</label>
          <select id="draft-github" value={editor.githubPatMode} onChange={(event) => edit('githubPatMode', event.target.value as DetectorMode)}>
            {detectorModes.map((mode) => <option key={mode} value={mode}>{detectorModeLabels[mode]}</option>)}
          </select>
        </div>
        <div className="grid gap-1">
          <label htmlFor="draft-payment-card">Draft payment card number</label>
          <select id="draft-payment-card" value={editor.paymentCardMode}
            onChange={(event) => edit('paymentCardMode', event.target.value as DetectorMode)}>
            {detectorModes.map((mode) => <option key={mode} value={mode}>{detectorModeLabels[mode]}</option>)}
          </select>
        </div>
        <div className="grid gap-1">
          <label htmlFor="draft-discovery">Draft AI app discovery</label>
          <select id="draft-discovery" value={editor.discoveryEnabled ? 'on' : 'off'} onChange={(event) => edit('discoveryEnabled', event.target.value === 'on')}>
            <option value="off">Off</option><option value="on">On</option>
          </select>
        </div>
      </div>
      <div className="policy-fields">
        {(['allow', 'block'] as const).map((action) => <div key={action} className="grid gap-1">
          <label htmlFor={`draft-${action}`}>{action === 'allow' ? 'Draft allowed domains' : 'Draft blocked domains'}</label>
          <textarea id={`draft-${action}`} rows={3} maxLength={13000} spellCheck={false} autoCapitalize="none"
            value={editor[action]} onChange={(event) => edit(action, event.target.value)} />
        </div>)}
      </div>
    </section>
    <section className="panel" aria-labelledby="preview-samples-heading">
      <h2 id="preview-samples-heading">Test samples</h2>
      <p className="muted">Built-in cases cover prompt detectors and top-level HTTP and HTTPS navigation. Custom samples stay in this tab.</p>
      <div className="policy-fields preview-inputs">
        <div className="grid gap-1">
          <label htmlFor="preview-prompt">Custom prompt</label>
          <textarea id="preview-prompt" rows={3} maxLength={16000} autoComplete="off" spellCheck={false} value={customPrompt}
            onChange={(event) => { setCustomPrompt(event.target.value); invalidate(); }} />
        </div>
        <div className="grid gap-1">
          <label htmlFor="preview-url">Custom navigation URL</label>
          <input id="preview-url" type="text" inputMode="url" autoComplete="off" spellCheck={false} maxLength={4096}
            placeholder="https://work.pilot.example.test/" value={customUrl}
            onChange={(event) => { setCustomUrl(event.target.value); invalidate(); }} />
        </div>
      </div>
      <button type="button" className="button primary" onClick={run}>Run preview</button>
      {error && <p className="feedback error" role="alert">{error}</p>}
    </section>
    {result && <PreviewResults result={result} groupId={groupId} scopeName={scopeName} />}
  </>;
}

function PreviewResults({ result, groupId, scopeName }: { result: PreviewResult; groupId?: string; scopeName: string }) {
  const { reference, candidate, rows } = result;
  const changes = rows.filter(changedDecision).length;
  return <>
    <section className="panel table-panel" aria-labelledby="preview-results-heading">
      <div className="panel-heading"><h2 id="preview-results-heading">Preview results</h2>
        <p className="table-note" role="status">{changes} of {rows.length} samples change</p></div>
      <div className="table-scroll" tabIndex={0} role="region" aria-labelledby="preview-results-heading">
        <table aria-labelledby="preview-results-heading">
          <thead><tr><th>Sample</th><th>Current {reference.label}</th><th>Draft</th></tr></thead>
          <tbody>{rows.map((row) => <tr key={row.name} className={changedDecision(row) ? 'preview-changed' : undefined}>
            <th scope="row">{row.name}</th>
            <td><Outcome outcome={row.current} /></td><td><Outcome outcome={row.draft} /></td>
          </tr>)}</tbody>
        </table>
      </div>
    </section>
    {!samePolicy(reference, candidate) && <section className="panel" aria-labelledby="preview-publish-heading">
      <h2 id="preview-publish-heading">Publish tested draft</h2>
      <p className="muted">Publish the draft settings to {scopeName} after reviewing these results.</p>
      <PolicyChanges reference={reference} candidate={candidate} />
      <MutationForm action={publishPreview} label="Publish previewed policy" appearance="primary"
        confirmation={`Publish the previewed settings to ${scopeName}?`}>
        {groupId && <input type="hidden" name="groupId" value={groupId} />}
        <input type="hidden" name="expectedVersion" value={reference.version} />
        <input type="hidden" name="mode" value={candidate.mode} />
        <input type="hidden" name="githubPatMode" value={candidate.githubPatMode} />
        <input type="hidden" name="paymentCardMode" value={candidate.paymentCardMode} />
        <input type="hidden" name="discoveryEnabled" value={candidate.discoveryEnabled ? 'on' : 'off'} />
        <input type="hidden" name="allow" value={candidate.domainRules.allow.join('\n')} />
        <input type="hidden" name="block" value={candidate.domainRules.block.join('\n')} />
      </MutationForm>
    </section>}
  </>;
}

function PolicyChanges({ reference, candidate }: { reference: PreviewPolicy; candidate: PreviewPolicy }) {
  const toggle = (value: boolean) => value ? 'On' : 'Off';
  const fields = [
    ['Test marker', decisionLabels[reference.mode], decisionLabels[candidate.mode]],
    ['GitHub classic PAT', detectorModeLabels[reference.githubPatMode], detectorModeLabels[candidate.githubPatMode]],
    ['Payment card number', detectorModeLabels[reference.paymentCardMode], detectorModeLabels[candidate.paymentCardMode]],
    ['AI app discovery', toggle(reference.discoveryEnabled), toggle(candidate.discoveryEnabled)],
  ];
  return <ul className="preview-changes" aria-label="Policy setting changes">
    {fields.filter(([, before, after]) => before !== after).map(([field, before, after]) =>
      <li key={field}>{field} · {before} → {after}</li>)}
    {(['allow', 'block'] as const).flatMap((action) => {
      const before = reference.domainRules[action];
      const after = candidate.domainRules[action];
      const added = after.filter((domain) => !before.includes(domain));
      const removed = before.filter((domain) => !after.includes(domain));
      const label = action === 'allow' ? 'allow list' : 'block list';
      return [added.length > 0 && <li key={`${action}-add`}>Add to {label} <code>{added.join(', ')}</code></li>,
        removed.length > 0 && <li key={`${action}-remove`}>Remove from {label} <code>{removed.join(', ')}</code></li>];
    })}
  </ul>;
}

function Outcome({ outcome }: { outcome: PreviewDecision }) {
  return <div className="form-row">
    <span className={`badge ${outcome.action}`}>{outcome.action === 'allow' ? 'Allow' : decisionLabels[outcome.action]}</span>
    {outcome.rule && <span className="preview-rule">{outcome.rule}</span>}
  </div>;
}
