'use client';

import { useState } from 'react';
import { readNavigationRules } from '../../lib/navigation';
import { detectorModes, modes, type DetectorMode, type PolicyMode } from '../../../../contracts/policy/prompt';
import { parseUploadTypes, uploadModes, uploadTypesError, uploadTypesHint, type UploadMode } from '../../../../contracts/policy/uploads';
import { aiPromptApps, decisionLabels, detectorModeLabels, promptAppLabels } from '../../lib/control';
import { changedDecision, parseWebAddress, runComparison, samePolicy,
  type PreviewDecision, type PreviewPolicy, type PreviewResult, type PreviewSnapshot } from '../../lib/preview';
import { publishPreview } from '../actions';
import { MutationForm } from '../forms';
import { PolicyChanges } from '../policy-changes';
import { customAppError, parseCustomApps } from '../../../../contracts/policy/discovery';

const navigationFields = [
  ['allow', 'Draft allowed domains'], ['block', 'Draft blocked domains'],
  ['allowPaths', 'Draft allowed paths'], ['blockPaths', 'Draft blocked paths'],
] as const;
type Editor = Omit<PreviewPolicy, 'domainRules' | 'pathRules' | 'uploadTypes' | 'customApps'> &
  Record<typeof navigationFields[number][0], string> & { uploadTypeText: Record<typeof aiPromptApps[number], string>; catalog: string };

function editorFor(snapshot: PreviewSnapshot): Editor {
  return {
    mode: snapshot.mode, githubPatMode: snapshot.githubPatMode, paymentCardMode: snapshot.paymentCardMode,
    discoveryEnabled: snapshot.discoveryEnabled,
    extensionInventoryEnabled: snapshot.extensionInventoryEnabled,
    uploadModes: snapshot.uploadModes,
    uploadTypeText: { chatgpt: snapshot.uploadTypes.chatgpt.join(', '), gemini: snapshot.uploadTypes.gemini.join(', ') },
    catalog: snapshot.customApps.map(({ host, name }) => `${host}, ${name}`).join('\n'),
    allow: snapshot.domainRules.allow.join('\n'), block: snapshot.domainRules.block.join('\n'),
    allowPaths: snapshot.pathRules.allow.join('\n'), blockPaths: snapshot.pathRules.block.join('\n'),
  };
}

export function PolicyPreview({ reference, snapshots, groupId, scopeName, writable, review }: {
  reference: PreviewSnapshot; snapshots: PreviewSnapshot[]; groupId?: string; scopeName: string; writable: boolean; review: boolean;
}) {
  const [source, setSource] = useState(reference.version);
  const [editor, setEditor] = useState(() => editorFor(reference));
  const [customPrompt, setCustomPrompt] = useState('');
  const [customUrl, setCustomUrl] = useState('');
  const [customFile, setCustomFile] = useState({ name: '', type: '' });
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
    const { domainRules, pathRules, error: invalid } = readNavigationRules(editor.allow, editor.block, editor.allowPaths, editor.blockPaths);
    if (!domainRules || !pathRules) {
      setError(invalid);
      return;
    }
    const address = customUrl.trim() ? parseWebAddress(customUrl) : undefined;
    if (customUrl.trim() && !address) {
      setError('Enter a complete HTTP or HTTPS address for custom navigation.');
      return;
    }
    const chatgpt = parseUploadTypes(editor.uploadTypeText.chatgpt);
    const gemini = parseUploadTypes(editor.uploadTypeText.gemini);
    if (!chatgpt || !gemini) {
      setError(uploadTypesError);
      return;
    }
    const customApps = parseCustomApps(editor.catalog);
    if (!customApps) {
      setError(customAppError);
      return;
    }
    const file = customFile.name || customFile.type.trim() ? customFile : undefined;
    setError('');
    setResult(runComparison(reference, {
      mode: editor.mode, githubPatMode: editor.githubPatMode, paymentCardMode: editor.paymentCardMode,
      discoveryEnabled: editor.discoveryEnabled, extensionInventoryEnabled: editor.extensionInventoryEnabled, domainRules, pathRules,
      uploadModes: editor.uploadModes, uploadTypes: { chatgpt, gemini }, customApps,
    }, customPrompt, address, file));
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
          <label htmlFor="draft-discovery">Draft app discovery</label>
          <select id="draft-discovery" value={editor.discoveryEnabled ? 'on' : 'off'} onChange={(event) => edit('discoveryEnabled', event.target.value === 'on')}>
            <option value="off">Off</option><option value="on">On</option>
          </select>
        </div>
        <div className="grid gap-1">
          <label htmlFor="draft-extension-inventory">Draft extension inventory</label>
          <select id="draft-extension-inventory" value={editor.extensionInventoryEnabled ? 'on' : 'off'}
            onChange={(event) => edit('extensionInventoryEnabled', event.target.value === 'on')}>
            <option value="off">Off</option><option value="on">On</option>
          </select>
        </div>
        {aiPromptApps.map((app) => <div className="grid gap-1" key={app}>
          <label htmlFor={`draft-upload-${app}`}>Draft {promptAppLabels[app]} file uploads</label>
          <select id={`draft-upload-${app}`} value={editor.uploadModes[app]}
            onChange={(event) => edit('uploadModes', { ...editor.uploadModes, [app]: event.target.value as UploadMode })}>
            {uploadModes.map((mode) => <option key={mode} value={mode}>{detectorModeLabels[mode]}</option>)}
          </select>
          <label htmlFor={`draft-upload-types-${app}`}>Draft {promptAppLabels[app]} file types</label>
          <textarea id={`draft-upload-types-${app}`} rows={2} value={editor.uploadTypeText[app]}
            onChange={(event) => edit('uploadTypeText', { ...editor.uploadTypeText, [app]: event.target.value })}
            maxLength={1700} spellCheck={false} autoCapitalize="none" autoComplete="off" aria-describedby="draft-upload-types-hint" />
        </div>)}
      </div>
      <p className="muted" id="draft-upload-types-hint">{uploadTypesHint}</p>
      <div className="grid gap-1" id="draft-app-catalog">
        <label htmlFor="draft-custom-apps">Custom app catalog</label>
        <p className="muted" id="custom-apps-hint">Enter the exact hostname and display name for each HTTPS site, one per line.
          App discovery must be on and enrolled browsers must grant the Chrome permission.</p>
        <textarea id="draft-custom-apps" rows={3} maxLength={8500} spellCheck={false} autoCapitalize="none"
          placeholder="workspace.example.test, Example Workspace" value={editor.catalog}
          aria-describedby="custom-apps-hint" onChange={(event) => edit('catalog', event.target.value)} />
      </div>
      <div className="policy-fields">
        {navigationFields.map(([field, label]) => <div key={field} className="grid gap-1">
          <label htmlFor={`draft-${field}`}>{label}</label>
          <textarea id={`draft-${field}`} rows={3} maxLength={16000} spellCheck={false} autoCapitalize="none"
            value={editor[field]} onChange={(event) => edit(field, event.target.value)} />
        </div>)}
      </div>
    </section>
    <section className="panel" aria-labelledby="preview-samples-heading">
      <h2 id="preview-samples-heading">Test samples</h2>
      <p className="muted">Built-in cases cover prompt detectors, navigation, and file upload policies. Custom samples stay in this tab.</p>
      <div className="policy-fields preview-inputs">
        <div className="grid gap-1">
          <label htmlFor="preview-prompt">Custom prompt</label>
          <textarea id="preview-prompt" rows={3} maxLength={16000} autoComplete="off" spellCheck={false} value={customPrompt}
            onChange={(event) => { setCustomPrompt(event.target.value); invalidate(); }} />
        </div>
        <div className="grid gap-1">
          <label htmlFor="preview-file-name">Custom file name</label>
          <input id="preview-file-name" value={customFile.name} maxLength={255} autoComplete="off" spellCheck={false}
            placeholder="example.pdf" onChange={(event) => { setCustomFile({ ...customFile, name: event.target.value }); invalidate(); }} />
        </div>
        <div className="grid gap-1">
          <label htmlFor="preview-file-type">Custom media type</label>
          <input id="preview-file-type" value={customFile.type} maxLength={128} autoComplete="off" spellCheck={false}
            placeholder="application/pdf" onChange={(event) => { setCustomFile({ ...customFile, type: event.target.value }); invalidate(); }} />
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
    {result && <PreviewResults result={result} groupId={groupId} scopeName={scopeName} writable={writable} review={review} />}
  </>;
}

function PreviewResults({ result, groupId, scopeName, writable, review }: {
  result: PreviewResult; groupId?: string; scopeName: string; writable: boolean; review: boolean;
}) {
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
      <h2 id="preview-publish-heading">{writable ? (review ? 'Request review of tested draft' : 'Publish tested draft') : 'Draft setting changes'}</h2>
      {writable && <p className="muted">{review ? 'Submit the tested settings for approval.' :
        `Publish the draft settings to ${scopeName} after reviewing these results.`}</p>}
      <PolicyChanges reference={reference} candidate={candidate} />
      {writable && <MutationForm action={publishPreview} label={review ? 'Request review of previewed policy' : 'Publish previewed policy'}
        appearance="primary" confirmation={review ? `Request review of these settings for ${scopeName}?` : `Publish the previewed settings to ${scopeName}?`}>
        {groupId && <input type="hidden" name="groupId" value={groupId} />}
        {review && <input type="hidden" name="expectReview" value="on" />}
        <input type="hidden" name="expectedVersion" value={reference.version} />
        <input type="hidden" name="mode" value={candidate.mode} />
        <input type="hidden" name="githubPatMode" value={candidate.githubPatMode} />
        <input type="hidden" name="paymentCardMode" value={candidate.paymentCardMode} />
        <input type="hidden" name="discoveryEnabled" value={candidate.discoveryEnabled ? 'on' : 'off'} />
        <input type="hidden" name="customApps" value={candidate.customApps.map(({ host, name }) => `${host}, ${name}`).join('\n')} />
        <input type="hidden" name="extensionInventoryEnabled" value={candidate.extensionInventoryEnabled ? 'on' : 'off'} />
        {aiPromptApps.map((app) => <input key={app} type="hidden" name={`upload-${app}`} value={candidate.uploadModes[app]} />)}
        {aiPromptApps.map((app) => <input key={app} type="hidden" name={`upload-types-${app}`} value={candidate.uploadTypes[app].join(', ')} />)}
        <input type="hidden" name="allow" value={candidate.domainRules.allow.join('\n')} />
        <input type="hidden" name="block" value={candidate.domainRules.block.join('\n')} />
        <input type="hidden" name="allowPaths" value={candidate.pathRules.allow.join('\n')} />
        <input type="hidden" name="blockPaths" value={candidate.pathRules.block.join('\n')} />
      </MutationForm>}
    </section>}
  </>;
}

function Outcome({ outcome }: { outcome: PreviewDecision }) {
  return <div className="form-row">
    <span className={`badge ${outcome.action}`}>{outcome.action === 'allow' ? 'Allow' : decisionLabels[outcome.action]}</span>
    {outcome.rule && <span className="preview-rule">{outcome.rule}</span>}
  </div>;
}
