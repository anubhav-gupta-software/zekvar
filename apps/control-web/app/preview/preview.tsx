'use client';

import { useEffect, useState } from 'react';
import { navigationRuleLimitError, readNavigationRules } from '../../lib/navigation';
import { detectorModes, fixtureRule, identifierRule, modes, privateKeyRule, readIdentifierProtection, ruleLabels,
  type DetectorMode, type PolicyMode, type PromptRuleId } from '../../../../contracts/policy/prompt';
import { identifierFormatError, identifierFormatHint, parseIdentifierFormats } from '../../../../contracts/policy/organization-identifiers';
import { parseUploadTypes, uploadApps, uploadModes, uploadTypesError, uploadTypesHint, type UploadApp, type UploadMode } from '../../../../contracts/policy/uploads';
import { aiPromptApps, decisionLabels, detectorModeLabels, promptAppLabels } from '../../lib/control';
import { changedDecision, parseWebAddress, runComparison, samePolicy,
  type PreviewDecision, type PreviewPolicy, type PreviewResult, type PreviewSnapshot } from '../../lib/preview';
import { publishPreview } from '../actions';
import { MutationForm } from '../forms';
import { PolicyChanges } from '../policy-changes';
import { customAppError, parseCustomApps } from '../../../../contracts/policy/discovery';
import { exceptionWindowMs, promptExceptionError, promptExceptionLimit, readPromptExceptions, samePromptExceptions, type PromptException } from '../../../../contracts/policy/prompt-exceptions';
import { chatGptApp, type AiPromptApp } from '../../../../contracts/policy/apps';
import { aiAppAccessCatalog } from '../../../../contracts/policy/ai-app-access';
import { domainRuleLimit, ruleCount } from '../../../../contracts/policy/domains';

const navigationFields = [
  ['allow', 'Draft allowed domains'], ['block', 'Draft blocked domains'],
  ['allowPaths', 'Draft allowed paths'], ['blockPaths', 'Draft blocked paths'],
] as const;
type Editor = Omit<PreviewPolicy, 'domainRules' | 'pathRules' | 'uploadTypes' | 'customApps' | 'identifierProtection'> &
  Record<typeof navigationFields[number][0], string> & { uploadTypeText: Record<UploadApp, string>; catalog: string;
    identifierMode?: DetectorMode; identifierFormats: string };

function editorFor(snapshot: PreviewSnapshot): Editor {
  return {
    mode: snapshot.mode, githubPatMode: snapshot.githubPatMode, paymentCardMode: snapshot.paymentCardMode, privateKeyMode: snapshot.privateKeyMode,
    identifierMode: snapshot.identifierProtection?.mode,
    identifierFormats: snapshot.identifierProtection?.formats.map(({ prefix, digits }) => `${prefix} ${digits}`).join('\n') ?? '',
    discoveryEnabled: snapshot.discoveryEnabled,
    extensionInventoryEnabled: snapshot.extensionInventoryEnabled,
    blockedAiAppHosts: snapshot.blockedAiAppHosts,
    claudePromptEnabled: snapshot.claudePromptEnabled,
    uploadModes: snapshot.uploadModes,
    fileInspection: snapshot.fileInspection,
    fileContentModes: snapshot.fileContentModes,
    uploadTypeText: { chatgpt: snapshot.uploadTypes.chatgpt.join(', '), gemini: snapshot.uploadTypes.gemini.join(', ') },
    catalog: snapshot.customApps.map(({ host, name }) => `${host}, ${name}`).join('\n'),
    promptExceptions: snapshot.promptExceptions.map((entry) => ({ ...entry, expiresAt: new Date(entry.expiresAt).toISOString().slice(0, -1) })),
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
  const [promptApp, setPromptApp] = useState<AiPromptApp>(chatGptApp);
  const [result, setResult] = useState<PreviewResult>();
  const [error, setError] = useState('');
  const [ready, setReady] = useState(false);
  const selectedAccess = editor.blockedAiAppHosts;
  const catalog = aiAppAccessCatalog(parseCustomApps(editor.catalog) ?? []);
  const orphanedAccess = (selectedAccess ?? []).filter((host) => !catalog.some((app) => app.host === host));

  useEffect(() => setReady(true), []);

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

  function editException(index: number, update: Partial<PromptException>) {
    edit('promptExceptions', editor.promptExceptions.map((entry, position) => position === index ? { ...entry, ...update } : entry));
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
    if (orphanedAccess.length) {
      setError('Keep each blocked AI app in the draft catalog or clear its access block.');
      return;
    }
    if (ruleCount(domainRules) + ruleCount(pathRules) + (editor.blockedAiAppHosts?.length ?? 0) > domainRuleLimit) {
      setError(navigationRuleLimitError);
      return;
    }
    const promptExceptions = readPromptExceptions(editor.promptExceptions.map((entry) => ({ ...entry, expiresAt: entry.expiresAt + 'Z' })));
    if (!promptExceptions) {
      setError(promptExceptionError);
      return;
    }
    const now = Date.now();
    if (promptExceptions.some((entry) => Date.parse(entry.expiresAt) > now + exceptionWindowMs ||
        (Date.parse(entry.expiresAt) <= now && !reference.promptExceptions.some((prior) => samePromptExceptions([entry], [prior]))))) {
      setError('Set each new or changed exception to expire within the next 24 hours.');
      return;
    }
    const identifiers = editor.identifierMode === undefined ? undefined :
      readIdentifierProtection({ mode: editor.identifierMode, formats: parseIdentifierFormats(editor.identifierFormats) });
    if (editor.identifierMode !== undefined && !identifiers) {
      setError(editor.identifierMode !== 'off' && !editor.identifierFormats.trim() ?
        'Enter at least one identifier format or set the detector to Off.' : identifierFormatError);
      return;
    }
    const file = customFile.name || customFile.type.trim() ? customFile : undefined;
    setError('');
    setResult(runComparison(reference, {
      mode: editor.mode, githubPatMode: editor.githubPatMode, paymentCardMode: editor.paymentCardMode, privateKeyMode: editor.privateKeyMode,
      identifierProtection: identifiers,
      discoveryEnabled: editor.discoveryEnabled, extensionInventoryEnabled: editor.extensionInventoryEnabled,
      extensionDeployment: reference.extensionDeployment,
      blockedAiAppHosts: editor.blockedAiAppHosts,
      claudePromptEnabled: editor.claudePromptEnabled, domainRules, pathRules,
      uploadModes: editor.uploadModes, uploadTypes: { chatgpt, gemini }, fileInspection: editor.fileInspection,
      fileContentModes: editor.fileContentModes, customApps, promptExceptions,
    }, customPrompt, address, file, promptApp));
  }

  return <fieldset disabled={!ready} className="m-0 min-w-0 border-0 p-0">
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
        {editor.privateKeyMode !== undefined && <div className="grid gap-1">
          <label htmlFor="draft-private-key">Draft private key</label>
          <select id="draft-private-key" value={editor.privateKeyMode}
            onChange={(event) => edit('privateKeyMode', event.target.value as DetectorMode)}>
            {detectorModes.map((mode) => <option key={mode} value={mode}>{detectorModeLabels[mode]}</option>)}
          </select>
        </div>}
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
        <div className="grid gap-1">
          <label htmlFor="draft-claude-prompt">Draft Claude prompt protection</label>
          <select id="draft-claude-prompt" value={editor.claudePromptEnabled ? 'on' : 'off'}
            onChange={(event) => edit('claudePromptEnabled', event.target.value === 'on')}>
            <option value="off">Off</option><option value="on">On · experimental</option>
          </select>
        </div>
        {uploadApps.map((app) => <div className="grid gap-1" key={app}>
          <label htmlFor={`draft-upload-${app}`}>Draft {promptAppLabels[app]} file uploads</label>
          <select id={`draft-upload-${app}`} value={editor.uploadModes[app]}
            onChange={(event) => edit('uploadModes', { ...editor.uploadModes, [app]: event.target.value as UploadMode })}>
            {uploadModes.map((mode) => <option key={mode} value={mode}>{detectorModeLabels[mode]}</option>)}
          </select>
          <label htmlFor={`draft-upload-types-${app}`}>Draft {promptAppLabels[app]} file types</label>
          <textarea id={`draft-upload-types-${app}`} rows={2} value={editor.uploadTypeText[app]}
            onChange={(event) => edit('uploadTypeText', { ...editor.uploadTypeText, [app]: event.target.value })}
            maxLength={1700} spellCheck={false} autoCapitalize="none" autoComplete="off" aria-describedby="draft-upload-types-hint" />
          {editor.fileContentModes ? <>
            <label htmlFor={`draft-file-content-${app}`}>Draft {promptAppLabels[app]} file content protection</label>
            <select id={`draft-file-content-${app}`} value={editor.fileContentModes[app]} aria-describedby="draft-file-content-hint"
              onChange={(event) => {
                if (editor.fileContentModes) edit('fileContentModes', { ...editor.fileContentModes, [app]: event.target.value as UploadMode });
              }}>
              {uploadModes.map((mode) => <option key={mode} value={mode}>{detectorModeLabels[mode]}</option>)}
            </select>
          </> : editor.fileInspection && <>
            <label htmlFor={`draft-file-inspection-${app}`}>Draft {promptAppLabels[app]} file content monitoring</label>
            <select id={`draft-file-inspection-${app}`} value={editor.fileInspection[app] ? 'on' : 'off'}
              onChange={(event) => {
                if (editor.fileInspection) edit('fileInspection', { ...editor.fileInspection, [app]: event.target.value === 'on' });
              }}>
              <option value="off">Off</option><option value="on">Monitor</option>
            </select>
          </>}
        </div>)}
      </div>
      <p className="muted" id="draft-upload-types-hint">{uploadTypesHint}</p>
      {editor.fileContentModes && <p className="muted" id="draft-file-content-hint">
        Block holds the batch and stops uploads with a sensitive match or an incomplete check.
      </p>}
      {editor.identifierMode !== undefined && <div id="draft-identifiers" className="grid gap-2 mb-4">
        <div className="form-row"><label htmlFor="draft-identifier-mode">Organization identifier detection</label>
          <select id="draft-identifier-mode" value={editor.identifierMode}
            onChange={(event) => edit('identifierMode', event.target.value as DetectorMode)}>
            {detectorModes.map((mode) => <option key={mode} value={mode}>{detectorModeLabels[mode]}</option>)}
          </select>
        </div>
        <label htmlFor="draft-identifier-formats">Identifier formats</label>
        <textarea id="draft-identifier-formats" rows={3} maxLength={384} spellCheck={false} autoCapitalize="none" autoComplete="off"
          placeholder={'CUST- 8\nCASE_ 6'} aria-describedby="draft-identifier-hint" value={editor.identifierFormats}
          onChange={(event) => edit('identifierFormats', event.target.value)} />
        <p className="muted" id="draft-identifier-hint">{identifierFormatHint}</p>
      </div>}
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
    {selectedAccess && <section className="panel" id="draft-ai-app-access" aria-labelledby="ai-app-access-heading">
      <h2 id="ai-app-access-heading">AI app access</h2>
      <p className="muted">Block selected hosts for new top-level web requests in Browser v0.26.0 or later. These blocks take precedence over domain and path rules.</p>
      <div className="ai-app-access-options">
        {[...catalog, ...orphanedAccess.map((host) => ({ host, name: 'Removed from draft catalog' }))].map(({ host, name }) =>
          <label key={host} className="ai-app-access-option">
            <input type="checkbox" aria-label={`Block ${host}`} checked={selectedAccess.includes(host)}
              onChange={(event) => edit('blockedAiAppHosts', event.target.checked
                ? [...selectedAccess, host].sort()
                : selectedAccess.filter((selected) => selected !== host))} />
            <span><strong>{name}</strong><code>{host}</code></span>
          </label>)}
      </div>
    </section>}
    <section className="panel" aria-labelledby="prompt-exceptions-heading">
      <h2 id="prompt-exceptions-heading">Temporary prompt exceptions</h2>
      <p className="muted">An exception can allow a flagged prompt for one detector and app until its UTC expiry. Other matching detectors still apply.</p>
      {editor.promptExceptions.map((entry, index) => <fieldset key={index} className="policy-fields prompt-exception-fields">
        <legend>Exception {index + 1}</legend>
        <div className="grid gap-1">
          <label htmlFor={`exception-app-${index}`}>App</label>
          <select id={`exception-app-${index}`} value={entry.appId}
            onChange={(event) => editException(index, { appId: event.target.value as AiPromptApp })}>
            {aiPromptApps.map((app) => <option key={app} value={app}>{promptAppLabels[app]}</option>)}
          </select>
        </div>
        <div className="grid gap-1">
          <label htmlFor={`exception-rule-${index}`}>Detector</label>
          <select id={`exception-rule-${index}`} value={entry.ruleId}
            onChange={(event) => editException(index, { ruleId: event.target.value as PromptRuleId })}>
            {Object.entries(ruleLabels).map(([rule, label]) => (rule === privateKeyRule && editor.privateKeyMode === undefined ||
              rule === identifierRule && editor.identifierMode === undefined) ? null :
              <option key={rule} value={rule}>{rule === fixtureRule ? 'Test marker' : label}</option>)}
          </select>
        </div>
        <div className="grid gap-1">
          <label htmlFor={`exception-expiry-${index}`}>Expires (UTC)</label>
          <input id={`exception-expiry-${index}`} type="datetime-local" step="any" value={entry.expiresAt}
            onChange={(event) => editException(index, { expiresAt: event.target.value })} />
        </div>
        <div className="grid gap-1">
          <label htmlFor={`exception-reason-${index}`}>Reason</label>
          <input id={`exception-reason-${index}`} maxLength={120} value={entry.reason}
            onChange={(event) => editException(index, { reason: event.target.value })} />
        </div>
        <div><button type="button" className="button small" aria-label={`Remove exception ${index + 1}`}
          onClick={() => edit('promptExceptions', editor.promptExceptions.filter((_entry, position) => position !== index))}>Remove</button></div>
      </fieldset>)}
      <button type="button" className="button small" disabled={editor.promptExceptions.length >= promptExceptionLimit} onClick={() => edit('promptExceptions',
        [...editor.promptExceptions, { appId: chatGptApp, ruleId: fixtureRule, expiresAt: '', reason: '' }])}>Add prompt exception</button>
    </section>
    <section className="panel" aria-labelledby="preview-samples-heading">
      <h2 id="preview-samples-heading">Test samples</h2>
      <p className="muted">Built-in cases cover prompt detectors, navigation, and file upload policies. Custom samples stay in this tab.</p>
      <div className="policy-fields preview-inputs">
        <div className="grid gap-1">
          <label htmlFor="preview-prompt-app">Prompt sample destination</label>
          <select id="preview-prompt-app" value={promptApp} onChange={(event) => { setPromptApp(event.target.value as AiPromptApp); invalidate(); }}>
            {aiPromptApps.map((app) => <option key={app} value={app}>{promptAppLabels[app]}</option>)}
          </select>
        </div>
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
  </fieldset>;
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
        {candidate.privateKeyMode !== undefined && <input type="hidden" name="privateKeyMode" value={candidate.privateKeyMode} />}
        {candidate.identifierProtection && <input type="hidden" name="identifierProtection" value={JSON.stringify(candidate.identifierProtection)} />}
        <input type="hidden" name="discoveryEnabled" value={candidate.discoveryEnabled ? 'on' : 'off'} />
        <input type="hidden" name="customApps" value={candidate.customApps.map(({ host, name }) => `${host}, ${name}`).join('\n')} />
        {candidate.blockedAiAppHosts && <>
          <input type="hidden" name="aiAppAccess" value="present" />
          {candidate.blockedAiAppHosts.map((host) => <input key={host} type="hidden" name="blockedAiAppHost" value={host} />)}
        </>}
        <input type="hidden" name="promptExceptions" value={JSON.stringify(candidate.promptExceptions)} />
        <input type="hidden" name="extensionInventoryEnabled" value={candidate.extensionInventoryEnabled ? 'on' : 'off'} />
        <input type="hidden" name="claudePromptEnabled" value={candidate.claudePromptEnabled ? 'on' : 'off'} />
        {uploadApps.map((app) => <input key={app} type="hidden" name={`upload-${app}`} value={candidate.uploadModes[app]} />)}
        {uploadApps.map((app) => <input key={app} type="hidden" name={`upload-types-${app}`} value={candidate.uploadTypes[app].join(', ')} />)}
        {candidate.fileContentModes ? uploadApps.map((app) => <input key={app} type="hidden" name={`file-content-${app}`}
          value={candidate.fileContentModes?.[app]} />) : candidate.fileInspection &&
          uploadApps.map((app) => <input key={app} type="hidden" name={`file-inspection-${app}`}
          value={candidate.fileInspection?.[app] ? 'on' : 'off'} />)}
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
