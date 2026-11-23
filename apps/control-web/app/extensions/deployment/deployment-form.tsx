'use client';

import { useEffect, useState } from 'react';
import { extensionRuleText, mergeExtensionDeployment, parseExtensionDeployment, sameExtensionDeployment, unlistedLabels,
  type DeploymentExport, type ExtensionDeployment } from '../../../lib/extension-deployment';
import { publishExtensionDeployment } from '../../actions';
import { MutationForm } from '../../forms';
import { ExtensionDeploymentChanges } from '../../policy-changes';

export function DeploymentEditor({ version, groupId, plan, review }: {
  version: number; groupId?: string; plan: ExtensionDeployment; review: boolean;
}) {
  const [ready, setReady] = useState(false);
  const [unlisted, setUnlisted] = useState(plan.unlisted);
  const [rules, setRules] = useState(() => extensionRuleText(plan));
  const [candidate, setCandidate] = useState<ExtensionDeployment>();
  const [feedback, setFeedback] = useState('');
  useEffect(() => setReady(true), []);
  function invalidate() {
    setCandidate(undefined);
    setFeedback('');
  }

  return <section className="panel" aria-labelledby="edit-deployment">
    <h2 id="edit-deployment">Edit deployment rules</h2>
    <fieldset className="border-0 m-0 p-0 min-w-0 grid gap-3" disabled={!ready}>
      <div className="grid gap-1">
        <label htmlFor="unlisted-extensions">Unlisted extensions</label>
        <select id="unlisted-extensions" value={unlisted} onChange={(event) => {
          setUnlisted(event.target.value === 'block' ? 'block' : 'preserve');
          invalidate();
        }}>
          <option value="preserve">{unlistedLabels.preserve}</option>
          <option value="block">{unlistedLabels.block}</option>
        </select>
      </div>
      <div className="grid gap-1">
        <label htmlFor="deployment-rules">Extension rules</label>
        <textarea id="deployment-rules" value={rules} onChange={(event) => { setRules(event.target.value); invalidate(); }}
          rows={6} maxLength={60000} spellCheck={false} autoCapitalize="none" aria-describedby="deployment-rule-format" />
        <p id="deployment-rule-format" className="muted">Enter one extension per line. Use <code>ID, allow</code>, <code>ID, block</code>,
          or <code>ID, force, HTTPS update manifest URL</code>.</p>
      </div>
      <div><button type="button" className="button" onClick={() => {
        const draft = parseExtensionDeployment(unlisted, rules);
        if ('error' in draft) {
          setFeedback(draft.error);
          return;
        }
        setCandidate(draft.deployment);
        setFeedback('');
      }}>Review changes</button></div>
    </fieldset>
    {feedback && <p className="feedback error" role="alert">{feedback}</p>}
    {candidate && (sameExtensionDeployment(plan, candidate)
      ? <p className="muted" role="status">The deployment rules match the published plan.</p>
      : <>
        <ul className="preview-changes" aria-label="Deployment changes">
          <ExtensionDeploymentChanges reference={plan} candidate={candidate} />
        </ul>
        <MutationForm action={publishExtensionDeployment} label={review ? 'Request deployment review' : 'Publish deployment plan'}
          confirmation={review ? 'Request review for this deployment plan?' : 'Publish this deployment plan?'} appearance="primary">
          {groupId && <input type="hidden" name="groupId" value={groupId} />}
          <input type="hidden" name="expectedVersion" value={version} />
          <input type="hidden" name="expectReview" value={review ? 'on' : 'off'} />
          <input type="hidden" name="unlisted" value={candidate.unlisted} />
          <input type="hidden" name="rules" value={extensionRuleText(candidate)} />
        </MutationForm>
      </>)}
  </section>;
}

export function DeploymentDownload({ version, plan }: { version: number; plan: ExtensionDeployment }) {
  const [ready, setReady] = useState(false);
  const [base, setBase] = useState('{}');
  const [protectedId, setProtectedId] = useState('');
  const [feedback, setFeedback] = useState('');
  const [result, setResult] = useState<DeploymentExport>();
  useEffect(() => setReady(true), []);
  function invalidate() {
    setResult(undefined);
    setFeedback('');
  }
  function download(settings: DeploymentExport['merged'], rollback: boolean) {
    const url = URL.createObjectURL(new Blob([JSON.stringify({ ExtensionSettings: settings }, null, 2) + '\n'], { type: 'application/json' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = rollback ? `chrome-extension-settings-v${version}-rollback.json` : `chrome-extension-settings-v${version}.json`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
  }
  return <section className="panel" aria-labelledby="export-deployment">
    <h2 id="export-deployment">Export Chrome policy</h2>
    <p className="muted">Use the current ExtensionSettings from the target device group. Review the merged policy, then apply it through device management.</p>
    <fieldset className="border-0 m-0 p-0 min-w-0 grid gap-3" disabled={!ready}>
      <div className="grid gap-1">
        <label htmlFor="original-chrome-policy">Existing ExtensionSettings</label>
        <textarea id="original-chrome-policy" value={base} onChange={(event) => { setBase(event.target.value); invalidate(); }}
          rows={6} maxLength={256000} spellCheck={false} autoCapitalize="none" aria-describedby="export-deployment-hint" />
        <p id="export-deployment-hint" className="muted">Paste only ExtensionSettings JSON. This input stays in your browser. Use an empty object for a group with no existing settings.</p>
      </div>
      <div className="grid gap-1">
        <label htmlFor="protected-extension-id">Pinned Zekvar Browser extension ID</label>
        <input id="protected-extension-id" value={protectedId} onChange={(event) => { setProtectedId(event.target.value); invalidate(); }}
          maxLength={32} spellCheck={false} autoCapitalize="none" autoComplete="off" />
        <p className="muted">Use the ID from the signed release. Required when blocking unlisted extensions.</p>
      </div>
      <div><button type="button" className="button" onClick={() => {
        const preview = mergeExtensionDeployment(plan, base, protectedId.trim());
        if ('error' in preview) {
          setFeedback(preview.error);
          return;
        }
        setFeedback('');
        setResult(preview.result);
      }}>Review export</button></div>
    </fieldset>
    {feedback && <p className="feedback error" role="alert">{feedback}</p>}
    {result && <>
      {result.changes.length > 0 ? <ul className="preview-changes" aria-label="Chrome policy changes">
        {result.changes.map(({ id, before, after }) => <li key={id}>
          {id === '*' ? 'Unlisted extensions' : <code>{id}</code>} · {before} → {after}
        </li>)}
      </ul> : <p className="muted" role="status">The published plan makes no changes to these Chrome settings.</p>}
      <details><summary>Review merged JSON</summary><pre className="deployment-json">{JSON.stringify({ ExtensionSettings: result.merged }, null, 2)}</pre></details>
      <div className="form-row">
        <button type="button" className="button primary" onClick={() => download(result.merged, false)}>Download Chrome policy</button>
        <button type="button" className="button" onClick={() => download(result.original, true)}>Download rollback policy</button>
      </div>
    </>}
  </section>;
}
