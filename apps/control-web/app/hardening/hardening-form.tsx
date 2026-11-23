'use client';

import { useEffect, useState } from 'react';
import { hardeningDifferences, hardeningFields, hardeningValue, mergeBrowserHardening, parseBrowserHardening,
  type BrowserHardening, type HardeningExport } from '../../lib/browser-hardening';
import { publishBrowserHardening } from '../actions';
import { MutationForm } from '../forms';

export function HardeningEditor({ version, groupId, plan, review }: {
  version: number; groupId?: string; plan: BrowserHardening; review: boolean;
}) {
  const [ready, setReady] = useState(false);
  const [draft, setDraft] = useState<BrowserHardening>();
  useEffect(() => setReady(true), []);
  const changes = draft ? hardeningDifferences(plan, draft) : [];
  return <section className="panel" aria-labelledby="edit-hardening">
    <h2 id="edit-hardening">Edit hardening settings</h2>
    <form onChange={() => setDraft(undefined)} onSubmit={(event) => {
      event.preventDefault();
      setDraft(parseBrowserHardening(new FormData(event.currentTarget)));
    }}>
      <fieldset className="border-0 m-0 p-0 min-w-0 grid gap-3" disabled={!ready}>
        {Object.entries(hardeningFields).map(([field, { label, options }]) => <div className="grid gap-1" key={field}>
          <label htmlFor={`hardening-${field}`}>{label}</label>
          <select id={`hardening-${field}`} name={field} defaultValue={hardeningValue(plan[field as keyof BrowserHardening])}>
            {Object.entries(options).map(([value, text]) => <option key={value} value={value}>{text}</option>)}
          </select>
        </div>)}
        <div><button className="button">Review hardening changes</button></div>
      </fieldset>
    </form>
    {draft && (changes.length ? <>
      <ul className="preview-changes" aria-label="Hardening changes">
        {changes.map(({ key, label, before, after }) => <li key={key}>{label} · {before} → {after}</li>)}
      </ul>
      <MutationForm action={publishBrowserHardening} label={review ? 'Request hardening review' : 'Publish hardening plan'}
        appearance="primary" confirmation={`Submit the Chrome hardening changes against version ${version}?`}>
        <input type="hidden" name="expectedVersion" value={version} />
        {groupId && <input type="hidden" name="groupId" value={groupId} />}
        {review && <input type="hidden" name="expectReview" value="on" />}
        {Object.entries(draft).map(([key, value]) => <input key={key} type="hidden" name={key} value={hardeningValue(value)} />)}
      </MutationForm>
    </> : <p className="muted" role="status">The draft matches the published plan.</p>)}
  </section>;
}

export function HardeningDownload({ version, plan }: { version: number; plan: BrowserHardening }) {
  const [ready, setReady] = useState(false);
  const [base, setBase] = useState('');
  const [feedback, setFeedback] = useState('');
  const [result, setResult] = useState<HardeningExport>();
  useEffect(() => setReady(true), []);
  function download(text: string, rollback: boolean) {
    const link = document.createElement('a');
    const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
    link.href = url;
    link.download = `chrome-hardening-v${version}${rollback ? '-rollback' : ''}.json`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
  }
  return <section className="panel" aria-labelledby="export-hardening">
    <h2 id="export-hardening">Export Chrome settings</h2>
    <fieldset className="border-0 m-0 p-0 min-w-0 grid gap-3" disabled={!ready}>
      <div className="grid gap-1">
        <label htmlFor="original-hardening-policy">Existing Chrome policy JSON</label>
        <textarea id="original-hardening-policy" value={base} onChange={(event) => {
          setBase(event.target.value);
          setResult(undefined);
          setFeedback('');
        }} rows={6} maxLength={256000} spellCheck={false} autoCapitalize="none" aria-describedby="hardening-export-hint" />
        <p id="hardening-export-hint" className="muted">Paste the flat managed-policy dictionary for the target Chrome group.
          This input stays in your browser. Use <code>{'{}'}</code> for a new policy.</p>
      </div>
      <div><button type="button" className="button" onClick={() => {
        const preview = mergeBrowserHardening(plan, base);
        setResult('result' in preview ? preview.result : undefined);
        setFeedback('error' in preview ? preview.error : '');
      }}>Review hardening export</button></div>
    </fieldset>
    {feedback && <p className="feedback error" role="alert">{feedback}</p>}
    {result && (result.changes.length ? <>
      <ul className="preview-changes" aria-label="Chrome setting changes">
        {result.changes.map(({ policy, before, after }) => <li key={policy}>
          <code>{policy}</code> · {before === undefined ? 'Unset' : String(before)} → {String(after)}
        </li>)}
      </ul>
      <details><summary>Review merged JSON</summary><pre className="deployment-json">{result.merged}</pre></details>
      <div className="form-row">
        <button type="button" className="button primary" onClick={() => download(result.merged, false)}>Download hardened Chrome policy</button>
        <button type="button" className="button" onClick={() => download(result.rollback, true)}>Download hardening rollback</button>
      </div>
    </> : <p className="muted" role="status">The existing Chrome settings already meet this plan.</p>)}
  </section>;
}
