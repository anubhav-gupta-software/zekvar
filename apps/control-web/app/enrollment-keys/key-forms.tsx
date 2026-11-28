'use client';

import { useActionState, useEffect, useState } from 'react';
import { utc, type Feedback, type PolicyGroup } from '../../lib/control';
import { maxKeyDays, maxKeyRedemptions, policySnippets, snippetErrors, type IssuedEnrollmentKey,
  type SnippetError } from '../../lib/enrollment-keys';
import { issueEnrollmentKey, revokeEnrollmentKey, rotateEnrollmentKey } from '../actions';
import { MutationForm } from '../forms';

function useClientReady() {
  const [ready, setReady] = useState(false);
  useEffect(() => setReady(true), []);
  return ready;
}

export function CreateKeyForm({ groups, requestId }: { groups: PolicyGroup[]; requestId: string }) {
  const [state, action, busy] = useActionState(issueEnrollmentKey, {} as Feedback);
  const ready = useClientReady();
  return <>
    <form action={action} className="form-row items-end">
      <input type="hidden" name="requestId" value={state.enrollmentKeyRequestId ?? requestId} />
      <div className="grid gap-1"><label htmlFor="key-label">Label</label>
        <input id="key-label" name="label" required minLength={2} maxLength={64} placeholder="Intune finance laptops" />
      </div>
      <div className="grid gap-1"><label htmlFor="key-group">Rollout group</label>
        <select id="key-group" name="groupId" defaultValue="">
          <option value="">Organization baseline</option>
          {groups.map(({ id, name }) => <option key={id} value={id}>{name}</option>)}
        </select>
      </div>
      <div className="grid gap-1"><label htmlFor="key-days">Lifetime in days</label>
        <input id="key-days" name="days" type="number" required min={1} max={maxKeyDays} defaultValue={14} />
      </div>
      <div className="grid gap-1"><label htmlFor="key-limit">Maximum browsers</label>
        <input id="key-limit" name="maxRedemptions" type="number" required min={1} max={maxKeyRedemptions} defaultValue={50} />
      </div>
      <button className="button primary" disabled={!ready || busy}>{busy ? 'Creating…' : 'Create enrollment key'}</button>
    </form>
    {state.error && <p className="feedback error" role="alert">{state.error}</p>}
    {state.issuedEnrollmentKey && <IssuedKey key={state.issuedEnrollmentKey.token} issued={state.issuedEnrollmentKey} idPrefix="created" />}
  </>;
}

export function RotateKeyForm({ keys, requestId }: { keys: { id: string; label: string }[]; requestId: string }) {
  const [state, action, busy] = useActionState(rotateEnrollmentKey, {} as Feedback);
  const ready = useClientReady();
  return <>
    <form action={action} className="form-row items-end">
      <input type="hidden" name="requestId" value={state.enrollmentKeyRequestId ?? requestId} />
      <div className="grid gap-1"><label htmlFor="rotate-key">Key to replace</label>
        <select id="rotate-key" name="keyId" required>
          {keys.map(({ id, label }) => <option key={id} value={id}>{label} · {id.slice(0, 8)}</option>)}
        </select>
      </div>
      <div className="grid gap-1"><label htmlFor="rotate-days">New key lifetime in days</label>
        <input id="rotate-days" name="days" type="number" required min={1} max={maxKeyDays} defaultValue={14} />
      </div>
      <div className="grid gap-1"><label htmlFor="rotate-overlap">Keep the old key for</label>
        <select id="rotate-overlap" name="overlapHours" defaultValue="72">
          <option value="">Until it expires</option>
          <option value="24">24 hours</option>
          <option value="72">3 days</option>
          <option value="168">7 days</option>
        </select>
      </div>
      <button className="button" disabled={!ready || busy}>{busy ? 'Rotating…' : 'Rotate enrollment key'}</button>
    </form>
    <p className="muted">The new key keeps the label, rollout group, and limit. Push it to the device manager, confirm new browsers enroll, then revoke the old key.</p>
    {state.error && <p className="feedback error" role="alert">{state.error}</p>}
    {state.issuedEnrollmentKey && <IssuedKey key={state.issuedEnrollmentKey.token} issued={state.issuedEnrollmentKey} idPrefix="rotated" />}
  </>;
}

export function KeyActions({ id, label }: { id: string; label: string }) {
  const ready = useClientReady();
  const accessible = `Revoke enrollment key ${label}`;
  if (!ready) return <button type="button" className="button small danger" aria-label={accessible} disabled>Revoke key</button>;
  return <MutationForm action={revokeEnrollmentKey} label="Revoke key" appearance="small danger" accessibleLabel={accessible}
    confirmation={`Revoke ${label}? Browsers that have not enrolled yet will be rejected. Enrolled browsers keep access until you revoke them.`}>
    <input type="hidden" name="keyId" value={id} />
  </MutationForm>;
}

function IssuedKey({ issued, idPrefix }: { issued: IssuedEnrollmentKey; idPrefix: string }) {
  const [visible, setVisible] = useState(true);
  const [status, setStatus] = useState('');
  if (!visible) return <p className="feedback" role="status">Key hidden. Control cannot show it again.</p>;
  return <div className="grant-result">
    <label htmlFor={`${idPrefix}-key`}>Enrollment key</label>
    <p className="muted">Copy it now. Control displays it once. {issued.key.label} · {issued.key.groupName ?? 'Organization baseline'} ·
      {' '}{issued.key.maxRedemptions ? `up to ${issued.key.maxRedemptions} browsers` : 'no limit'} · expires {utc.format(new Date(issued.key.expiresAt))} UTC.</p>
    <div className="form-row">
      <input id={`${idPrefix}-key`} className="font-mono min-w-0 flex-1" value={issued.token} readOnly autoComplete="off" spellCheck={false}
        onFocus={(event) => event.target.select()} />
      <button type="button" className="button small" onClick={async () => {
        try {
          await navigator.clipboard.writeText(issued.token);
          setStatus('Enrollment key copied.');
        } catch { setStatus('Select the key and copy it manually.'); }
      }}>Copy key</button>
      <button type="button" className="button small" onClick={() => setVisible(false)}>Hide key</button>
    </div>
    {status && <p role="status" className="feedback">{status}</p>}
    <PolicySnippetBuilder idPrefix={idPrefix} initialKey={issued.token} />
  </div>;
}

const fieldLabels: Record<SnippetError, string> = {
  extensionId: 'Enter the 32-letter extension ID of the signed release.',
  updateUrl: 'Enter the HTTPS update manifest URL.',
  controlOrigin: 'Enter the exact Control browser API origin.',
  key: 'Enter an enrollment key that starts with zke_.',
};

export function PolicySnippetBuilder({ idPrefix, initialKey = '' }: { idPrefix: string; initialKey?: string }) {
  const [input, setInput] = useState({ extensionId: '', updateUrl: '', controlOrigin: '', key: initialKey });
  const [selected, setSelected] = useState('google-admin');
  const [status, setStatus] = useState('');
  const errors = snippetErrors(input);
  const snippets = errors.length ? [] : policySnippets(input);
  const snippet = snippets.find(({ id }) => id === selected);
  const field = (name: keyof typeof input, label: string, placeholder: string) => <div className="grid gap-1 min-w-0">
    <label htmlFor={`${idPrefix}-${name}`}>{label}</label>
    <input id={`${idPrefix}-${name}`} value={input[name]} placeholder={placeholder} autoComplete="off" spellCheck={false}
      className={name === 'key' ? 'font-mono' : undefined}
      onChange={(event) => { setInput({ ...input, [name]: event.target.value.trim() }); setStatus(''); }} />
  </div>;
  return <div className="grid gap-3 mt-3" role="group" aria-label="Managed policy snippet">
    <div className="policy-fields">
      {field('extensionId', 'Extension ID', 'abcdefghijklmnopabcdefghijklmnop')}
      {field('updateUrl', 'Update URL', 'https://updates.example.com/pilot/updates.xml')}
      {field('controlOrigin', 'Control origin', 'https://browser.example.com')}
      {!initialKey && field('key', 'Key for snippets', 'zke_…')}
    </div>
    {errors.length > 0 ? <ul className="muted" aria-label="Snippet inputs needed">{errors.map((error) => <li key={error}>{fieldLabels[error]}</li>)}</ul> : <>
      <div className="grid gap-1"><label htmlFor={`${idPrefix}-manager`}>Device manager</label>
        <select id={`${idPrefix}-manager`} value={selected} onChange={(event) => { setSelected(event.target.value); setStatus(''); }}>
          {snippets.map(({ id, title }) => <option key={id} value={id}>{title}</option>)}
        </select>
      </div>
      {snippet && <>
        <p className="muted"><strong>{snippet.target}.</strong> {snippet.steps}</p>
        <label htmlFor={`${idPrefix}-snippet`}>{snippet.title} policy</label>
        <textarea id={`${idPrefix}-snippet`} className="deployment-json font-mono w-full" rows={12} readOnly value={snippet.content}
          spellCheck={false} onFocus={(event) => event.target.select()} />
        <div className="form-row">
          <button type="button" className="button small" onClick={async () => {
            try {
              await navigator.clipboard.writeText(snippet.content);
              setStatus(`${snippet.title} policy copied.`);
            } catch { setStatus('Select the policy and copy it manually.'); }
          }}>Copy policy</button>
        </div>
        {status && <p role="status" className="feedback">{status}</p>}
        <p className="muted">These snippets follow each vendor&apos;s documented Chrome policy format and have not been verified in Google Admin, Intune, or Jamf by Zekvar. Test on a canary group first.</p>
      </>}
    </>}
  </div>;
}
