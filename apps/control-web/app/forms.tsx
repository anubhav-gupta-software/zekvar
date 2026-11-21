'use client';

import { useActionState, useState, useTransition, type ReactNode } from 'react';
import { useRouter } from 'next/navigation';
import { issueGrant, publishDomainRules, signIn } from './actions';
import { utc, type DomainRules, type Feedback, type PathRules } from '../lib/control';

export function RefreshSection({ label }: { label: string }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  return <button type="button" className="button small" aria-label={label} disabled={pending}
    onClick={() => startTransition(() => router.refresh())}>{pending ? 'Refreshing…' : 'Refresh'}</button>;
}

export function DomainRulesForm({ rules, paths, version, groupId }: {
  rules?: DomainRules; paths?: PathRules; version?: number; groupId?: string;
}) {
  return <MutationForm action={publishDomainRules} label="Publish navigation rules" appearance="primary">
    {groupId && <input type="hidden" name="groupId" value={groupId} />}
    <input type="hidden" name="expectedVersion" value={version ?? ''} />
    <p className="muted" id="domain-policy-scope">
      Enter one hostname or hostname/path per line, such as <code>example.com/work</code>. Rules cover top-level
      navigation and include subdomains. Chrome checks the most specific hostname first, then the longest matching path.
    </p>
    <div className="policy-fields" key={version}>
      <DomainList name="allow" label="Allowed domains" initial={rules?.allow} />
      <DomainList name="block" label="Blocked domains" initial={rules?.block} />
      <DomainList name="allowPaths" label="Allowed paths" initial={paths?.allow} />
      <DomainList name="blockPaths" label="Blocked paths" initial={paths?.block} />
    </div>
  </MutationForm>;
}

function DomainList({ name, label, initial }: { name: string; label: string; initial?: string[] }) {
  const [value, setValue] = useState(initial?.join('\n') ?? '');
  return <div className="grid gap-1">
    <label htmlFor={`${name}-domains`}>{label}</label>
    <textarea id={`${name}-domains`} name={name} rows={3} maxLength={16000} spellCheck={false} autoCapitalize="none"
      value={value} onChange={(event) => setValue(event.target.value)} aria-describedby="domain-policy-scope" />
  </div>;
}

function Notice({ state }: { state: Feedback }) {
  if (state.error) return <p className="feedback error" role="alert">{state.error}</p>;
  if (state.message) return <p className="feedback" role="status">{state.message}</p>;
  return null;
}

export function SignInForm({ invalid }: { invalid?: boolean }) {
  const [state, action, busy] = useActionState(signIn, invalid ? { error: 'Your session ended. Sign in again.' } : {});
  return <form action={action} className="grid gap-3">
    <label htmlFor="token">Control token</label>
    <input id="token" name="token" type="password" autoComplete="off" spellCheck={false}
      required placeholder="Enter your Control API token" />
    <button className="button primary mt-2" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
    <Notice state={state} />
  </form>;
}

export function MutationForm({ action, children, label, appearance = '', confirmation, accessibleLabel }: {
  action: (state: Feedback, data: FormData) => Promise<Feedback>;
  children?: ReactNode;
  label: string;
  appearance?: string;
  confirmation?: string;
  accessibleLabel?: string;
}) {
  const [state, submit, busy] = useActionState(action, {});
  return <div>
    <form action={submit} className="form-row" onSubmit={(event) => {
      if (confirmation && !window.confirm(confirmation)) event.preventDefault();
    }}>
      {children}
      <button className={`button ${appearance}`} aria-label={accessibleLabel} disabled={busy}>
        {busy ? 'Working…' : label}
      </button>
    </form>
    <Notice state={state} />
  </div>;
}

export function EnrollmentForm() {
  const [state, action, busy] = useActionState(issueGrant, {} as Feedback);
  return <>
    <form action={action}>
      <button className="button" disabled={busy}>{busy ? 'Creating…' : 'Create enrollment grant'}</button>
    </form>
    <Notice state={state} />
    {state.grant && <EnrollmentCode key={state.grant.grant} value={state.grant.grant} expiresAt={state.grant.expiresAt} />}
  </>;
}

function EnrollmentCode({ value, expiresAt }: { value: string; expiresAt: string }) {
  return <CopyableCode id="enrollment-grant" label="Enrollment grant" value={value} expiresAt={expiresAt} />;
}

export function CopyableCode({ id, label, value, expiresAt }: { id: string; label: string; value: string; expiresAt: string }) {
  const [status, setStatus] = useState('');
  return <div className="grant-result">
    <label htmlFor={id}>{label}</label>
    <div className="form-row">
      <input id={id} value={value} readOnly autoComplete="off" className="font-mono" onFocus={(event) => event.target.select()} />
      <button type="button" className="button small" onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setStatus('Copied.');
        } catch {
          setStatus('Select the value and copy it manually.');
        }
      }}>Copy</button>
    </div>
    <p className="muted">Expires {utc.format(new Date(expiresAt))} UTC.</p>
    {status && <p role="status" className="feedback">{status}</p>}
  </div>;
}
