'use client';

import { useActionState, useState } from 'react';
import type { Feedback } from '../../lib/control';
import { issueControlAccess } from '../actions';
import { CopyableCode } from '../forms';

export function IssueAccessForm({ activeIds }: { activeIds: string[] }) {
  const [state, submit, busy] = useActionState(issueControlAccess, {} as Feedback);
  const [hidden, setHidden] = useState<string>();
  const issued = state.issuedAccess;
  return <>
    <form action={submit} className="form-row">
      <div className="grid gap-1">
        <label htmlFor="access-name">Name</label>
        <input id="access-name" name="name" required minLength={2} maxLength={64} />
      </div>
      <div className="grid gap-1">
        <label htmlFor="access-role">Role</label>
        <select id="access-role" name="role">
          <option value="auditor">Auditor</option>
          <option value="administrator">Administrator</option>
        </select>
      </div>
      <div className="grid gap-1">
        <label htmlFor="access-hours">Expires after</label>
        <select id="access-hours" name="hours" defaultValue="24">
          <option value="1">1 hour</option><option value="24">1 day</option>
          <option value="168">7 days</option><option value="720">30 days</option>
        </select>
      </div>
      <button className="button primary" disabled={busy}>{busy ? 'Issuing…' : 'Issue token'}</button>
    </form>
    {state.error && <p className="feedback error" role="alert">{state.error}</p>}
    {issued && activeIds.includes(issued.access.id) && issued.access.id !== hidden && <>
      <p className="feedback" role="status">Copy the token for {issued.access.name}. Control only shows it at issuance.</p>
      <CopyableCode key={issued.access.id} id="issued-token" label="Issued token" value={issued.token} expiresAt={issued.access.expiresAt} />
      <button type="button" className="button small mt-3" onClick={() => setHidden(issued.access.id)}>Hide token</button>
    </>}
  </>;
}
