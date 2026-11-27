'use client';

import { useActionState } from 'react';
import { requestOrganizationDeletion } from '../actions';
import type { Feedback } from '../../lib/control';

export function OrganizationDeletionForm({ organization, graceDays }: { organization: string; graceDays: number }) {
  const [state, action, busy] = useActionState(requestOrganizationDeletion, {} as Feedback);
  if (state.deletionReceipt) return <div className="grid gap-2">
    <p className="feedback" role="status">{state.message}</p>
    <p className="muted" id="receipt-token-help">Store the deletion ID and receipt token now. Control shows the token once. After deletion
      completes, your operator can use them to retrieve the final signed receipt.</p>
    <label htmlFor="deletion-id">Deletion ID</label>
    <input id="deletion-id" value={state.deletionReceipt.id} readOnly className="font-mono" onFocus={(event) => event.target.select()} />
    <label htmlFor="receipt-token">Receipt token</label>
    <input id="receipt-token" value={state.deletionReceipt.token} readOnly className="font-mono" aria-describedby="receipt-token-help"
      onFocus={(event) => event.target.select()} />
    <a className="button" href="/data-deletion">Continue</a>
  </div>;
  return <div>
    <form action={action} className="grid gap-2" onSubmit={(event) => {
      if (!window.confirm(`Delete ${organization} permanently after ${graceDays} days? All Control access stops now.`)) event.preventDefault();
    }}>
      <label htmlFor="confirm-slug">Type <code>{organization}</code> to confirm</label>
      <input id="confirm-slug" name="confirmSlug" autoComplete="off" spellCheck={false} required aria-describedby="organization-deletion-help" />
      <div><button className="button danger" disabled={busy}>{busy ? 'Working…' : 'Request organization deletion'}</button></div>
    </form>
    {state.error && <p className="feedback error" role="alert">{state.error}</p>}
  </div>;
}
