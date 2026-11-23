'use client';

import { useActionState, useState } from 'react';
import type { Feedback } from '../../lib/control';
import { issueEventFeedKey } from '../actions';
import { CopyableCode } from '../forms';

export function EventFeedForm({ requestId, activeIds }: { requestId: string; activeIds: string[] }) {
  const [state, submit, busy] = useActionState(issueEventFeedKey, {} as Feedback);
  const [hidden, setHidden] = useState<string>();
  const issued = state.issuedEventFeedKey;
  return <>
    <form action={submit} className="form-row">
      <input type="hidden" name="requestId" value={requestId} />
      <div className="grid gap-1">
        <label htmlFor="feed-key-name">Collector name</label>
        <input id="feed-key-name" name="name" required minLength={2} maxLength={64} />
      </div>
      <div className="grid gap-1">
        <label htmlFor="feed-key-days">Key lifetime (days)</label>
        <input id="feed-key-days" name="days" type="number" min={1} max={90} defaultValue={30} required />
      </div>
      <button className="button primary" disabled={busy}>{busy ? 'Issuing…' : 'Issue event feed key'}</button>
    </form>
    {state.error && <p className="feedback error" role="alert">{state.error}</p>}
    {issued && activeIds.includes(issued.key.id) && issued.key.id !== hidden && <>
      <p className="feedback" role="status">Copy the key for {issued.key.name}. Control only shows it at issuance.</p>
      <CopyableCode key={issued.key.id} id="issued-feed-key" label="Issued event feed key" value={issued.token} expiresAt={issued.key.expiresAt} />
      <button type="button" className="button small mt-3" onClick={() => setHidden(issued.key.id)}>Hide event feed key</button>
    </>}
  </>;
}
