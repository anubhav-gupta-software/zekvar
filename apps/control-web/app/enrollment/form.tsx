'use client';

import { useActionState, useEffect, useState } from 'react';
import { utc, type Feedback, type PolicyGroup } from '../../lib/control';
import type { IssuedEnrollmentBatch } from '../../lib/enrollment';
import { cancelEnrollmentBatch, issueEnrollmentBatch } from '../actions';
import { MutationForm } from '../forms';

function useClientReady() {
  const [ready, setReady] = useState(false);
  useEffect(() => setReady(true), []);
  return ready;
}

export function EnrollmentBatchForm({ groups, groupId, requestId }: { groups: PolicyGroup[]; groupId?: string; requestId: string }) {
  const [state, action, busy] = useActionState(issueEnrollmentBatch, {} as Feedback);
  const ready = useClientReady();
  return <>
    <form action={action} className="form-row">
      <input type="hidden" name="requestId" value={state.enrollmentRequestId ?? requestId} />
      <div className="grid gap-1"><label htmlFor="enrollment-group">Rollout group</label>
        <select id="enrollment-group" name="groupId" defaultValue={groupId ?? ''}>
          <option value="">Organization baseline</option>
          {groups.map(({ id, name }) => <option key={id} value={id}>{name}</option>)}
        </select>
      </div>
      <div className="grid gap-1"><label htmlFor="grant-count">Grant count</label>
        <input id="grant-count" name="count" type="number" required min={1} max={25} defaultValue={1} />
      </div>
      <button className="button primary self-end" disabled={!ready || busy}>{busy ? 'Creating…' : 'Create enrollment batch'}</button>
    </form>
    {state.error && <p className="feedback error" role="alert">{state.error}</p>}
    {state.issuedEnrollmentBatch && <BatchCodes key={state.issuedEnrollmentBatch.id} batch={state.issuedEnrollmentBatch} />}
  </>;
}

export function CancelBatchForm({ id }: { id: string }) {
  const ready = useClientReady();
  const label = `Cancel unused grants for ${id.slice(0, 13)}`;
  if (!ready) return <button type="button" className="button small danger" aria-label={label} disabled>Cancel unused grants</button>;
  return <MutationForm action={cancelEnrollmentBatch} label="Cancel unused grants" appearance="small danger"
    accessibleLabel={label} confirmation="Cancel the unused grants in this batch? Enrolled browsers keep their access.">
    <input type="hidden" name="batchId" value={id} />
  </MutationForm>;
}

function BatchCodes({ batch }: { batch: IssuedEnrollmentBatch }) {
  const [visible, setVisible] = useState(true);
  const [feedback, setFeedback] = useState('');
  const codes = batch.grants.join('\n');
  if (!visible) return null;
  return <div className="grant-result">
    <label htmlFor="batch-grants">Enrollment grant codes</label>
    <p className="muted">Copy the codes now. Control displays them once. They expire {utc.format(new Date(batch.expiresAt))} UTC.</p>
    <textarea id="batch-grants" className="font-mono" rows={Math.min(batch.grants.length + 1, 8)} readOnly value={codes}
      autoComplete="off" spellCheck={false} onFocus={(event) => event.target.select()} />
    <div className="form-row">
      <button type="button" className="button small" onClick={async () => {
        try {
          await navigator.clipboard.writeText(codes);
          setFeedback('Grant codes copied.');
        } catch { setFeedback('Select the grant codes and copy them manually.'); }
      }}>Copy grant codes</button>
      <button type="button" className="button small" onClick={() => setVisible(false)}>Hide grant codes</button>
    </div>
    {feedback && <p role="status" className="feedback">{feedback}</p>}
  </div>;
}
