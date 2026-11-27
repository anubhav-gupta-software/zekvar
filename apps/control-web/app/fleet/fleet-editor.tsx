'use client';

import { useActionState, useState } from 'react';
import { utc, type Feedback, type PolicyGroup } from '../../lib/control';
import type { FleetBrowser, FleetRequest } from '../../lib/fleet';
import { applyFleetChange } from '../actions';

type ReviewedBatch = { request: FleetRequest; destination?: string; browsers: FleetBrowser[] };

export function FleetEditor({ entries, writable, groups, baselineVersion }: {
  entries: FleetBrowser[]; writable: boolean; groups: PolicyGroup[]; baselineVersion?: number;
}) {
  const [selected, setSelected] = useState<string[]>([]);
  const [operation, setOperation] = useState<FleetRequest['operation']>('assign');
  const [target, setTarget] = useState('');
  const [review, setReview] = useState<ReviewedBatch>();
  const destination = groups.find(({ id }) => id === target);
  const version = destination?.effectiveVersion ?? baselineVersion;
  const selection = entries.filter(({ installationId }) => selected.includes(installationId));
  const movable = selection.every((browser) => browser.assignmentAware || browser.groupId === (destination?.id ?? null));

  function editSelection(id: string, checked: boolean) {
    setReview(undefined);
    setSelected((prior) => checked ? prior.length < 25 ? [...prior, id] : prior : prior.filter((entry) => entry !== id));
  }

  function reviewBatch() {
    setReview({
      destination: operation === 'assign' ? destination?.name ?? 'Organization baseline' : undefined,
      browsers: selection,
      request: {
        requestId: crypto.randomUUID(), operation, groupId: operation === 'assign' ? destination?.id ?? null : null,
        expectedPolicyVersion: operation === 'assign' ? version! : null,
        selections: selection.map(({ installationId, assignmentVersion }) => ({ installationId, assignmentVersion })),
      },
    });
  }

  return <>
    <section className="panel table-panel" aria-labelledby="fleet-browsers-heading">
      <div className="panel-heading"><h2 id="fleet-browsers-heading">Active browsers</h2>
        {writable && <div className="form-row">
          <span className="table-note" aria-live="polite">{selection.length} selected · Maximum 25</span>
          {entries.length > 0 && <button type="button" className="button small" disabled={!!review}
            onClick={() => { setReview(undefined); setSelected(entries.slice(0, 25).map(({ installationId }) => installationId)); }}>
            Select first {Math.min(entries.length, 25)} shown</button>}
          {selection.length > 0 && <button type="button" className="button small" disabled={!!review}
            onClick={() => { setReview(undefined); setSelected([]); }}>Clear selection</button>}
        </div>}
      </div>
      {entries.length ? <div className="table-scroll" tabIndex={0} role="region" aria-labelledby="fleet-browsers-heading">
        <table aria-labelledby="fleet-browsers-heading">
          <thead><tr>{writable && <th scope="col">Select</th>}<th scope="col">Installation</th><th scope="col">Assigned group</th>
            <th scope="col">Expected policy</th><th scope="col">Browser version</th><th scope="col">Last seen (UTC)</th></tr></thead>
          <tbody>{entries.map((browser) => {
            const id = browser.installationId;
            const shortId = id.slice(0, 13);
            const checked = selected.includes(id);
            return <tr key={id}>
              {writable && <td><input type="checkbox" aria-label={`Select browser ${shortId}`} checked={checked}
                disabled={!!review || !checked && selection.length >= 25} onChange={(event) => editSelection(id, event.target.checked)} /></td>}
              <th scope="row"><code title={id}>{shortId}</code></th>
              <td>{browser.groupName ?? 'Organization baseline'}{!browser.assignmentAware && <div className="muted">Update and sync to move</div>}</td>
              <td>v{browser.expectedPolicyVersion}</td><td>{browser.extensionVersion ?? 'Unreported'}</td>
              <td><time dateTime={browser.lastSeenAt}>{utc.format(new Date(browser.lastSeenAt))}</time></td>
            </tr>;
          })}</tbody>
        </table>
      </div> : <p className="empty">No active browsers match this view.</p>}
    </section>
    {writable && entries.length > 0 && <section className="panel" aria-labelledby="fleet-action-heading">
      <h2 id="fleet-action-heading">Bulk browser action</h2>
      <div className="form-row">
        <div className="grid gap-1">
          <label htmlFor="fleet-operation">Action</label>
          <select id="fleet-operation" value={operation} disabled={!!review} onChange={(event) => {
            setOperation(event.target.value === 'revoke' ? 'revoke' : 'assign');
            setReview(undefined);
          }}>
            <option value="assign">Assign to rollout group</option><option value="revoke">Revoke browser access</option>
          </select>
        </div>
        {operation === 'assign' && <div className="grid gap-1">
          <label htmlFor="fleet-destination">Destination</label>
          <select id="fleet-destination" value={target} disabled={!!review} onChange={(event) => { setTarget(event.target.value); setReview(undefined); }}>
            <option value="">Organization baseline{baselineVersion ? ` · v${baselineVersion}` : ''}</option>
            {groups.map(({ id, name, effectiveVersion }) => <option key={id} value={id}>{name} · v{effectiveVersion}</option>)}
          </select>
        </div>}
        <button type="button" className="button" disabled={!!review || !selection.length || (operation === 'assign' && (!version || !movable))}
          onClick={reviewBatch}>Review browser batch</button>
      </div>
      {operation === 'assign' && !movable && <p className="feedback" role="status">Update and sync the selected browsers that require an upgrade, or clear those selections.</p>}
    </section>}
    {review && <FleetSubmit key={review.request.requestId} batch={review} edit={() => setReview(undefined)}
      reset={() => { setReview(undefined); setSelected([]); }} />}
  </>;
}

function FleetSubmit({ batch, edit, reset }: { batch: ReviewedBatch; edit: () => void; reset: () => void }) {
  const [state, submit, busy] = useActionState(applyFleetChange, {} as Feedback);
  const { request } = batch;
  const revoking = request.operation === 'revoke';
  const count = request.selections.length;
  return <section className="panel" aria-labelledby="review-fleet-heading">
    <h2 id="review-fleet-heading">Review browser batch</h2>
    {state.fleetChange ? <>
      <p className="feedback" role="status">{state.fleetChange.changedInstallations.length} of {state.fleetChange.selectedCount} browsers changed.
        {' '}Batch <code>{state.fleetChange.batchId}</code>.</p>
      <div className="form-row">
        <button type="button" className="button" onClick={reset}>Start another batch</button>
        <a className="button small" href="/audit?action=browser_fleet_changed">Review fleet audit</a>
      </div>
    </> : <>
      <p className="muted">{revoking ? 'Revoked browsers need a fresh enrollment to reconnect.' :
        `Assign to ${batch.destination} with reviewed policy v${request.expectedPolicyVersion}. Browsers sync to their new rollout policy.`}</p>
      <ul className="preview-changes" aria-label="Browsers in this batch">
        {batch.browsers.map(({ installationId, groupName }) => <li key={installationId}>
          <code title={installationId}>{installationId.slice(0, 13)}</code> · {groupName ?? 'Organization baseline'}
        </li>)}
      </ul>
      <form action={submit} className="form-row" onSubmit={(event) => {
        if (!window.confirm(revoking ? `Revoke access for ${count} selected browsers?` : `Assign ${count} selected browsers to ${batch.destination}?`)) {
          event.preventDefault();
        }
      }}>
        <input type="hidden" name="requestId" value={request.requestId} />
        <input type="hidden" name="operation" value={request.operation} />
        <input type="hidden" name="selections" value={JSON.stringify(request.selections)} />
        {!revoking && <><input type="hidden" name="groupId" value={request.groupId ?? ''} />
          <input type="hidden" name="expectedPolicyVersion" value={request.expectedPolicyVersion ?? ''} /></>}
        <button className={`button ${revoking ? 'danger' : 'primary'}`} disabled={busy}>
          {busy ? 'Working…' : revoking ? 'Revoke selected browsers' : 'Assign selected browsers'}
        </button>
        <button type="button" className="button" onClick={edit} disabled={busy}>Edit selection</button>
      </form>
      {state.error && <p className="feedback error" role="alert">{state.error}</p>}
    </>}
  </section>;
}
