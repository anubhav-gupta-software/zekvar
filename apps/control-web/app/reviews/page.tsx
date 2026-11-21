import { redirect } from 'next/navigation';
import type { ControlSession } from '../../lib/access';
import { ApiError, controlApi } from '../../lib/api';
import { utc } from '../../lib/control';
import { previewSnapshot, samePolicy } from '../../lib/preview';
import { reviewOperations, reviewStatuses, type PolicyReview } from '../../lib/reviews';
import { sessionToken } from '../../lib/session';
import { decidePolicyReview, setPolicyReview } from '../actions';
import { MutationForm, RefreshSection } from '../forms';
import { PolicyChanges } from '../policy-changes';
import { Sidebar } from '../workspace';

export default async function PolicyReviewPage() {
  const token = await sessionToken();
  if (!token) redirect('/');
  const result = await Promise.all([controlApi.session(token), controlApi.policyReviews(token)]).catch((error) => {
    if (error instanceof ApiError && error.status === 401) redirect('/');
    if (error instanceof ApiError) return undefined;
    throw error;
  });
  return <div className="workspace">
    <Sidebar active="reviews" session={result?.[0]} />
    <main className="dashboard">
      <header className="page-heading">
        <div>{result && <p className="eyebrow">{result[0].organization}</p>}<h1>Policy reviews</h1></div>
        <span className="badge local"><span aria-hidden="true" />Local demo</span>
      </header>
      {result ? <ReviewQueue session={result[0]} required={result[1].required} entries={result[1].entries} /> :
        <section className="panel" role="alert">Control could not load policy reviews. Reload to try again.</section>}
    </main>
  </div>;
}

function ReviewQueue({ session, required, entries }: { session: ControlSession; required: boolean; entries: PolicyReview[] }) {
  return <>
    <section className="panel" aria-labelledby="requirement-heading">
      <div className="panel-heading">
        <h2 id="requirement-heading">Two-person approval</h2>
        <span className={`badge ${required ? 'current' : ''}`}>{required ? 'Required' : 'Optional'}</span>
      </div>
      <p className="muted">When required, a named administrator requests a change and a different administrator approves it. Requests expire after 24 hours.</p>
      {session.role === 'owner' && <MutationForm action={setPolicyReview} label={required ? 'Disable required reviews' : 'Require policy reviews'}
        appearance={required ? 'danger' : 'primary'} confirmation={required ?
          'Disable required reviews and cancel pending requests?' : 'Require two named administrators for policy changes?'}>
        <input type="hidden" name="required" value={required ? 'off' : 'on'} />
      </MutationForm>}
    </section>
    <section className="panel" aria-labelledby="requests-heading">
      <div className="panel-heading"><h2 id="requests-heading">Review requests</h2><RefreshSection label="Refresh policy reviews" /></div>
      {entries.length ? <div className="grid gap-3">
        {entries.map((entry) => <ReviewRequest key={entry.id} entry={entry} session={session} required={required} />)}
      </div> : <p className="muted">No policy reviews yet.</p>}
    </section>
  </>;
}

function ReviewRequest({ entry, session, required }: { entry: PolicyReview; session: ControlSession; required: boolean }) {
  const scope = entry.groupName ?? 'Organization baseline';
  const before = previewSnapshot(entry.snapshots.before, scope);
  const after = previewSnapshot(entry.snapshots.candidate, scope);
  const canDecide = required && entry.status === 'pending' && session.role === 'administrator' && session.access;
  const own = session.access?.id === entry.requester.id;
  const sameName = session.access?.name.toLowerCase() === entry.requester.name.toLowerCase();
  return <article className="panel" id={`review-${entry.id}`} aria-label={`${reviewOperations[entry.operation]} for ${scope}`}>
    <div className="panel-heading">
      <h3>{reviewOperations[entry.operation]} · {scope}</h3>
      <span className={`badge ${entry.status === 'approved' ? 'current' : ''}`}>{reviewStatuses[entry.status]}</span>
    </div>
    <p className="muted">Requested by {entry.requester.name} · {utc.format(new Date(entry.requestedAt))} UTC</p>
    <p>Reference v{before.version}
      {entry.sourceVersion && <> · Source {entry.sourceGroupName && `${entry.sourceGroupName} `}v{entry.sourceVersion}</>}
      {entry.publishedVersion && <> · Published v{entry.publishedVersion}</>}
    </p>
    {entry.status === 'pending' && <p className="muted">Expires {utc.format(new Date(entry.expiresAt))} UTC</p>}
    {entry.status === 'stale' && <p className="muted">The policy or requesting credential changed. Submit a fresh request from the current policy.</p>}
    {entry.reviewer && <p className="muted">{reviewStatuses[entry.status]} by {entry.reviewer.name}</p>}
    <details open={entry.status === 'pending'}>
      <summary>Policy changes</summary>
      {samePolicy(before, after) ? <p className="muted">The settings match the reference version.</p> :
        <PolicyChanges reference={before} candidate={after} />}
    </details>
    {canDecide && <div className="form-row mt-3">
      {!own && !sameName && <MutationForm action={decidePolicyReview} label="Approve and publish" appearance="primary"
        confirmation={`Publish the reviewed policy to ${scope}?`}>
        <input type="hidden" name="id" value={entry.id} />
        <input type="hidden" name="decision" value="approve" />
      </MutationForm>}
      <MutationForm action={decidePolicyReview} label={own ? 'Withdraw request' : 'Reject request'}
        confirmation={own ? 'Withdraw this policy review request?' : 'Reject this policy review request?'}>
        <input type="hidden" name="id" value={entry.id} />
        <input type="hidden" name="decision" value="close" />
      </MutationForm>
    </div>}
  </article>;
}
