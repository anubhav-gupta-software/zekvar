import { redirect } from 'next/navigation';
import { ApiError, controlApi } from '../../lib/api';
import { roleLabels } from '../../lib/access';
import { utc } from '../../lib/control';
import { credentialCreators, credentialKinds, staleDaysValue, type AccessReviewCredential } from '../../lib/evidence';
import { sessionToken } from '../../lib/session';
import { attestAccessReview } from '../actions';
import { MutationForm } from '../forms';
import { DeploymentBadge, Sidebar } from '../workspace';

const statuses = { active: 'Active', expired: 'Expired', revoked: 'Revoked' };
const roles = { ...roleLabels, event_feed: 'Event feed' };

export default async function AccessReview({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const token = await sessionToken();
  if (!token) redirect('/');
  const staleDays = staleDaysValue((await searchParams).staleDays);
  const result = await (async () => {
    const session = await controlApi.session(token);
    if (session.role !== 'owner' && session.role !== 'auditor') return { session };
    return { session, report: staleDays ? await controlApi.accessReview(token, staleDays) : undefined };
  })().catch((error) => {
    if (error instanceof ApiError && error.status === 401) redirect('/');
    if (error instanceof ApiError) return null;
    throw error;
  });
  const session = result?.session;
  const report = result?.report;
  const allowed = session?.role === 'owner' || session?.role === 'auditor';

  return <div className="workspace">
    <Sidebar active="access-review" session={session} />
    <main className="dashboard">
      <header className="page-heading">
        <div>{session && <p className="eyebrow">{session.organization}</p>}<h1>Access review</h1></div>
        <DeploymentBadge />
      </header>
      {!result ? <section className="panel" role="alert">Control could not load the access review. Try reloading this page.</section> :
        !allowed ? <section className="panel" role="alert">Only the organization owner and auditors can view the access review.</section> : <>
        <section className="panel" aria-labelledby="review-summary-heading">
          <div className="panel-heading"><h2 id="review-summary-heading">Credentials to review</h2>
            {report && <span className="badge">Generated {utc.format(new Date(report.generatedAt))} UTC</span>}</div>
          <p className="muted">Confirm each person still needs their role, revoke credentials that are no longer needed in <strong>Control access</strong>,
            then record the review. The record lists the reviewed credential set and appears in the audit log and evidence pack.</p>
          <form action="/access-review" method="get" className="filters">
            <div><label htmlFor="stale-days">Stale after (days unused)</label>
              <input id="stale-days" name="staleDays" type="number" min={1} max={365} step={1} defaultValue={staleDays ?? 90} />
            </div>
            <button className="button">Apply</button>
          </form>
          {!report ? <p className="empty" role="alert">Choose a stale threshold from 1 to 365 days.</p> :
            <dl className="policy-fields" aria-label="Access review summary">
              <div><dt>Active credentials</dt><dd>{report.summary.active}</dd></div>
              <div><dt>Stale credentials</dt><dd className={report.summary.stale ? 'emphasis' : undefined}>{report.summary.stale}</dd></div>
              <div><dt>SSO identities</dt><dd>{report.summary.ssoIdentities}</dd></div>
              <div><dt>Event feed keys</dt><dd>{report.summary.eventFeedKeys}</dd></div>
            </dl>}
        </section>
        {report && <section className="panel table-panel" aria-labelledby="review-credentials-heading">
          <div className="panel-heading"><h2 id="review-credentials-heading">Credential inventory</h2></div>
          <div className="table-scroll" role="region" tabIndex={0} aria-labelledby="review-credentials-heading">
            <table aria-labelledby="review-credentials-heading">
              <thead><tr><th>Name</th><th>Type</th><th>Role</th><th>SSO subject</th><th>Status</th><th>Last used (UTC)</th>
                <th>Expires (UTC)</th><th>Created by</th></tr></thead>
              <tbody>{report.credentials.map((credential) => <CredentialRow key={`${credential.kind}-${credential.id ?? 'owner'}`} credential={credential} />)}</tbody>
            </table>
          </div>
        </section>}
        {report && session?.role === 'owner' && <section className="panel" aria-labelledby="attest-heading">
          <h2 id="attest-heading">Record review</h2>
          <p className="muted" id="attest-help">Recording fails if credentials change after this report loaded.</p>
          <MutationForm action={attestAccessReview} label="Record access review" appearance="primary">
            <input type="hidden" name="fingerprint" value={report.fingerprint} />
            <input type="hidden" name="staleDays" value={report.staleDays} />
            <div className="grid gap-1">
              <label htmlFor="reviewer">Reviewer name</label>
              <input id="reviewer" name="reviewer" required minLength={2} maxLength={64} autoComplete="name" aria-describedby="attest-help" />
            </div>
            <div className="grid gap-1">
              <label htmlFor="review-notes">Notes</label>
              <textarea id="review-notes" name="notes" maxLength={1000} rows={3} />
            </div>
          </MutationForm>
        </section>}
        {report && <section className="panel table-panel" aria-labelledby="attestations-heading">
          <div className="panel-heading"><h2 id="attestations-heading">Recorded reviews</h2></div>
          {report.attestations.length ? <div className="table-scroll" role="region" tabIndex={0} aria-labelledby="attestations-heading">
            <table aria-labelledby="attestations-heading">
              <thead><tr><th>Recorded (UTC)</th><th>Reviewer</th><th>Credentials</th><th>Notes</th></tr></thead>
              <tbody>{report.attestations.map((entry) => <tr key={entry.id}>
                <td><time dateTime={entry.recordedAt}>{utc.format(new Date(entry.recordedAt))}</time></td>
                <td className="emphasis">{entry.reviewer}</td>
                <td>{entry.activeCredentials} active · {entry.staleCredentials} stale over {entry.staleDays} days</td>
                <td className="whitespace-pre-line">{entry.notes || '—'}</td>
              </tr>)}</tbody>
            </table>
          </div> : <p className="empty">No access reviews have been recorded within the audit retention window.</p>}
        </section>}
      </>}
    </main>
  </div>;
}

function CredentialRow({ credential }: { credential: AccessReviewCredential }) {
  return <tr>
    <td className="emphasis">{credential.name}{credential.stale && <> <span className="badge warn">Stale</span></>}</td>
    <td>{credentialKinds[credential.kind]}</td>
    <td>{roles[credential.role]}</td>
    <td>{credential.subject ? <code title={credential.issuer ?? undefined}>{credential.subject}</code> : '—'}</td>
    <td>{statuses[credential.status]}</td>
    <td>{credential.lastUsedAt ? <time dateTime={credential.lastUsedAt}>{utc.format(new Date(credential.lastUsedAt))}</time> : 'Never'}</td>
    <td>{credential.expiresAt ? <time dateTime={credential.expiresAt}>{utc.format(new Date(credential.expiresAt))}</time> : 'No expiry'}</td>
    <td>{credentialCreators[credential.createdBy]}</td>
  </tr>;
}
