import { redirect } from 'next/navigation';
import { ApiError, controlApi } from '../../lib/api';
import { roleLabels } from '../../lib/access';
import { reviewOperations, reviewStatuses } from '../../lib/reviews';
import { auditActions, auditFilters, type AuditEntry } from '../../lib/audit';
import { aiApps, classificationLabels, utc } from '../../lib/control';
import { cleanupCounts, retentionFields, type RetentionField } from '../../lib/retention';
import { sessionToken } from '../../lib/session';
import { DeploymentBadge, Sidebar } from '../workspace';

export default async function Audit({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const token = await sessionToken();
  if (!token) redirect('/');
  const filters = auditFilters(await searchParams);
  const result = await Promise.all([
    controlApi.session(token),
    filters ? controlApi.audit(token, filters.query) : undefined,
  ]).catch((error) => {
    if (error instanceof ApiError && error.status === 401) redirect('/');
    if (error instanceof ApiError) return null;
    throw error;
  });
  const [session, audit] = result ?? [];
  const previousFilters = filters?.page.toString();
  const older = new URLSearchParams(filters?.page);
  if (audit?.next) {
    older.set('beforeAt', audit.next.occurredAt);
    older.set('beforeId', audit.next.id);
  }

  return <div className="workspace">
    <Sidebar active="audit" session={session} />
    <main className="dashboard">
      <header className="page-heading">
        <div>{session && <p className="eyebrow">{session.organization}</p>}<h1>Audit log</h1></div>
        <DeploymentBadge />
      </header>
      <section className="panel table-panel" aria-labelledby="audit-heading">
        <div className="panel-heading">
          <h2 id="audit-heading">Control activity</h2>
          {audit && <a className="button small" href={`/audit/export?${previousFilters ?? ''}`} download>Export JSON</a>}
        </div>
        <form action="/audit" method="get" className="filters">
          <div><label htmlFor="audit-action">Action</label>
            <select id="audit-action" name="action" defaultValue={filters?.action ?? ''}>
              <option value="">All actions</option>
              {Object.entries(auditActions).map(([action, label]) => <option key={action} value={action}>{label}</option>)}
            </select>
          </div>
          <div><label htmlFor="audit-from">From (UTC)</label>
            <input id="audit-from" name="from" type="date" defaultValue={filters?.from ?? ''} />
          </div>
          <div><label htmlFor="audit-through">Through (UTC)</label>
            <input id="audit-through" name="through" type="date" defaultValue={filters?.through ?? ''} />
          </div>
          <button className="button">Apply filters</button>
          {previousFilters && <a className="clear-link" href="/audit">Clear filters</a>}
        </form>
        {!filters ? <p className="empty" role="alert">Choose a valid action and date range, then apply the filters.</p> :
          !audit ? <p className="empty" role="alert">Control could not load the audit log. Try reloading this page.</p> :
          <>
            <div className="table-scroll" role="region" tabIndex={0} aria-labelledby="audit-heading">
              <table aria-labelledby="audit-heading">
                <thead><tr><th>Time (UTC)</th><th>Action</th><th>Actor</th><th>Details</th></tr></thead>
                <tbody>{audit.entries.map((entry) => <AuditRow key={entry.id} entry={entry} />)}</tbody>
              </table>
            </div>
            {!audit.entries.length && <p className="empty">No audit entries match this view.</p>}
            <div className="table-footer">
              <p className="table-note">JSON export includes up to 1,000 matching entries, newest first.</p>
              <div className="form-row">
                {filters.beforeAt && <a className="button small" href={`/audit?${previousFilters ?? ''}`}>Newest entries</a>}
                {audit.next && <a className="button small" href={`/audit?${older}`}>Older entries</a>}
              </div>
            </div>
          </>}
      </section>
    </main>
  </div>;
}

const actorLabels = { organization_admin: 'Organization admin', named_administrator: 'Named administrator',
  sso_identity: 'Single sign-on identity', browser_enrollment: 'Browser enrollment', system: 'Scheduled cleanup' };

function auditDetails(entry: AuditEntry) {
  const batch = entry.enrollmentBatchChange;
  if (batch) return <>{entry.installationId && <><code title={entry.installationId}>{entry.installationId.slice(0, 13)}</code> · </>}
    {batch.groupName ?? 'Organization baseline'} · {batch.count} {batch.count === 1 ? 'grant' : 'grants'} ·
    {' '}<code title={batch.batchId}>{batch.batchId.slice(0, 13)}</code></>;
  const review = entry.reviewChange;
  if (review?.reviewId) return <>{review.operation && reviewOperations[review.operation]} · {review.status && reviewStatuses[review.status]}
    {review.publishedVersion && <> · v{review.publishedVersion}</>} · <code title={review.reviewId}>{review.reviewId.slice(0, 13)}</code></>;
  if (review) return <>{review.required ? 'Reviews required' : 'Reviews optional'}
    {!!review.cancelled && <> · {review.cancelled} cancelled</>}</>;
  const credential = entry.subjectAccess;
  if (credential) return <span title={credential.id}>{credential.name} · {roleLabels[credential.role]}</span>;
  const group = entry.groupChange;
  if (group?.sourceVersion) return `v${entry.policyVersion} promoted from ${group.groupName} v${group.sourceVersion}`;
  if (group?.installationId) return <><code title={group.installationId}>{group.installationId.slice(0, 13)}</code> · {group.groupName ?? 'Organization baseline'}</>;
  if (group?.groupName) return `${group.groupName}${entry.policyVersion ? ` · v${entry.policyVersion}${entry.restoredFrom ? ` from v${entry.restoredFrom}` : ''}` : ''}`;
  if (entry.policyVersion) return `v${entry.policyVersion}${entry.restoredFrom ? ` from v${entry.restoredFrom}` : ''}`;
  if (entry.installationId) return <code title={entry.installationId}>{entry.installationId.slice(0, 13)}</code>;
  if (entry.appId && entry.classification) {
    return `${aiApps[entry.appId as keyof typeof aiApps] ?? 'Custom app'} · ${classificationLabels[entry.classification]}`;
  }
  if (entry.cleanup) return cleanupCounts(entry.cleanup);
  if (entry.retention) {
    const policy = entry.retention;
    return <ul>{(Object.keys(retentionFields) as RetentionField[]).map((field) =>
      <li key={field}>{retentionFields[field]} · {policy[field] === null ? 'No expiry' : policy[field] === 1 ? '1 day' : `${policy[field]} days`}</li>)}</ul>;
  }
  return '—';
}

function AuditRow({ entry }: { entry: AuditEntry }) {
  return <tr>
    <td><time dateTime={entry.occurredAt}>{utc.format(new Date(entry.occurredAt))}</time></td>
    <td className="emphasis">{auditActions[entry.action]}</td>
    <td>{entry.actorAccess ? <span title={entry.actorAccess.id}>{entry.actorAccess.name}</span> : actorLabels[entry.actor]}</td>
    <td>{auditDetails(entry)}</td>
  </tr>;
}
