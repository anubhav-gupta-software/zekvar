import { randomUUID } from 'node:crypto';
import { redirect } from 'next/navigation';
import { ApiError, controlApi } from '../../lib/api';
import { canWrite } from '../../lib/access';
import { utc } from '../../lib/control';
import type { EnrollmentBatch } from '../../lib/enrollment';
import { sessionToken } from '../../lib/session';
import { RefreshSection } from '../forms';
import { DeploymentBadge, Sidebar } from '../workspace';
import { CancelBatchForm, EnrollmentBatchForm } from './form';

export default async function Enrollment({ searchParams }: { searchParams: Promise<{ group?: string | string[] }> }) {
  const token = await sessionToken();
  if (!token) redirect('/');
  const { group } = await searchParams;
  const result = await Promise.all([controlApi.session(token), controlApi.groups(token), controlApi.enrollmentBatches(token)]).catch((error) => {
    if (error instanceof ApiError && error.status === 401) redirect('/');
    if (error instanceof ApiError) return undefined;
    throw error;
  });
  const [session, groups, batches] = result ?? [];
  const selected = groups?.find(({ id }) => id === group);
  const writable = canWrite(session);
  return <div className="workspace">
    <Sidebar active="enrollment" session={session} />
    <main className="dashboard">
      <header className="page-heading">
        <div>{session && <p className="eyebrow">{session.organization}</p>}<h1>Enrollment batches</h1></div>
        <DeploymentBadge />
      </header>
      {groups && writable && <section className="panel" aria-labelledby="create-enrollment-heading">
        <h2 id="create-enrollment-heading">Create a batch</h2>
        <p className="muted">Issue one single-use grant per browser profile. Grants expire in 10 minutes. Direct group enrollment requires Browser v0.21.0 or later.</p>
        {group !== undefined && !selected ? <p role="alert">That rollout group is unavailable. <a className="underline" href="/enrollment">Choose another group</a>.</p>
          : <EnrollmentBatchForm groups={groups} groupId={selected?.id} requestId={randomUUID()} />}
      </section>}
      <section className="panel table-panel" aria-labelledby="recent-batches">
        <div className="panel-heading"><h2 id="recent-batches">Recent batches</h2><RefreshSection label="Refresh enrollment batches" /></div>
        {batches ? <>
          <div className="table-scroll" tabIndex={0} role="region" aria-labelledby="recent-batches">
            <table aria-labelledby="recent-batches">
              <thead><tr><th>Batch</th><th>Rollout group</th><th>Status</th><th>Redeemed</th><th>Available</th><th>Expires (UTC)</th>{writable && <th>Action</th>}</tr></thead>
              <tbody>{batches.map((batch) => <BatchRow key={batch.id} batch={batch} writable={writable} />)}</tbody>
            </table>
          </div>
          {batches.length === 0 && <p className="empty">No enrollment batches yet.</p>}
          {batches.length === 100 && <p className="empty">Showing the latest 100 batches.</p>}
        </> : <p className="empty" role="alert">Control could not load enrollment batches. Try refreshing this page.</p>}
      </section>
    </main>
  </div>;
}

const statusLabels = { open: 'Open', used: 'Fully redeemed', expired: 'Expired', cancelled: 'Cancelled' };

function BatchRow({ batch, writable }: { batch: EnrollmentBatch; writable: boolean }) {
  return <tr>
    <td><code title={batch.id}>{batch.id.slice(0, 13)}</code></td>
    <td>{batch.groupName ?? 'Organization baseline'}</td>
    <td>{statusLabels[batch.status]}</td>
    <td>{batch.redeemed} of {batch.size}</td>
    <td>{batch.available}</td>
    <td><time dateTime={batch.expiresAt}>{utc.format(new Date(batch.expiresAt))}</time></td>
    {writable && <td>{batch.available > 0 ? <CancelBatchForm id={batch.id} /> : '—'}</td>}
  </tr>;
}
