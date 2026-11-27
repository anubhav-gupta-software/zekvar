import { redirect } from 'next/navigation';
import { ApiError, controlApi } from '../../lib/api';
import { canWrite, type ControlSession } from '../../lib/access';
import { utc, type Installation, type PolicyGroup } from '../../lib/control';
import { deletionStatuses, type OrganizationDeletionView } from '../../lib/deletion';
import { sessionToken } from '../../lib/session';
import { cancelOrganizationDeletion, deleteInstallationData, purgePolicyHistory } from '../actions';
import { MutationForm } from '../forms';
import { DeploymentBadge, Sidebar } from '../workspace';
import { OrganizationDeletionForm } from './forms';

async function load<T>(read: Promise<T>) {
  return read.catch((error: unknown) => {
    if (error instanceof ApiError && error.status === 401) redirect('/');
    if (error instanceof ApiError) return undefined;
    throw error;
  });
}

export default async function DataDeletionPage() {
  const token = await sessionToken();
  if (!token) redirect('/');
  const session: ControlSession | undefined = await load(controlApi.session(token));
  const owner = session?.role === 'owner';
  const suspended = Boolean(session?.deletion);
  const [view, installations, groups] = await Promise.all([
    owner ? load(controlApi.organizationDeletion(token)) : undefined,
    suspended ? undefined : load(controlApi.installations(token)),
    suspended ? undefined : load(controlApi.groups(token)),
  ]);
  const writable = canWrite(session) && !suspended;
  const revoked = installations?.filter((installation) => installation.revokedAt) ?? [];
  // While deletion is scheduled the owner can use only this page, so it renders without the navigation column.
  return <div className={suspended ? undefined : 'workspace'}>
    {!suspended && <Sidebar active="data-deletion" session={session} />}
    <main className="dashboard">
      <header className="page-heading">
        <div>{session && <p className="eyebrow">{session.organization}</p>}<h1>Data deletion</h1></div>
        <DeploymentBadge />
      </header>
      {!session && <section className="panel" role="alert">Control could not load your session. Try reloading this page.</section>}
      {owner && view && <OrganizationPanel view={view} organization={session.organization} />}
      {owner && <section className="panel" aria-labelledby="export-heading">
        <h2 id="export-heading">Export organization data</h2>
        <p className="muted">Download every retained policy version, rollout group, review, browser installation record, security event,
          triage decision, incident case, alert, and audit entry as one JSON file. Credential hashes are left out.</p>
        {view?.deletion?.status === 'deleting' ? <p className="muted">Export is unavailable while deletion is in progress.</p>
          : <a className="button" href="/data-deletion/export" download>Download organization export</a>}
      </section>}
      {writable && installations && <section className="panel table-panel" aria-labelledby="browser-deletion-heading">
        <div className="panel-heading"><h2 id="browser-deletion-heading">Delete revoked browser data</h2></div>
        <p className="muted">Permanently delete a revoked browser and its events, triage, case memberships, alert evidence, observations,
          inventory, and delivery records. The audit log keeps a record with the browser ID and the deleted counts.</p>
        {revoked.length ? <div className="table-scroll" tabIndex={0} role="region" aria-labelledby="browser-deletion-heading">
          <table aria-labelledby="browser-deletion-heading">
            <thead><tr><th>Browser</th><th>Enrolled (UTC)</th><th>Revoked (UTC)</th><th>Action</th></tr></thead>
            <tbody>{revoked.map((installation) => <RevokedRow key={installation.installationId} installation={installation} />)}</tbody>
          </table>
        </div> : <p className="empty">No revoked browsers. Revoke a browser before deleting its data.</p>}
      </section>}
      {writable && groups && <section className="panel" aria-labelledby="purge-heading">
        <h2 id="purge-heading">Purge policy history</h2>
        <p className="muted" id="purge-help">Delete superseded policy versions published before the cutoff date (00:00 UTC). Control keeps the
          current version and any version used by an open review, an active rollout, a retained event, a browser, or retained inventory,
          template, or exception evidence. Audit entries keep the version numbers.</p>
        <PurgeForm groups={groups} dryRun />
        <PurgeForm groups={groups} />
      </section>}
    </main>
  </div>;
}

function OrganizationPanel({ view, organization }: { view: OrganizationDeletionView; organization: string }) {
  const deletion = view.deletion;
  const active = deletion && (deletion.status === 'pending' || deletion.status === 'deleting');
  return <section className="panel" aria-labelledby="organization-deletion-heading">
    <div className="panel-heading"><h2 id="organization-deletion-heading">Delete this organization</h2>
      {active && <span className="badge">{deletionStatuses[deletion.status]}</span>}</div>
    {active ? <>
      <dl className="policy-fields">
        <div><dt>Requested (UTC)</dt><dd>{utc.format(new Date(deletion.requestedAt))}</dd></div>
        <div><dt>Permanent deletion starts (UTC)</dt><dd>{utc.format(new Date(deletion.purgeAfter))}</dd></div>
        {deletion.status === 'deleting' && <div><dt>Rows deleted</dt><dd>{deletion.deletedRows.toLocaleString('en-US')}</dd></div>}
      </dl>
      <p className="muted">Control access tokens, single sign-on, browser credentials, event feed keys, and alert webhooks are suspended.
        {deletion.status === 'pending' ? ' Cancel to restore them.' : ' Deletion is running and can no longer be cancelled.'}</p>
      <div className="form-row">
        <a className="button" href="/data-deletion/receipt" download>Download signed receipt</a>
        {deletion.status === 'pending' && <MutationForm action={cancelOrganizationDeletion} label="Cancel organization deletion" appearance="primary" />}
      </div>
    </> : <>
      <p className="muted" id="organization-deletion-help">Schedule permanent deletion of all {organization} data. During a {view.graceDays}-day
        grace period every credential stops working and only you can sign in to export data, download the signed receipt, or cancel.
        Encrypted backups keep deleted data until they age out under the operator’s backup retention.</p>
      {deletion?.status === 'cancelled' && <p className="muted">The previous request was cancelled on {utc.format(new Date(deletion.cancelledAt!))} UTC.</p>}
      {view.available ? <OrganizationDeletionForm organization={organization} graceDays={view.graceDays} />
        : <p role="alert">Organization deletion is unavailable until the operator configures a deletion receipt key.</p>}
    </>}
  </section>;
}

function RevokedRow({ installation }: { installation: Installation }) {
  const id = installation.installationId;
  return <tr>
    <td><code title={id}>{id.slice(0, 13)}</code></td>
    <td>{utc.format(new Date(installation.enrolledAt))}</td>
    <td>{utc.format(new Date(installation.revokedAt!))}</td>
    <td><MutationForm action={deleteInstallationData} label="Delete data" appearance="danger small" accessibleLabel={`Delete data for browser ${id.slice(0, 13)}`}
      confirmation="Permanently delete this browser and every record derived from it?">
      <input type="hidden" name="installationId" value={id} />
    </MutationForm></td>
  </tr>;
}

function PurgeForm({ groups, dryRun = false }: { groups: PolicyGroup[]; dryRun?: boolean }) {
  const prefix = dryRun ? 'preview' : 'purge';
  return <MutationForm action={purgePolicyHistory} label={dryRun ? 'Preview purge' : 'Purge policy history'} appearance={dryRun ? '' : 'danger'}
    preserveValues confirmation={dryRun ? undefined : 'Permanently delete the superseded policy versions in this scope?'}>
    {dryRun && <input type="hidden" name="dryRun" value="on" />}
    <div className="grid gap-1">
      <label htmlFor={`${prefix}-scope`}>{dryRun ? 'Preview scope' : 'Scope'}</label>
      <select id={`${prefix}-scope`} name="scope" defaultValue="baseline" aria-describedby="purge-help">
        <option value="baseline">Organization baseline</option>
        {groups.map((group) => <option key={group.id} value={group.id}>{group.name}</option>)}
      </select>
    </div>
    <div className="grid gap-1">
      <label htmlFor={`${prefix}-before`}>{dryRun ? 'Preview cutoff' : 'Published before'}</label>
      <input id={`${prefix}-before`} name="publishedBefore" type="date" required aria-describedby="purge-help"
        max={new Date().toISOString().slice(0, 10)} />
    </div>
  </MutationForm>;
}
