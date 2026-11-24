import { redirect } from 'next/navigation';
import { canWrite } from '../../../lib/access';
import { alertFilters, alertNumber, alertStatus, extensionAlertPath, extensionAlertsPath } from '../../../lib/alerts';
import { ApiError, controlApi } from '../../../lib/api';
import { utc } from '../../../lib/control';
import { sessionToken } from '../../../lib/session';
import { saveExtensionAlertSettings } from '../../actions';
import { MutationForm, RefreshSection } from '../../forms';
import { DeploymentBadge, Sidebar } from '../../workspace';

export default async function ExtensionAlerts({ searchParams }: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const token = await sessionToken();
  if (!token) redirect('/');
  const search = await searchParams;
  const filters = Object.keys(search).every((key) => ['status', 'beforeAt', 'beforeId'].includes(key)) ? alertFilters(search) : undefined;
  const data = await Promise.all([
    controlApi.session(token), controlApi.extensionAlertSettings(token), filters ? controlApi.extensionAlerts(token, filters.query) : undefined,
  ]).catch((error: unknown) => {
    if (error instanceof ApiError && error.status === 401) redirect('/?session=ended');
    if (error instanceof ApiError) return undefined;
    throw error;
  });
  const [session, settings, alerts] = data ?? [];
  const next = new URLSearchParams(filters?.page);
  if (alerts?.next) {
    next.set('beforeAt', alerts.next.triggeredAt);
    next.set('beforeId', alerts.next.id);
  }
  return <div className="workspace">
    <Sidebar active="alerts" session={session} />
    <main className="dashboard">
      <header className="page-heading">
        <div>{session && <p className="eyebrow">{session.organization}</p>}<h1>Extension access alerts</h1></div>
        <div className="form-row"><a className="button small" href="/alerts">AI block alerts</a><DeploymentBadge /></div>
      </header>
      {settings && <section className="panel" aria-labelledby="extension-alert-settings-heading">
        <div className="panel-heading"><h2 id="extension-alert-settings-heading">Alert rule</h2>
          <span className="badge">{settings.enabled ? 'On' : 'Off'}</span></div>
        <p className="muted">Open one alert per inventory report when an enabled extension gains site access, a selected privileged permission, or a risky install source.</p>
        {canWrite(session) && <MutationForm action={saveExtensionAlertSettings} label="Save extension alert settings">
          <input type="hidden" name="revision" value={settings.revision} />
          <label htmlFor="extension-alert-mode">Alert on expanded access</label>
          <select key={settings.revision} id="extension-alert-mode" name="enabled" defaultValue={settings.enabled ? 'on' : 'off'}>
            <option value="off">Off</option><option value="on">On</option>
          </select>
        </MutationForm>}
      </section>}
      <section className="panel table-panel" aria-labelledby="extension-alert-inbox-heading">
        <div className="panel-heading"><h2 id="extension-alert-inbox-heading">Extension alert inbox</h2>
          <RefreshSection label="Refresh extension alerts" /></div>
        <form action={extensionAlertsPath} method="get" className="filters">
          <div><label htmlFor="extension-alert-status">Status</label>
            <select id="extension-alert-status" name="status" defaultValue={filters?.status ?? 'open'}>
              <option value="open">Open</option><option value="acknowledged">Acknowledged</option><option value="all">All alerts</option>
            </select>
          </div>
          <button className="button">Apply alert filters</button>
        </form>
        {!filters ? <p className="empty" role="alert">Choose valid alert filters.</p> : !alerts ?
          <p className="empty" role="alert">Control could not load extension alerts. Try refreshing.</p> : alerts.entries.length ?
            <div className="table-scroll" role="region" tabIndex={0} aria-labelledby="extension-alert-inbox-heading">
              <table aria-labelledby="extension-alert-inbox-heading"><thead>
                <tr><th>Alert</th><th>Browser</th><th>Rollout group</th><th>Extensions</th><th>Status</th><th>Reported (UTC)</th></tr>
              </thead><tbody>{alerts.entries.map((alert) => <tr key={alert.id}>
                <td><a className="underline" href={extensionAlertPath(alert.id)}>Extension alert {alertNumber(alert.id)}</a></td>
                <td><code title={alert.installationId}>{alert.installationId.slice(0, 13)}</code></td>
                <td>{alert.groupName ?? 'Organization baseline'}</td>
                <td>{alert.changeCount}</td><td><span className="badge">{alertStatus(alert)}</span></td>
                <td><time dateTime={alert.triggeredAt}>{utc.format(new Date(alert.triggeredAt))}</time></td>
              </tr>)}</tbody></table>
            </div> : <p className="empty">No extension alerts match this view.</p>}
        {alerts && (filters?.paged || alerts.next) && <div className="table-footer"><div className="form-row">
          {filters?.paged && <a className="button small" href={`${extensionAlertsPath}?${filters.page}`}>Newest alerts</a>}
          {alerts.next && <a className="button small" href={`${extensionAlertsPath}?${next}`}>Older alerts</a>}
        </div></div>}
      </section>
    </main>
  </div>;
}
