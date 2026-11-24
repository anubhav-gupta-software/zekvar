import { redirect } from 'next/navigation';
import { canWrite } from '../../lib/access';
import { alertFilters, alertNumber, alertPath, alertRollout, alertStatus, extensionAlertsPath } from '../../lib/alerts';
import { ApiError, controlApi } from '../../lib/api';
import { aiPromptApps, promptAppLabels, utc } from '../../lib/control';
import { sessionToken } from '../../lib/session';
import { saveAlertSettings } from '../actions';
import { MutationForm, RefreshSection } from '../forms';
import { DeploymentBadge, Sidebar } from '../workspace';

export default async function Alerts({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const token = await sessionToken();
  if (!token) redirect('/');
  const filters = alertFilters(await searchParams);
  const data = await Promise.all([
    controlApi.session(token), controlApi.alertSettings(token), filters ? controlApi.alerts(token, filters.query) : undefined,
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
        <div>{session && <p className="eyebrow">{session.organization}</p>}<h1>Security alerts</h1></div>
        <div className="form-row">
          <a className="button small" href={extensionAlertsPath}>Extension access alerts</a>
          <DeploymentBadge />
        </div>
      </header>
      {settings && <section className="panel" aria-labelledby="alert-settings-heading">
        <div className="panel-heading"><h2 id="alert-settings-heading">Repeated AI blocks</h2>
          <span className="badge">{settings.enabled ? 'On' : 'Off'}</span>
        </div>
        <p className="muted">Open an alert when the same AI app and recorded rollout group reach the threshold in a 15-minute window.</p>
        {canWrite(session) ? <MutationForm action={saveAlertSettings} label="Save alert settings">
          <input type="hidden" name="revision" value={settings.revision} />
          <div className="form-row">
            <div><label htmlFor="alert-mode">Alert rule</label>
              <select key={settings.revision} id="alert-mode" name="enabled" defaultValue={settings.enabled ? 'on' : 'off'}>
                <option value="off">Off</option><option value="on">On</option>
              </select>
            </div>
            <div><label htmlFor="alert-threshold">Blocked events per window</label>
              <input key={settings.revision} id="alert-threshold" name="threshold" type="number" min={2} max={100} step={1}
                required defaultValue={settings.threshold} />
            </div>
          </div>
        </MutationForm> : <p className="muted">Threshold of {settings.threshold} blocks per window</p>}
      </section>}
      <section className="panel table-panel" aria-labelledby="alert-inbox-heading">
        <div className="panel-heading"><h2 id="alert-inbox-heading">Alert inbox</h2>
          <RefreshSection label="Refresh alerts" />
        </div>
        <form action="/alerts" method="get" className="filters">
          <div><label htmlFor="alert-status">Status</label>
            <select id="alert-status" name="status" defaultValue={filters?.status ?? 'open'}>
              <option value="open">Open</option><option value="acknowledged">Acknowledged</option><option value="all">All alerts</option>
            </select>
          </div>
          <div><label htmlFor="alert-app">AI application</label>
            <select id="alert-app" name="app" defaultValue={filters?.app ?? ''}>
              <option value="">All AI applications</option>
              {aiPromptApps.map((app) => <option key={app} value={app}>{promptAppLabels[app]}</option>)}
            </select>
          </div>
          <button className="button">Apply alert filters</button>
        </form>
        {!filters ? <p className="empty" role="alert">Choose valid alert filters.</p> :
          !alerts ? <p className="empty" role="alert">Control could not load the alert inbox. Try refreshing.</p> :
            alerts.entries.length ? <div className="table-scroll" role="region" tabIndex={0} aria-labelledby="alert-inbox-heading">
              <table aria-labelledby="alert-inbox-heading"><thead>
                <tr><th>Alert</th><th>Application</th><th>Recorded rollout group</th><th>Blocks</th><th>Status</th><th>Triggered (UTC)</th></tr>
              </thead><tbody>{alerts.entries.map((alert) => <tr key={alert.id}>
                <td><a className="underline" href={alertPath(alert.id)}>Alert {alertNumber(alert.id)}</a></td>
                <td>{promptAppLabels[alert.appId]}</td><td>{alertRollout(alert)}</td>
                <td>{alert.blockCount} <span className="muted">· threshold {alert.threshold}</span></td>
                <td><span className="badge">{alertStatus(alert)}</span></td>
                <td><time dateTime={alert.triggeredAt}>{utc.format(new Date(alert.triggeredAt))}</time></td>
              </tr>)}</tbody></table>
            </div> : <p className="empty">No alerts match this view.</p>}
        {alerts && (filters?.paged || alerts.next) && <div className="table-footer">
          <div className="form-row">
            {filters?.paged && <a className="button small" href={`/alerts?${filters.page}`}>Newest alerts</a>}
            {alerts.next && <a className="button small" href={`/alerts?${next}`}>Older alerts</a>}
          </div>
        </div>}
      </section>
    </main>
  </div>;
}
