import { redirect } from 'next/navigation';
import { ApiError, controlApi, type SaasInventoryApp } from '../../lib/api';
import { canWrite } from '../../lib/access';
import { isSaasCategory, isSaasClassification, isSaasRisk, saasApp, saasCatalog, saasCatalogVersion, saasCategories,
  saasClassificationLabels, saasClassifications, saasRisks, type SaasApp } from '../../../../contracts/policy/saas-catalog';
import { sessionToken } from '../../lib/session';
import { classifySaasApp } from '../actions';
import { MutationForm, RefreshSection } from '../forms';
import { DeploymentBadge, Sidebar } from '../workspace';

type Filters = { category?: string | string[]; risk?: string | string[]; status?: string | string[]; seen?: string | string[] };
type Row = SaasInventoryApp & { app: SaasApp };

function single(value: string | string[] | undefined) {
  return typeof value === 'string' ? value : undefined;
}

export default async function SaasInventoryPage({ searchParams }: { searchParams: Promise<Filters> }) {
  const token = await sessionToken();
  if (!token) redirect('/');
  const query = await searchParams;
  const category = single(query.category);
  const risk = single(query.risk);
  const status = single(query.status);
  const seen = single(query.seen) === 'seen';
  const data = await Promise.all([controlApi.session(token), controlApi.saasApps(token)]).catch((error) => {
    if (error instanceof ApiError && error.status === 401) redirect('/');
    if (error instanceof ApiError) return undefined;
    throw error;
  });
  const [session, inventory] = data ?? [];
  const writable = canWrite(session);
  const rows: Row[] = (inventory?.apps ?? []).flatMap((entry) => {
    const app = saasApp(entry.appId);
    return app ? [{ ...entry, app }] : [];
  }).filter(({ app, status: current, browsersSeen }) => (!isSaasCategory(category) || app.category === category) &&
    (!isSaasRisk(risk) || app.risk === risk) && (!isSaasClassification(status) || current === status) && (!seen || browsersSeen > 0))
    .sort((a, b) => b.browsersSeen - a.browsersSeen || a.app.name.localeCompare(b.app.name));
  const observed = (inventory?.apps ?? []).filter(({ browsersSeen }) => browsersSeen > 0).length;

  return <div className="workspace">
    <Sidebar active="saas" session={session} />
    <main className="dashboard">
      <header className="page-heading">
        <div>{session && <p className="eyebrow">{session.organization}</p>}<h1>SaaS inventory</h1></div>
        <DeploymentBadge />
      </header>
      {inventory ? <>
        <section className="panel" aria-labelledby="saas-summary-heading">
          <h2 id="saas-summary-heading">Catalog and collection</h2>
          <p className="muted">Bundled catalog v{inventory.catalogVersion} · {saasCatalog.length} apps · {observed} seen in the last
            {' '}{inventory.windowDays} days · SaaS app inventory is <strong>{inventory.discoveryEnabled ? 'on' : 'off'}</strong> in current policies.</p>
          <p className="muted">Browser v0.43.0 or later reports only the catalog app and the UTC day after the browser grants the catalog
            discovery permission. Page addresses, paths, queries, and titles never leave the browser. Turn it on per scope with
            {' '}<strong>SaaS app inventory</strong> under Policies or Policy preview. Records follow the AI observations retention window.</p>
          {inventory.catalogVersion !== saasCatalogVersion && <p role="status">Control and the dashboard use different catalog versions.</p>}
        </section>
        <section className="panel table-panel" aria-labelledby="saas-heading">
          <div className="panel-heading"><h2 id="saas-heading">SaaS apps</h2><RefreshSection label="Refresh SaaS inventory" /></div>
          <form className="filters" method="get" action="/saas" aria-label="Filter SaaS apps">
            <div><label htmlFor="saas-category">Category</label>
              <select id="saas-category" name="category" defaultValue={isSaasCategory(category) ? category : ''}>
                <option value="">All categories</option>
                {Object.entries(saasCategories).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
              </select></div>
            <div><label htmlFor="saas-risk">Risk</label>
              <select id="saas-risk" name="risk" defaultValue={isSaasRisk(risk) ? risk : ''}>
                <option value="">All risks</option>
                {Object.entries(saasRisks).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
              </select></div>
            <div><label htmlFor="saas-status">Classification</label>
              <select id="saas-status" name="status" defaultValue={isSaasClassification(status) ? status : ''}>
                <option value="">All classifications</option>
                {saasClassifications.map((value) => <option key={value} value={value}>{saasClassificationLabels[value]}</option>)}
              </select></div>
            <div><label htmlFor="saas-seen">Activity</label>
              <select id="saas-seen" name="seen" defaultValue={seen ? 'seen' : ''}>
                <option value="">All catalog apps</option><option value="seen">Seen in window</option>
              </select></div>
            <button className="button small">Apply filters</button>
          </form>
          <div className="table-scroll" tabIndex={0} role="region" aria-labelledby="saas-heading">
            <table aria-labelledby="saas-heading">
              <thead><tr><th>Application</th><th>Category</th><th>Risk</th><th>Browsers seen ({inventory.windowDays} days)</th>
                <th>Seen (UTC days)</th><th>Classification</th><th>Enforcement</th></tr></thead>
              <tbody>{rows.map((row) => <SaasRow key={row.appId} row={row} writable={writable} />)}</tbody>
            </table>
          </div>
          {rows.length === 0 && <p className="empty">No catalog apps match these filters.</p>}
        </section>
      </> : <section className="panel" role="alert">Control could not load the SaaS inventory. Try reloading this page.</section>}
    </main>
  </div>;
}

function SaasRow({ row, writable }: { row: Row; writable: boolean }) {
  const { app } = row;
  return <tr>
    <th scope="row" className="emphasis">{app.name}
      <div className="muted">{[...app.domains, ...app.hosts].join(', ')}</div></th>
    <td>{saasCategories[app.category]}</td>
    <td><span className={`badge ${app.risk === 'business' ? 'monitor' : 'warn'}`}>{saasRisks[app.risk]}</span></td>
    <td>{row.browsersSeen}</td>
    <td>{row.lastSeenDay ? <>First {row.firstSeenDay}<div className="muted">Last {row.lastSeenDay}</div></> : '—'}</td>
    <td>{writable ? <MutationForm action={classifySaasApp} label="Save" appearance="small" accessibleLabel={`Save ${app.name} classification`}>
      <input type="hidden" name="appId" value={app.id} />
      <select key={row.status} name="status" aria-label={`${app.name} classification`} defaultValue={row.status}>
        {saasClassifications.map((value) => <option key={value} value={value}>{saasClassificationLabels[value]}</option>)}
      </select>
    </MutationForm> : saasClassificationLabels[row.status]}</td>
    <td>{writable && row.status === 'unsanctioned' ?
      <a className="button small" href={`/preview?blockSaas=${encodeURIComponent(app.id)}#draft-heading`}
        aria-label={`Block ${app.name} in policy preview`}>Block in preview</a> : '—'}</td>
  </tr>;
}
