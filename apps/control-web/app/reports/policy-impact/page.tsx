import { redirect } from 'next/navigation';
import { ApiError, controlApi } from '../../../lib/api';
import { composerStateLabels, composerStates, promptAppLabels, utc } from '../../../lib/control';
import { policyImpactQuery, type PolicyImpactReport } from '../../../lib/policy-impact';
import { sessionToken } from '../../../lib/session';
import { DeploymentBadge, Sidebar } from '../../workspace';
import { RefreshSection } from '../../forms';

const format = new Intl.NumberFormat('en-US');
const path = '/reports/policy-impact';
type Search = Record<string, string | string[] | undefined>;

export default async function ImpactPage({ searchParams }: { searchParams: Promise<Search> }) {
  const token = await sessionToken();
  if (!token) redirect('/');
  const search = await searchParams;
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(search)) {
    for (const item of Array.isArray(value) ? value : value === undefined ? [] : [value]) query.append(key, item);
  }
  const result = await Promise.all([controlApi.session(token), controlApi.groups(token), loadReport(token, query)])
    .catch((error: unknown) => {
      if (error instanceof ApiError && error.status === 401) redirect('/');
      if (error instanceof ApiError) return undefined;
      throw error;
    });
  const [session, groups, outcome] = result ?? [];
  const report = outcome?.report;
  const groupId = groups?.find(({ id }) => id === query.get('scope')?.toLowerCase())?.id;
  const latest = `${path}?${policyImpactQuery(groupId)}`;

  return <div className="workspace">
    <Sidebar active="reports" session={session} />
    <main className="dashboard">
      <header className="page-heading">
        <div>{session && <p className="eyebrow">{session.organization}</p>}<h1>Policy rollout impact</h1></div>
        <DeploymentBadge />
      </header>
      {groups && <section className="panel" aria-labelledby="impact-scope">
        <div className="panel-heading"><h2 id="impact-scope">Destination policy</h2><RefreshSection label="Refresh rollout impact" /></div>
        <form action={path} method="get" className="form-row preview-scope">
          <div className="grid min-w-0 max-w-full gap-1">
            <label htmlFor="impact-group">Scope</label>
            <select id="impact-group" name="scope" defaultValue={groupId ?? 'baseline'} className="max-w-full">
              <option value="baseline">Organization baseline and inheriting groups</option>
              {groups.map(({ id, name }) => <option key={id} value={id}>{name}</option>)}
            </select>
          </div>
          <button className="button">View impact</button>
        </form>
      </section>}
      {report ? <ImpactResults report={report} /> : <section className="panel" role="alert">
        {outcome?.status === 409 ? <>The reviewed policy version changed. <a className="underline" href={latest}>Open the current rollout impact</a>.</> :
          outcome?.status === 404 ? 'This policy scope or report is unavailable.' :
            outcome?.status === 400 ? 'Choose a valid destination scope and reviewed version.' :
              'Control could not load rollout impact. Try reloading the page.'}
      </section>}
    </main>
  </div>;
}

async function loadReport(token: string, query: URLSearchParams) {
  try {
    return { report: await controlApi.policyImpact(token, query), status: 200 };
  } catch (error) {
    if (error instanceof ApiError && error.status !== 401) return { report: undefined, status: error.status };
    throw error;
  }
}

function ImpactResults({ report }: { report: PolicyImpactReport }) {
  const { scope, totals, cohorts, outsideScope, freshness } = report;
  const label = scope.groupName ?? 'Organization baseline';
  const pending = totals.active - totals.reportingAndAcknowledged;
  const download = policyImpactQuery(scope.groupId, scope.policyVersion);
  return <>
    <section className="panel" aria-labelledby="impact-summary">
      <div className="panel-heading"><h2 id="impact-summary">{label} · v{scope.policyVersion}</h2>
        <a className="button small" download href={`${path}/export?${download}`}>Export fresh snapshot (JSON)</a></div>
      <p className="muted">Snapshot at <time dateTime={report.asOf}>{utc.format(new Date(report.asOf))} UTC</time>.</p>
      <div className="metrics impact-metrics" aria-label="Rollout impact counts">
        <article className="metric"><p>Browsers in scope</p><strong>{format.format(totals.active)}</strong></article>
        <article className="metric"><p>Reporting and current</p><strong>{format.format(totals.reportingAndAcknowledged)}</strong></article>
        <article className="metric"><p>Stale or pending</p><strong>{format.format(pending)}</strong></article>
        <article className="metric"><p>Browsers outside scope</p><strong>{format.format(outsideScope)}</strong></article>
      </div>
      {!scope.groupId ? <p className="muted">Baseline changes reach unassigned browsers and groups that inherit the baseline.</p>
        : scope.followsBaseline && <p className="muted">Publishing a policy for this group makes it independent of the baseline.</p>}
    </section>
    <section className="panel table-panel" aria-labelledby="impact-cohorts">
      <div className="panel-heading"><h2 id="impact-cohorts">Affected rollout cohorts</h2></div>
      <div className="table-scroll" role="region" tabIndex={0} aria-labelledby="impact-cohorts">
        <table aria-labelledby="impact-cohorts">
          <thead><tr><th scope="col">Cohort</th><th scope="col">Browsers</th><th scope="col">Reporting</th>
            <th scope="col">Policy acknowledged</th><th scope="col">Reporting and current</th></tr></thead>
          <tbody>{cohorts.map(({ groupId, groupName, counts }) => <tr key={groupId ?? 'baseline'}>
            <th scope="row">{groupName ?? 'Unassigned browsers'}</th>
            <td>{format.format(counts.active)}</td><td>{format.format(counts.reporting)}</td>
            <td>{format.format(counts.acknowledged)}</td><td>{format.format(counts.reportingAndAcknowledged)}</td>
          </tr>)}</tbody>
        </table>
      </div>
      <p className="table-footer table-note">Reporting uses a {freshness.heartbeatSeconds}-second check-in window.</p>
    </section>
    <section className="panel table-panel" aria-labelledby="impact-composers">
      <div className="panel-heading"><h2 id="impact-composers">Composer coverage on v{scope.policyVersion}</h2></div>
      <div className="table-scroll" role="region" tabIndex={0} aria-labelledby="impact-composers">
        <table aria-labelledby="impact-composers">
          <thead><tr><th scope="col">Application</th>
            {composerStates.map((state) => <th scope="col" key={state}>{composerStateLabels[state]}</th>)}</tr></thead>
          <tbody>{report.composers.map(({ appId, counts }) => <tr key={appId}>
            <th scope="row">{promptAppLabels[appId]}</th>
            {composerStates.map((state) => <td key={state}>{format.format(counts[state])}</td>)}
          </tr>)}</tbody>
        </table>
      </div>
      <p className="table-footer table-note">Test the proposed policy on a managed canary to confirm enforcement.</p>
    </section>
  </>;
}
