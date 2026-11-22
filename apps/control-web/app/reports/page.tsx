import { redirect } from 'next/navigation';
import { ApiError, controlApi } from '../../lib/api';
import { aiPromptApps, decisionLabels, decisions, promptAppLabels, ruleLabels, utc } from '../../lib/control';
import { eventTotal, reportFilters, type AiEnforcementReport, type DecisionCounts, type ReportBreakdown } from '../../lib/reports';
import { sessionToken } from '../../lib/session';
import { uploadRule } from '../../../../contracts/policy/uploads';
import { DeploymentBadge, Sidebar } from '../workspace';

const number = new Intl.NumberFormat('en-US');
const date = new Intl.DateTimeFormat('en-US', { dateStyle: 'medium', timeZone: 'UTC' });
const reportRuleLabels = { ...ruleLabels, [uploadRule]: 'AI file upload' };

export default async function Reports({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const token = await sessionToken();
  if (!token) redirect('/');
  const filters = reportFilters(await searchParams);
  const result = await Promise.all([
    controlApi.session(token),
    filters ? controlApi.aiEnforcement(token, filters.query) : undefined,
  ]).catch((error: unknown) => {
    if (error instanceof ApiError && error.status === 401) redirect('/');
    if (error instanceof ApiError) return null;
    throw error;
  });
  const [session, report] = result ?? [];
  const download = new URLSearchParams(filters?.query);
  if (report) download.set('asOf', String(Date.parse(report.asOf)));

  return <div className="workspace">
    <Sidebar active="reports" session={session} />
    <main className="dashboard">
      <header className="page-heading">
        <div>{session && <p className="eyebrow">{session.organization}</p>}<h1>AI enforcement report</h1></div>
        <DeploymentBadge />
      </header>
      <section className="panel table-panel" aria-labelledby="report-heading">
        <div className="panel-heading">
          <h2 id="report-heading">Report filters</h2>
          {report && <a className="button small" href={`/reports/export?${download}`} download>Export report (JSON)</a>}
        </div>
        <form action="/reports" method="get" className="filters">
          <div><label htmlFor="report-days">Reporting window (UTC)</label>
            <select id="report-days" name="days" defaultValue={filters?.days ?? '7'}>
              <option value="7">Last 7 days</option>
              <option value="30">Last 30 days</option>
            </select>
          </div>
          <div><label htmlFor="report-app">AI application</label>
            <select id="report-app" name="appId" defaultValue={filters?.app ?? ''}>
              <option value="">All supported AI apps</option>
              {aiPromptApps.map((app) => <option key={app} value={app}>{promptAppLabels[app]}</option>)}
            </select>
          </div>
          <button className="button">Apply report filters</button>
        </form>
        {!filters ? <p className="empty" role="alert">Choose a valid AI application and reporting window.</p> :
          !report ? <p className="empty" role="alert">Control could not load the AI enforcement report. Try reloading this page.</p> :
            <div className="table-footer">
              <p className="table-note">From <time dateTime={report.startOn}>{date.format(new Date(report.startOn))}</time> through{' '}
                <time dateTime={report.asOf}>{utc.format(new Date(report.asOf))} UTC</time></p>
              <a className="clear-link report-events-link" href="/#events">Investigate security events</a>
            </div>}
      </section>
      {report && <ReportResults report={report} />}
    </main>
  </div>;
}

function ReportResults({ report }: { report: AiEnforcementReport }) {
  const total = eventTotal(report.counts);
  const peak = Math.max(1, ...report.daily.map(({ counts }) => eventTotal(counts)));
  return <>
    <section className="metrics" aria-label="Summary of policy events">
      <article className="metric"><p>Policy events</p><strong>{number.format(total)}</strong></article>
      <article className="metric"><p>Warnings</p><strong>{number.format(report.counts.warn)}</strong></article>
      <article className="metric"><p>Blocks</p><strong>{number.format(report.counts.block)}</strong></article>
    </section>
    <section className="panel table-panel" aria-labelledby="report-daily">
      <div className="panel-heading"><h2 id="report-daily">Daily policy events</h2></div>
      <div className="table-footer report-note"><p className="table-note">
        Counts reflect retained events for supported AI apps. A warning and its override each count as an event.
      </p></div>
      {total === 0 ? <p className="empty">No retained policy events match this report.</p> :
        <div className="table-scroll" role="region" tabIndex={0} aria-labelledby="report-daily">
          <table className="report-table" aria-labelledby="report-daily">
            <thead><tr><th scope="col">Day (UTC)</th><DecisionHeaders /><th scope="col">Total</th></tr></thead>
            <tbody>{report.daily.slice().reverse().map(({ day, counts }) => {
              const dailyTotal = eventTotal(counts);
              return <tr key={day}>
                <th scope="row"><time dateTime={day}>{date.format(new Date(day))}</time></th>
                <DecisionCells counts={counts} />
                <td><div className="report-total"><meter aria-hidden="true" min={0} max={peak} value={dailyTotal} />
                  {number.format(dailyTotal)}</div></td>
              </tr>;
            })}</tbody>
          </table>
        </div>}
    </section>
    {total > 0 && <>
      <ReportBreakdownTable heading="By AI application" id="report-apps" name="Application" rows={report.byApp} labels={promptAppLabels} />
      <ReportBreakdownTable heading="By policy rule" id="report-rules" name="Rule" rows={report.byRule} labels={reportRuleLabels} />
      {report.bySource && <ReportBreakdownTable heading="By activity" id="report-source" name="Activity" rows={report.bySource}
        labels={{ prompt: 'Prompt', file_policy: 'File upload policy', file_content: 'File content inspection' }} />}
    </>}
  </>;
}

function DecisionHeaders() {
  return decisions.map((decision) => <th key={decision} scope="col">{decisionLabels[decision]}</th>);
}

function DecisionCells({ counts }: { counts: DecisionCounts }) {
  return decisions.map((decision) => <td key={decision}>{number.format(counts[decision])}</td>);
}

function ReportBreakdownTable({ heading, id, name, rows, labels }: {
  heading: string; id: string; name: string; rows: ReportBreakdown[]; labels: Readonly<Record<string, string>>;
}) {
  return <section className="panel table-panel" aria-labelledby={id}>
    <div className="panel-heading"><h2 id={id}>{heading}</h2></div>
    <div className="table-scroll" role="region" tabIndex={0} aria-labelledby={id}>
      <table className="report-table" aria-labelledby={id}>
        <thead><tr><th scope="col">{name}</th><DecisionHeaders /><th scope="col">Total</th></tr></thead>
        <tbody>{rows.map(({ id, counts }) => <tr key={id}>
          <th scope="row">{Object.hasOwn(labels, id) ? labels[id] : id}</th><DecisionCells counts={counts} />
          <td>{number.format(eventTotal(counts))}</td>
        </tr>)}</tbody>
      </table>
    </div>
  </section>;
}
