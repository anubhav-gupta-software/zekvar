import { redirect } from 'next/navigation';
import { ApiError, controlApi } from '../../lib/api';
import { utc } from '../../lib/control';
import { drillKinds, type Attestation } from '../../lib/evidence';
import { sessionToken } from '../../lib/session';
import { recordDrill } from '../actions';
import { MutationForm } from '../forms';
import { DeploymentBadge, Sidebar } from '../workspace';

export default async function Evidence() {
  const token = await sessionToken();
  if (!token) redirect('/');
  const result = await (async () => {
    const session = await controlApi.session(token);
    if (session.role !== 'owner' && session.role !== 'auditor') return { session };
    const pages = await Promise.all(['backup_drill_recorded', 'restore_drill_recorded'].map((action) =>
      controlApi.audit(token, new URLSearchParams({ action, limit: '20' }))));
    const drills = pages.flatMap(({ entries }) => entries).filter((entry) => entry.attestation)
      .sort((left, right) => right.occurredAt.localeCompare(left.occurredAt)).map((entry) => entry.attestation as Attestation);
    return { session, drills };
  })().catch((error) => {
    if (error instanceof ApiError && error.status === 401) redirect('/');
    if (error instanceof ApiError) return null;
    throw error;
  });
  const session = result?.session;
  const allowed = session?.role === 'owner' || session?.role === 'auditor';
  const now = new Date().toISOString().slice(0, 16);

  return <div className="workspace">
    <Sidebar active="evidence" session={session} />
    <main className="dashboard">
      <header className="page-heading">
        <div>{session && <p className="eyebrow">{session.organization}</p>}<h1>Compliance evidence</h1></div>
        <DeploymentBadge />
      </header>
      {!result ? <section className="panel" role="alert">Control could not load compliance evidence. Try reloading this page.</section> :
        !allowed ? <section className="panel" role="alert">Only the organization owner and auditors can download compliance evidence.</section> : <>
        <section className="panel" aria-labelledby="pack-heading">
          <h2 id="pack-heading">Evidence pack</h2>
          <p className="muted" id="pack-help">A dated JSON bundle of policy version history, review and rollout approvals, access reviews,
            retention settings, recorded drills, audit counts, and data encryption status. It contains no security event records, prompt text,
            detection terms, or credentials. Each download is recorded in the audit log.</p>
          <form action="/evidence/export" method="get" className="filters">
            <div><label htmlFor="pack-days">Period (days)</label>
              <select id="pack-days" name="days" defaultValue="90" aria-describedby="pack-help">
                <option value="30">30</option><option value="90">90</option><option value="180">180</option><option value="365">365</option>
              </select>
            </div>
            <button className="button primary">Download evidence pack</button>
          </form>
        </section>
        {session?.role === 'owner' && <section className="panel" aria-labelledby="drill-heading">
          <h2 id="drill-heading">Record a backup or restore drill</h2>
          <p className="muted">Record each scheduled backup check or recovery rehearsal with its archive checksum and measured recovery time.</p>
          <MutationForm action={recordDrill} label="Record drill" appearance="primary">
            <div className="grid gap-1"><label htmlFor="drill-kind">Drill</label>
              <select id="drill-kind" name="kind">{Object.entries(drillKinds).map(([kind, label]) =>
                <option key={kind} value={kind}>{label}</option>)}</select></div>
            <div className="grid gap-1"><label htmlFor="drill-time">Performed (UTC)</label>
              <input id="drill-time" name="performedAt" type="datetime-local" required defaultValue={now} max={now} /></div>
            <div className="grid gap-1"><label htmlFor="drill-outcome">Outcome</label>
              <select id="drill-outcome" name="outcome"><option value="succeeded">Succeeded</option><option value="failed">Failed</option></select></div>
            <div className="grid gap-1"><label htmlFor="drill-operator">Operator</label>
              <input id="drill-operator" name="operator" required minLength={2} maxLength={64} /></div>
            <div className="grid gap-1"><label htmlFor="drill-checksum">Archive SHA-256</label>
              <input id="drill-checksum" name="archiveSha256" pattern="[a-fA-F0-9]{64}" maxLength={64} spellCheck={false} autoComplete="off" /></div>
            <div className="grid gap-1"><label htmlFor="drill-minutes">Recovery time (minutes)</label>
              <input id="drill-minutes" name="recoveryMinutes" type="number" min={0} max={10080} step={1} /></div>
            <div className="grid gap-1"><label htmlFor="drill-notes">Notes</label>
              <textarea id="drill-notes" name="notes" maxLength={1000} rows={2} /></div>
          </MutationForm>
        </section>}
        <section className="panel table-panel" aria-labelledby="drills-heading">
          <div className="panel-heading"><h2 id="drills-heading">Recorded drills</h2></div>
          {result.drills?.length ? <div className="table-scroll" role="region" tabIndex={0} aria-labelledby="drills-heading">
            <table aria-labelledby="drills-heading">
              <thead><tr><th>Performed (UTC)</th><th>Drill</th><th>Outcome</th><th>Operator</th><th>Recovery</th><th>Archive</th></tr></thead>
              <tbody>{result.drills.map((drill) => <tr key={drill.id}>
                <td><time dateTime={drill.performedAt}>{utc.format(new Date(drill.performedAt!))}</time></td>
                <td className="emphasis">{drillKinds[drill.kind as keyof typeof drillKinds]}</td>
                <td>{drill.outcome === 'succeeded' ? 'Succeeded' : <span className="badge block">Failed</span>}</td>
                <td>{drill.operator}</td>
                <td>{drill.recoveryMinutes != null ? `${drill.recoveryMinutes} min` : '—'}</td>
                <td>{drill.archiveSha256 ? <code title={drill.archiveSha256}>{drill.archiveSha256.slice(0, 12)}</code> : '—'}</td>
              </tr>)}</tbody>
            </table>
          </div> : <p className="empty">No drills have been recorded within the audit retention window.</p>}
        </section>
      </>}
    </main>
  </div>;
}
