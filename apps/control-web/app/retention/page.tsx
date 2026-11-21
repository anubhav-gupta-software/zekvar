import { redirect } from 'next/navigation';
import { ApiError, controlApi } from '../../lib/api';
import { retentionFields, type RetentionField } from '../../lib/retention';
import { sessionToken } from '../../lib/session';
import { cleanupRetention, saveRetention } from '../actions';
import { MutationForm } from '../forms';
import { Sidebar } from '../workspace';

export default async function RetentionPage() {
  const token = await sessionToken();
  if (!token) redirect('/');
  const result = await Promise.all([controlApi.session(token), controlApi.retention(token)]).catch((error) => {
    if (error instanceof ApiError && error.status === 401) redirect('/');
    if (error instanceof ApiError) return null;
    throw error;
  });
  const [session, policy] = result ?? [];
  return <div className="workspace">
    <Sidebar active="retention" />
    <main className="dashboard">
      <header className="page-heading">
        <div>{session && <p className="eyebrow">{session.organization}</p>}<h1>Data retention</h1></div>
        <span className="badge local"><span aria-hidden="true" />Local demo</span>
      </header>
      {policy ? <>
        <section className="panel" aria-labelledby="retention-heading">
          <div className="panel-heading"><h2 id="retention-heading">Retention windows</h2><span className="badge">Organization-wide</span></div>
          <p className="muted" id="retention-help">Enter 1 to 3,650 days per dataset. Leave a field blank for no expiry. A shorter window expires older records immediately and schedules deletion.</p>
          <MutationForm action={saveRetention} label="Save retention" appearance="primary"
            confirmation="Apply these retention windows? Records that expire under this setting will be permanently deleted.">
            <div className="policy-fields" key={JSON.stringify(policy)}>
              {(Object.keys(retentionFields) as RetentionField[]).map((field) => <div className="grid gap-1" key={field}>
                <label htmlFor={field}>{retentionFields[field]} (days)</label>
                <input id={field} name={field} type="number" min={1} max={3650} step={1} defaultValue={policy[field] ?? ''}
                  placeholder="No expiry" aria-describedby="retention-help" />
              </div>)}
            </div>
          </MutationForm>
        </section>
        <section className="panel" aria-labelledby="cleanup-heading">
          <h2 id="cleanup-heading">Delete expired records</h2>
          <p className="muted">Control runs cleanup on a schedule. Run it now to delete up to 1,000 expired records per dataset.</p>
          <MutationForm action={cleanupRetention} label="Run cleanup" appearance="danger"
            confirmation="Permanently delete expired records from this organization now?" />
        </section>
      </> : <section className="panel" role="alert">Control could not load the retention settings. Try reloading this page.</section>}
    </main>
  </div>;
}
