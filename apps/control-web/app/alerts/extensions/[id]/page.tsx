import { notFound, redirect } from 'next/navigation';
import { canWrite } from '../../../../lib/access';
import { alertNumber, alertStatus, extensionAlertsPath } from '../../../../lib/alerts';
import { ApiError, controlApi } from '../../../../lib/api';
import { isId, utc } from '../../../../lib/control';
import { sessionToken } from '../../../../lib/session';
import { acknowledgeExtensionAlert } from '../../../actions';
import { ExtensionChangesTable } from '../../../extensions/change-table';
import { MutationForm } from '../../../forms';
import { DeploymentBadge, Sidebar } from '../../../workspace';

export default async function ExtensionAlertDetail({ params }: { params: Promise<{ id: string }> }) {
  const token = await sessionToken();
  if (!token) redirect('/');
  const { id } = await params;
  if (!isId(id)) notFound();
  const data = await Promise.all([controlApi.session(token), controlApi.extensionAlert(token, id)]).catch((error: unknown) => {
    if (error instanceof ApiError && error.status === 401) redirect('/?session=ended');
    if (error instanceof ApiError && error.status === 404) notFound();
    if (error instanceof ApiError) return undefined;
    throw error;
  });
  const [session, detail] = data ?? [];
  const alert = detail?.alert;
  return <div className="workspace">
    <Sidebar active="alerts" session={session} />
    <main className="dashboard">
      <header className="page-heading">
        <div>{session && <p className="eyebrow">{session.organization}</p>}<h1>Extension alert {alertNumber(id)}</h1></div>
        <DeploymentBadge />
      </header>
      <div className="form-row mb-3"><a className="button small" href={extensionAlertsPath}>Back to extension alerts</a></div>
      {detail && alert ? <>
        <section className="panel" aria-labelledby="extension-alert-detail-heading">
          <div className="panel-heading"><h2 id="extension-alert-detail-heading">Expanded extension access</h2>
            <span className="badge">{alertStatus(alert)}</span></div>
          <p>{alert.groupName ?? 'Organization baseline'} · Policy v{alert.policyVersion}</p>
          <p className="muted">Reported <time dateTime={alert.triggeredAt}>{utc.format(new Date(alert.triggeredAt))} UTC</time></p>
          <p><a className="underline" href={`/extensions?browser=${alert.installationId}#extension-details`}>Open browser inventory</a></p>
          {alert.acknowledgedAt ? <p className="muted">Acknowledged <time dateTime={alert.acknowledgedAt}>
            {utc.format(new Date(alert.acknowledgedAt))} UTC</time></p> : canWrite(session) &&
            <MutationForm action={acknowledgeExtensionAlert.bind(null, id)} label="Acknowledge alert" />}
        </section>
        <section className="panel table-panel" aria-labelledby="extension-alert-evidence-heading">
          <div className="panel-heading"><h2 id="extension-alert-evidence-heading">Changes that triggered this alert</h2></div>
          <ExtensionChangesTable label="Alert changes" changes={detail.changes} />
        </section>
      </> : <section className="panel"><p role="alert">Control could not load this extension alert. Try refreshing.</p></section>}
    </main>
  </div>;
}
