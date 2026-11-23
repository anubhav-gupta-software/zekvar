import { notFound, redirect } from 'next/navigation';
import { canWrite } from '../../../lib/access';
import { alertNumber, alertPath, alertRollout, alertStatus, type AlertWebhook } from '../../../lib/alerts';
import { ApiError, controlApi } from '../../../lib/api';
import { fileCheckUnavailableLabel, isId, promptAppLabels, ruleLabels, utc } from '../../../lib/control';
import { readEventCursor, setEventCursor } from '../../../lib/events';
import { sessionToken } from '../../../lib/session';
import { eventPath, initialTriage, triageStatuses } from '../../../lib/triage';
import { fileInspectionUnavailableRule, uploadRule } from '../../../../../contracts/policy/uploads';
import { acknowledgeAlert } from '../../actions';
import { MutationForm, RefreshSection } from '../../forms';
import { DeploymentBadge, Sidebar } from '../../workspace';

const evidenceLabels: Record<string, string> = {
  ...ruleLabels, [uploadRule]: 'AI file upload', [fileInspectionUnavailableRule]: fileCheckUnavailableLabel,
};
const webhookStatuses: Record<AlertWebhook['status'], string> = {
  queued: 'Queued', sending: 'Sending', retrying: 'Retry scheduled', sent: 'Delivered', failed: 'Failed', paused: 'Destination unavailable',
};
const webhookFailures: Record<string, string> = {
  http_status: 'Receiver rejected the request',
  network_error: 'Connection failed',
  request_timeout: 'Receiver timed out',
  delivery_unconfirmed: 'Final delivery attempt unconfirmed',
  recovery_cancelled: 'Cancelled during database recovery',
};

function AlertDelivery({ delivery }: { delivery: AlertWebhook }) {
  const next = delivery.nextAttemptAt;
  const last = delivery.lastAttemptAt;
  const sent = delivery.sentAt;
  const failure = delivery.failureCode && webhookFailures[delivery.failureCode];
  return <section className="panel" aria-labelledby="webhook-delivery-heading">
    <div className="panel-heading"><h2 id="webhook-delivery-heading">Webhook delivery</h2>
      <RefreshSection label="Refresh delivery status" /></div>
    <p><span className="badge">{webhookStatuses[delivery.status]}</span>{' '}
      <span className="muted">{delivery.attempts} {delivery.attempts === 1 ? 'attempt' : 'attempts'}</span></p>
    {sent ? <p className="muted">Delivered <time dateTime={sent}>{utc.format(new Date(sent))} UTC</time></p> :
      last && <p className="muted">Last attempt <time dateTime={last}>{utc.format(new Date(last))} UTC</time></p>}
    {failure && <p className="muted">{failure}{delivery.lastHttpStatus && <> · HTTP {delivery.lastHttpStatus}</>}</p>}
    {next && delivery.status === 'retrying' && <p className="muted">Next attempt <time dateTime={next}>{utc.format(new Date(next))} UTC</time></p>}
  </section>;
}

export default async function AlertDetail({ params, searchParams }: {
  params: Promise<{ id: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const token = await sessionToken();
  if (!token) redirect('/');
  const { id } = await params;
  if (!isId(id)) notFound();
  const { cursor, invalidCursor } = readEventCursor(await searchParams);
  const query = new URLSearchParams();
  if (cursor) setEventCursor(query, cursor);
  const data = await Promise.all([controlApi.session(token), controlApi.alert(token, id, query)]).catch((error: unknown) => {
    if (error instanceof ApiError && error.status === 401) redirect('/?session=ended');
    if (error instanceof ApiError && error.status === 404) notFound();
    if (error instanceof ApiError) return undefined;
    throw error;
  });
  const [session, detail] = data ?? [];
  const alert = detail?.alert;
  const evidence = detail?.evidence;
  const next = new URLSearchParams();
  if (evidence?.next) setEventCursor(next, evidence.next);

  return <div className="workspace">
    <Sidebar active="alerts" session={session} />
    <main className="dashboard">
      <header className="page-heading">
        <div>{session && <p className="eyebrow">{session.organization}</p>}<h1>Alert {alertNumber(id)}</h1></div>
        <DeploymentBadge />
      </header>
      <div className="form-row mb-3"><a className="button small" href="/alerts">Back to alert inbox</a></div>
      {alert && evidence ? <>
        <section className="panel" aria-labelledby="alert-detail-heading">
          <div className="panel-heading"><h2 id="alert-detail-heading">Repeated AI blocks</h2>
            <span className="badge">{alertStatus(alert)}</span></div>
          <p>{promptAppLabels[alert.appId]} · {alertRollout(alert)}</p>
          <p className="muted">{alert.blockCount} blocks received · Threshold {alert.threshold}</p>
          <p className="muted">Window <time dateTime={alert.windowStart}>{utc.format(new Date(alert.windowStart))}</time>{' '}
            through <time dateTime={alert.windowEnd}>{utc.format(new Date(alert.windowEnd))} UTC</time></p>
          {alert.acknowledgedAt ? <p className="muted">Acknowledged <time dateTime={alert.acknowledgedAt}>
            {utc.format(new Date(alert.acknowledgedAt))} UTC</time></p> : canWrite(session) &&
            <MutationForm action={acknowledgeAlert.bind(null, id)} label="Acknowledge alert" />}
        </section>
        {detail.webhook && <AlertDelivery delivery={detail.webhook} />}
        <section className="panel table-panel" aria-labelledby="alert-evidence-heading">
          <div className="panel-heading"><h2 id="alert-evidence-heading">Blocked events</h2><RefreshSection label="Refresh alert evidence" /></div>
          {invalidCursor ? <div className="table-footer"><p role="alert">Choose a complete evidence cursor.</p>
            <a className="button small" href={alertPath(id)}>Newest blocked events</a></div> :
            evidence.entries.length ? <div className="table-scroll" tabIndex={0} role="region" aria-labelledby="alert-evidence-heading">
              <table aria-labelledby="alert-evidence-heading"><thead>
                <tr><th>Received (UTC)</th><th>Detector</th><th>Event triage</th><th>Event</th></tr>
              </thead><tbody>{evidence.entries.map((event) => <tr key={`${event.installationId}/${event.eventId}`}>
                <td><time dateTime={event.receivedAt}>{utc.format(new Date(event.receivedAt))}</time></td>
                <td>{evidenceLabels[event.ruleId] ?? event.ruleId}</td>
                <td>{triageStatuses[(event.triage ?? initialTriage).status]}</td>
                <td><a className="underline" href={eventPath(event.installationId, event.eventId)}>Review event {event.eventId.slice(0, 8)}</a></td>
              </tr>)}</tbody></table>
            </div> : <p className="empty">No retained events on this page.</p>}
          {!invalidCursor && (cursor || evidence.next) && <div className="table-footer"><div className="form-row">
            {cursor && <a className="button small" href={alertPath(id)}>Newest blocked events</a>}
            {evidence.next && <a className="button small" href={`${alertPath(id)}?${next}`}>Older blocked events</a>}
          </div></div>}
        </section>
      </> : <section className="panel"><p role="alert">Control could not load this alert. Try refreshing.</p></section>}
    </main>
  </div>;
}
