import { notFound, redirect } from 'next/navigation';
import { uploadMethods, uploadRule } from '../../../../../../contracts/policy/uploads';
import { canWrite } from '../../../../lib/access';
import { ApiError, controlApi } from '../../../../lib/api';
import { browserHealthFilters } from '../../../../lib/browser-health';
import { decisionLabels, isPromptApp, promptAppLabels, ruleLabels, utc } from '../../../../lib/control';
import { eventFilters, setEventCursor } from '../../../../lib/events';
import { sessionToken } from '../../../../lib/session';
import { initialTriage, isTriageId, triageDispositions, triageStatuses, type TriageState } from '../../../../lib/triage';
import { saveEventTriage } from '../../../actions';
import { MutationForm } from '../../../forms';
import { DeploymentBadge, Sidebar } from '../../../workspace';
import { TriageFields } from './triage-fields';

type Search = Record<string, string | string[] | undefined>;

export default async function ReviewEvent({ params, searchParams }: {
  params: Promise<{ installationId: string; eventId: string }>; searchParams: Promise<Search>;
}) {
  const token = await sessionToken();
  if (!token) redirect('/');
  const { installationId, eventId } = await params;
  if (!isTriageId(installationId) || !isTriageId(eventId)) notFound();
  const search = await searchParams;
  const filters = eventFilters(search);
  const returnQuery = new URLSearchParams([...filters.page, ...browserHealthFilters(search)]);
  if (filters.cursor) setEventCursor(returnQuery, filters.cursor);

  const data = await Promise.all([
    controlApi.session(token), controlApi.event(token, installationId, eventId), controlApi.triageAssignees(token),
  ]).catch((error: unknown) => {
    if (error instanceof ApiError && error.status === 401) redirect('/?session=ended');
    if (error instanceof ApiError && error.status === 404) notFound();
    if (error instanceof ApiError) return undefined;
    throw error;
  });
  const [session, details, assignees] = data ?? [];
  const event = details?.event;
  const triage = event?.triage ?? initialTriage;
  const names = new Map(assignees?.map(({ id, name }) => [id, name]));
  if (triage.assignee) names.set(triage.assignee.id, triage.assignee.name);
  const rollout = event?.rollout;
  return <div className="workspace">
    <Sidebar active="events" session={session} />
    <main className="dashboard">
      <header className="page-heading">
        <div>{session && <p className="eyebrow">{session.organization}</p>}<h1>Security event</h1></div>
        <DeploymentBadge />
      </header>
      <a className="button small mb-4" href={`/?${returnQuery}#events`}>Back to security events</a>
      {!event || !details ? <p className="panel feedback error" role="alert">Control could not load this event. Reload the page to try again.</p> : <>
        <section className="panel" aria-labelledby="event-detail-heading">
          <div className="panel-heading"><h2 id="event-detail-heading">Detection details</h2>
            <span className={`badge ${event.decision}`}>{decisionLabels[event.decision]}</span>
          </div>
          <dl className="policy-fields mt-4 gap-y-4 text-sm">
            <div><dt className="muted">Application</dt><dd>{isPromptApp(event.appId) ? promptAppLabels[event.appId] : event.appId}</dd></div>
            <div><dt className="muted">Detector</dt><dd>{event.ruleId === uploadRule ? 'File upload'
              : ruleLabels[event.ruleId as keyof typeof ruleLabels] ?? event.detectorCategory}
              {event.uploadMethod && <> · {uploadMethods[event.uploadMethod]}</>}</dd></div>
            <div><dt className="muted">Policy</dt><dd>v{event.policyVersion}</dd></div>
            <div><dt className="muted">Occurred (UTC)</dt><dd><Timestamp value={event.timestamp} /></dd></div>
            <div><dt className="muted">Received (UTC)</dt><dd><Timestamp value={event.receivedAt} /></dd></div>
            <div><dt className="muted">Recorded rollout</dt><dd>{rollout?.kind === 'group' ? rollout.groupName
              : rollout?.kind === 'baseline' ? 'Organization baseline' : 'Unattributed'}</dd></div>
            <div><dt className="muted">Browser installation ID</dt><dd><code className="break-all">{event.installationId}</code></dd></div>
            <div><dt className="muted">Event ID</dt><dd><code className="break-all">{event.eventId}</code></dd></div>
          </dl>
        </section>
        <section className="panel" aria-labelledby="event-triage-heading">
          <div className="panel-heading"><h2 id="event-triage-heading">Triage</h2>
            <span className={`badge ${triage.status === 'resolved' ? 'current' : ''}`}>{triageStatuses[triage.status]}</span>
          </div>
          <p className="muted">Assigned to {triage.assignee ? `${triage.assignee.name}${triage.assignee.active ? '' : ' (inactive)'}` : 'no one'}
            {triage.disposition && <> · {triageDispositions[triage.disposition]}</>}
            {triage.updatedAt && <> · Last changed <Timestamp value={triage.updatedAt} /> UTC</>}</p>
          {canWrite(session) && <MutationForm action={saveEventTriage.bind(null, installationId, eventId)}
            label="Save triage" appearance="primary" preserveValues>
            <TriageFields key={triage.revision} triage={triage} assignees={assignees ?? []} />
          </MutationForm>}
        </section>
        <section className="panel table-panel" aria-labelledby="event-activity-heading">
          <div className="panel-heading"><h2 id="event-activity-heading">Triage activity</h2>
            <a className="button small" href="/audit?action=event_triage_changed">Open audit log</a>
          </div>
          {details.activity.length ? <>
            <div className="table-scroll" tabIndex={0} role="region" aria-labelledby="event-activity-heading">
              <table aria-labelledby="event-activity-heading"><thead><tr><th>Time (UTC)</th><th>Actor</th><th>Previous</th><th>Updated</th></tr></thead>
                <tbody>{details.activity.map(({ id, occurredAt, actorAccess, change }) => <tr key={id}>
                  <td><Timestamp value={occurredAt} /></td>
                  <td>{actorAccess?.name ?? 'Organization admin'}</td>
                  <td><State state={change.before} names={names} /></td>
                  <td><State state={change.after} names={names} /></td>
                </tr>)}</tbody>
              </table>
            </div>
            {details.activity.length === 50 && <div className="table-footer"><p className="table-note">Latest 50 retained changes.</p></div>}
          </> : <p className="empty">No retained triage changes.</p>}
        </section>
      </>}
    </main>
  </div>;
}

function Timestamp({ value }: { value: string }) {
  return <time dateTime={value}>{utc.format(new Date(value))}</time>;
}

function State({ state, names }: { state: TriageState; names: Map<string, string> }) {
  return <>{triageStatuses[state.status]}{state.disposition && <> · {triageDispositions[state.disposition]}</>}
    <div className="muted">{state.assigneeId
      ? <span title={state.assigneeId}>{names.get(state.assigneeId) ?? state.assigneeId.slice(0, 8)}</span> : 'Unassigned'}</div>
  </>;
}
