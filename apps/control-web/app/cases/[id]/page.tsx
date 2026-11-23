import { notFound, redirect } from 'next/navigation';
import { canWrite } from '../../../lib/access';
import { ApiError, controlApi } from '../../../lib/api';
import { caseCategories, caseNumber, casePath } from '../../../lib/cases';
import { decisionLabels, fileCheckUnavailableLabel, isPromptApp, promptAppLabels, ruleLabels, utc } from '../../../lib/control';
import { sessionToken } from '../../../lib/session';
import { eventPath, isTriageId, triageDispositions, triageStatuses } from '../../../lib/triage';
import { fileInspectionUnavailableRule, uploadMethods, uploadRule } from '../../../../../contracts/policy/uploads';
import { linkIncidentEvent, saveIncidentCase } from '../../actions';
import { MutationForm } from '../../forms';
import { TriageFields } from '../../triage-fields';
import { DeploymentBadge, Sidebar } from '../../workspace';
import { CaseActivityDetails } from '../case-activity';

export default async function CaseDetail({ params }: { params: Promise<{ id: string }> }) {
  const token = await sessionToken();
  if (!token) redirect('/');
  const { id } = await params;
  if (!isTriageId(id)) notFound();
  const data = await Promise.all([controlApi.session(token), controlApi.case(token, id), controlApi.triageAssignees(token)])
    .catch((error: unknown) => {
      if (error instanceof ApiError && error.status === 401) redirect('/?session=ended');
      if (error instanceof ApiError && error.status === 404) notFound();
      if (error instanceof ApiError) return undefined;
      throw error;
    });
  const [session, details, assignees] = data ?? [];
  const record = details?.case;
  const triage = record?.triage;
  const writable = canWrite(session);

  return <div className="workspace">
    <Sidebar active="cases" session={session} />
    <main className="dashboard">
      <header className="page-heading">
        <div>{session && <p className="eyebrow">{session.organization}</p>}<h1>{caseNumber(id)}</h1></div>
        <DeploymentBadge />
      </header>
      <div className="form-row mb-4">
        <a className="button small" href="/cases">Back to incident cases</a>
        {record && <a className="button small" href={`${casePath(id)}/export`} download>Export case (JSON)</a>}
      </div>
      {!details || !record || !triage ? <p className="panel feedback error" role="alert">Control could not load this case. Reload to try again.</p> : <>
        <section className="panel" aria-labelledby="case-triage-heading">
          <div className="panel-heading"><h2 id="case-triage-heading">Case triage</h2>
            <span className={`badge ${triage.status === 'resolved' ? 'current' : ''}`}>{triageStatuses[triage.status]}</span>
          </div>
          <p className="muted">{caseCategories[record.category]} · Opened <Timestamp value={record.createdAt} /> UTC</p>
          <p className="muted">Assigned to {triage.assignee ? `${triage.assignee.name}${triage.assignee.active ? '' : ' (inactive)'}` : 'no one'}
            {triage.disposition && <> · {triageDispositions[triage.disposition]}</>}</p>
          {writable && <MutationForm action={saveIncidentCase.bind(null, id)} label="Save case triage" appearance="primary" preserveValues>
            <TriageFields key={triage.revision} triage={triage} assignees={assignees ?? []} />
          </MutationForm>}
        </section>
        <section className="panel table-panel" aria-labelledby="case-events-heading">
          <div className="panel-heading"><h2 id="case-events-heading">Linked security events</h2>
            {writable && triage.status !== 'resolved' && <a className="button small" href="/#events">Find more events</a>}
          </div>
          <div className="table-scroll" tabIndex={0} role="region" aria-labelledby="case-events-heading">
            <table aria-labelledby="case-events-heading"><thead>
              <tr><th>Occurred (UTC)</th><th>Application</th><th>Detector</th><th>Decision</th><th>Event triage</th><th>Event</th>
                {writable && triage.status !== 'resolved' && <th>Action</th>}</tr>
            </thead><tbody>
              {details.events.map((event) => <tr key={`${event.installationId}/${event.eventId}`}>
                <td><Timestamp value={event.timestamp} /></td>
                <td>{isPromptApp(event.appId) ? promptAppLabels[event.appId] : event.appId}</td>
                <td>{event.ruleId === uploadRule ? 'File upload' : event.ruleId === fileInspectionUnavailableRule ? fileCheckUnavailableLabel :
                  ruleLabels[event.ruleId as keyof typeof ruleLabels] ?? event.detectorCategory}
                  {event.uploadMethod && <div className="muted">{uploadMethods[event.uploadMethod]}</div>}</td>
                <td><span className={`badge ${event.decision}`}>{decisionLabels[event.decision]}</span></td>
                <td>{triageStatuses[event.triage?.status ?? 'needs_review']}</td>
                <td><a className="underline" href={eventPath(event.installationId, event.eventId)}
                  aria-label={`Review event ${event.eventId}`}>{event.eventId.slice(0, 8)}</a></td>
                {writable && triage.status !== 'resolved' && <td>
                  <MutationForm action={linkIncidentEvent.bind(null, id, { installationId: event.installationId, eventId: event.eventId },
                    triage.revision, false)} label="Unlink event" accessibleLabel={`Unlink event ${event.eventId}`} appearance="small"
                    confirmation="Unlink this event from the case?" />
                </td>}
              </tr>)}
            </tbody></table>
          </div>
          {details.events.length === 0 && <p className="empty">This case has no retained linked events.</p>}
        </section>
        <section className="panel table-panel" aria-labelledby="case-activity-heading">
          <div className="panel-heading"><h2 id="case-activity-heading">Case activity</h2>
            <a className="button small" href="/audit?action=incident_case_changed">Open audit log</a>
          </div>
          {details.activity.length > 0 ? <>
            <div className="table-scroll" tabIndex={0} role="region" aria-labelledby="case-activity-heading">
              <table aria-labelledby="case-activity-heading"><thead><tr><th>Time (UTC)</th><th>Actor</th><th>Change</th></tr></thead>
                <tbody>{details.activity.map((entry) => <tr key={entry.id}>
                  <td><Timestamp value={entry.occurredAt} /></td><td>{entry.actorAccess?.name ?? 'Organization admin'}</td>
                  <td><CaseActivityDetails change={entry.change} /></td>
                </tr>)}</tbody>
              </table>
            </div>
            {details.activity.length === 50 && <div className="table-footer"><p className="table-note">Latest 50 retained changes.</p></div>}
          </> : <p className="empty">No retained case activity.</p>}
        </section>
      </>}
    </main>
  </div>;
}

function Timestamp({ value }: { value: string }) {
  return <time dateTime={value}>{utc.format(new Date(value))}</time>;
}
