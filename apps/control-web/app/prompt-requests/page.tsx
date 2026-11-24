import { redirect } from 'next/navigation';
import { canWrite } from '../../lib/access';
import { ApiError, controlApi } from '../../lib/api';
import { decisionLabels, promptAppLabels, ruleLabels, utc } from '../../lib/control';
import { promptRequestDecisions, promptRequestLabels, type PromptExceptionRequest, type PromptRequestDecision } from '../../lib/prompt-requests';
import { sessionToken } from '../../lib/session';
import { eventPath } from '../../lib/triage';
import { decidePromptRequest } from '../actions';
import { MutationForm, RefreshSection } from '../forms';
import { DeploymentBadge, Sidebar } from '../workspace';

export default async function PromptRequests({ searchParams }: { searchParams: Promise<{ status?: string | string[] }> }) {
  const token = await sessionToken();
  if (!token) redirect('/');
  const status = (await searchParams).status === 'decided' ? 'decided' : 'pending';
  const result = await Promise.all([controlApi.session(token), controlApi.promptExceptionRequests(token, status)])
    .catch((error: unknown) => {
      if (error instanceof ApiError && error.status === 401) redirect('/');
      if (error instanceof ApiError) return undefined;
      throw error;
    });
  const [session, requests] = result ?? [];
  return <div className="workspace">
    <Sidebar active="prompt-requests" session={session} />
    <main className="dashboard">
      <header className="page-heading">
        <div>{session && <p className="eyebrow">{session.organization}</p>}<h1>Prompt exception requests</h1></div>
        <DeploymentBadge />
      </header>
      <section className="panel table-panel" aria-labelledby="request-inbox">
        <div className="panel-heading"><h2 id="request-inbox">{status === 'pending' ? 'Pending requests' : 'Decided requests'}</h2>
          <RefreshSection label="Refresh prompt requests" /></div>
        <nav className="table-footer form-row" aria-label="Request status">
          {(['pending', 'decided'] as const).map((value) => <a key={value} href={`/prompt-requests?status=${value}`}
            aria-current={status === value ? 'page' : undefined} className={`button small ${status === value ? 'primary' : ''}`}>
            {value === 'pending' ? 'Pending' : 'Decided'}</a>)}
        </nav>
        {requests && requests.length > 0 ? <div className="table-scroll" role="region" tabIndex={0} aria-labelledby="request-inbox">
          <table aria-labelledby="request-inbox">
            <thead><tr><th scope="col">Submitted (UTC)</th><th scope="col">Detection</th><th scope="col">Policy scope</th>
              <th scope="col">Decision</th></tr></thead>
            <tbody>{requests.map((request) => <RequestRow key={request.id} request={request} writable={canWrite(session)} />)}</tbody>
          </table>
        </div> : <p className="empty" role={requests ? undefined : 'alert'}>
          {requests ? `No ${status} prompt exception requests.` : 'Control could not load prompt exception requests.'}
        </p>}
        {requests?.length === 100 && <p className="table-footer table-note">
          {status === 'pending' ? 'Showing the oldest 100 pending requests.' : 'Showing the most recent 100 decisions.'}
        </p>}
      </section>
    </main>
  </div>;
}

function RequestRow({ request, writable }: { request: PromptExceptionRequest; writable: boolean }) {
  const { id, groupId, groupName, status, appId, ruleId } = request;
  const preview = `/preview${groupId ? `?group=${groupId}` : ''}#prompt-exceptions-heading`;
  const scope = groupName ?? 'Organization baseline';
  const rule = ruleId === 'fixture-secret' ? 'Test marker' : ruleLabels[ruleId];
  return <tr>
    <td><time dateTime={request.requestedAt}>{utc.format(new Date(request.requestedAt))}</time></td>
    <th scope="row">{promptAppLabels[appId]} · {rule}
      <div className="form-row"><span className={`badge ${request.decision}`}>{decisionLabels[request.decision]}</span>
        <a className="underline" href={eventPath(request.installationId, request.eventId)}>Open detection</a></div>
    </th>
    <td>{scope} · v{request.policyVersion}</td>
    <td>{status === 'pending' ? <><span className="badge warn">Pending</span>
      {writable && <div className="grid gap-2 mt-2">
        <a className="underline" href={preview}>Open scoped policy preview</a>
        <div className="form-row">
          {promptRequestDecisions.map((choice) => <DecisionForm key={choice} id={id} status={choice} />)}
        </div>
      </div>}
    </> : <><span className="badge">{promptRequestLabels[status]}</span>
      <p className="table-note">{request.decidedBy}{request.publishedVersion && ` · v${request.publishedVersion}`}</p>
      {request.decidedAt && <time dateTime={request.decidedAt}>{utc.format(new Date(request.decidedAt))}</time>}
    </>}</td>
  </tr>;
}

function DecisionForm({ id, status }: { id: string; status: PromptRequestDecision }) {
  const decline = status === 'declined';
  return <MutationForm action={decidePromptRequest} label={decline ? 'Decline request' : 'Record published exception'}
    appearance="small" confirmation={decline ? 'Decline this prompt exception request?' : 'Record the active exception for this prompt request?'}>
    <input type="hidden" name="id" value={id} />
    <input type="hidden" name="status" value={status} />
  </MutationForm>;
}
