import { redirect } from 'next/navigation';
import { canWrite } from '../../lib/access';
import { ApiError, controlApi } from '../../lib/api';
import { caseCategories, caseListFilters, caseNumber, casePath } from '../../lib/cases';
import { utc } from '../../lib/control';
import { sessionToken } from '../../lib/session';
import { eventPath, triageStatuses } from '../../lib/triage';
import { linkIncidentEvent } from '../actions';
import { MutationForm } from '../forms';
import { DeploymentBadge, Sidebar } from '../workspace';

export default async function Cases({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const token = await sessionToken();
  if (!token) redirect('/');
  const filters = caseListFilters(await searchParams);
  const source = filters?.source;
  const data = await Promise.all([
    controlApi.session(token),
    filters ? controlApi.cases(token, filters.query) : undefined,
    source ? controlApi.event(token, source.installationId, source.eventId).catch((error: unknown) => {
      if (error instanceof ApiError && error.status === 404) return null;
      throw error;
    }) : undefined,
  ]).catch((error: unknown) => {
    if (error instanceof ApiError && error.status === 401) redirect('/?session=ended');
    if (error instanceof ApiError) return undefined;
    throw error;
  });
  const [session, results, event] = data ?? [];
  const next = new URLSearchParams(filters?.page);
  if (results?.next) {
    next.set('beforeAt', results.next.createdAt);
    next.set('beforeId', results.next.id);
  }
  const showLinkActions = Boolean(source && event?.event && !event.incidentCase && canWrite(session));

  return <div className="workspace">
    <Sidebar active="cases" session={session} />
    <main className="dashboard">
      <header className="page-heading">
        <div>{session && <p className="eyebrow">{session.organization}</p>}<h1>Incident cases</h1></div>
        <DeploymentBadge />
      </header>
      {source && <section className="panel" aria-labelledby="link-case-heading">
        <div className="panel-heading"><h2 id="link-case-heading">Link a security event</h2>
          <a className="button small" href={eventPath(source.installationId, source.eventId)}>Back to event</a>
        </div>
        {event === null ? <p className="feedback error" role="alert">This event is no longer available.</p> :
          event?.incidentCase ? <p className="muted">This event is linked to{' '}
            <a className="underline" href={casePath(event.incidentCase.id)}>{caseNumber(event.incidentCase.id)}</a>.</p> :
            showLinkActions && <p className="muted">Choose an open case for event <code>{source.eventId.slice(0, 8)}</code>.</p>}
      </section>}
      <section className="panel table-panel" aria-labelledby="case-list-heading">
        <div className="panel-heading"><h2 id="case-list-heading">Investigations</h2>
          <a className="button small" href="/#events">Find security events</a>
        </div>
        <form action="/cases" method="get" className="filters">
          {source && <>
            <input type="hidden" name="installation" value={source.installationId} />
            <input type="hidden" name="event" value={source.eventId} />
          </>}
          <div><label htmlFor="case-list-status">Status</label>
            <select id="case-list-status" name="status" defaultValue={filters?.status ?? ''}>
              <option value="">All statuses</option>
              {Object.entries(triageStatuses).map(([status, title]) => <option key={status} value={status}>{title}</option>)}
            </select>
          </div>
          <label className="form-row"><input type="checkbox" name="open" value="1" defaultChecked={filters?.open === '1'} /> Open cases only</label>
          <button className="button">Apply case filters</button>
          {filters?.page.size ? <a className="clear-link" href="/cases">Clear filters</a> : null}
        </form>
        {!filters ? <p className="empty" role="alert">Choose valid case filters.</p> :
          !results ? <p className="empty" role="alert">Control could not load incident cases. Reload this page to try again.</p> : <>
            <div className="table-scroll" tabIndex={0} role="region" aria-labelledby="case-list-heading">
              <table aria-labelledby="case-list-heading"><thead>
                <tr><th>Case</th><th>Category</th><th>Status</th><th>Assignee</th><th>Events</th><th>Opened (UTC)</th>
                  {showLinkActions && <th>Action</th>}
                </tr>
              </thead><tbody>
                {results.entries.map((item) => <tr key={item.id}>
                  <td><a className="underline" href={casePath(item.id)}>{caseNumber(item.id)}</a></td>
                  <td>{caseCategories[item.category]}</td><td>{triageStatuses[item.triage.status]}</td>
                  <td>{item.triage.assignee ? `${item.triage.assignee.name}${item.triage.assignee.active ? '' : ' (inactive)'}` : 'Unassigned'}</td>
                  <td>{item.eventCount}</td><td><time dateTime={item.createdAt}>{utc.format(new Date(item.createdAt))}</time></td>
                  {showLinkActions && source && <td>{item.triage.status !== 'resolved' &&
                    <MutationForm action={linkIncidentEvent.bind(null, item.id, source, item.triage.revision, true)}
                      label="Link event" accessibleLabel={`Link event to ${caseNumber(item.id)}`} appearance="small" />}
                  </td>}
                </tr>)}
              </tbody></table>
            </div>
            {results.entries.length === 0 && <p className="empty">No incident cases match this view.</p>}
            {(filters.paged || results.next) && <div className="table-footer">
              <div className="form-row">
                {filters.paged && <a className="button small" href={`/cases?${filters.page}`}>Newest cases</a>}
                {results.next && <a className="button small" href={`/cases?${next}`}>Older cases</a>}
              </div>
            </div>}
          </>}
      </section>
    </main>
  </div>;
}
