import { ApiError, controlApi } from '../lib/api';
import {
  chatGptApp, decisionLabels, decisions, fixtureApp, modes, utc,
  type Decision, type Installation, type Policy, type SecurityEvent,
} from '../lib/control';
import { sessionToken } from '../lib/session';
import { publishPolicy, restorePolicy, revokeInstallation, signOut } from './actions';
import { EnrollmentForm, MutationForm, SignInForm } from './forms';

type Search = Record<string, string | string[] | undefined>;

function eventFilters(search: Search) {
  const query = new URLSearchParams();
  const app = search.app === fixtureApp || search.app === chatGptApp ? search.app : '';
  const decision = decisions.find((value) => value === search.decision) ?? '';
  const period = search.period === 'day' || search.period === 'week' ? search.period : '';
  if (app) query.set('appId', app);
  if (decision) query.set('decision', decision);
  if (period) query.set('since', new Date(Date.now() - (period === 'day' ? 1 : 7) * 86_400_000).toISOString());
  return { app, decision, period, query };
}

export default async function Control({ searchParams }: { searchParams: Promise<Search> }) {
  const token = await sessionToken();
  if (!token) return <SignIn />;
  const filters = eventFilters(await searchParams);

  try {
    const [session, policies, installations, events] = await Promise.all([
      controlApi.session(token), controlApi.policies(token),
      controlApi.installations(token), controlApi.events(token, filters.query),
    ]);
    const current = policies[0];
    const active = installations.filter(({ revokedAt }) => !revokedAt).length;
    return <div className="workspace" id="overview">
      <aside className="sidebar">
        <Brand />
        <nav aria-label="Dashboard sections">
          <a href="#overview">Overview</a>
          <a href="#policies">Policies</a>
          <a href="#browsers">Browsers</a>
          <a href="#events">Events</a>
        </nav>
        <div className="sidebar-footer">
          <form action={signOut}><button className="button small">Sign out</button></form>
        </div>
      </aside>
      <main className="dashboard">
        <header className="page-heading">
          <div>
            <p className="eyebrow">{session.organization}</p>
            <h1>Security overview</h1>
          </div>
          <span className="badge local"><span aria-hidden="true" />Local demo</span>
        </header>

        <div className="metrics" aria-label="Control summary">
          <div className="metric"><p>Current policy</p>
            <strong>{current ? decisionLabels[current.mode] : 'None'}</strong>
            <span>{current ? `Version ${current.version}` : 'Publish a policy to get started'}</span>
          </div>
          <div className="metric"><p>Active installations</p><strong>{active}</strong>
            <span>{installations.length === 100 ? 'Among the latest 100' : 'With valid credentials'}</span>
          </div>
          <div className="metric"><p>Events shown</p><strong>{events.length}</strong>
            <span>{filters.query.size ? 'Filtered view' : 'Latest 100 events'}</span>
          </div>
        </div>

        <div className="controls-grid">
          <section className="panel" id="policies" aria-labelledby="policies-heading">
            <div className="panel-heading"><h2 id="policies-heading">Publish a policy</h2><span className="badge">Organization-wide</span></div>
            <p className="muted">Set how Zekvar responds when the synthetic prompt rule matches.</p>
            <MutationForm action={publishPolicy} label="Publish policy" appearance="primary">
              <label htmlFor="publish-mode" className="sr-only">Policy mode</label>
              <select key={current?.version} id="publish-mode" name="mode" defaultValue={current?.mode ?? 'monitor'}>
                {modes.map((mode) => <option key={mode} value={mode}>{decisionLabels[mode]}</option>)}
              </select>
            </MutationForm>
          </section>
          <section className="panel" aria-labelledby="enrollment-heading">
            <div className="panel-heading"><h2 id="enrollment-heading">Browser enrollment</h2></div>
            <p className="muted">Create a single-use grant for a browser. It expires in 10 minutes.</p>
            <EnrollmentForm />
          </section>
        </div>

        <section className="panel table-panel" aria-labelledby="history-heading">
          <div className="panel-heading"><h2 id="history-heading">Policy history</h2><span className="table-note">Latest 100 versions</span></div>
          <div className="table-scroll" tabIndex={0} role="region" aria-labelledby="history-heading">
            <table aria-labelledby="history-heading">
              <thead><tr><th>Version</th><th>Mode</th><th>Published (UTC)</th><th>Restore source</th><th>Action</th></tr></thead>
              <tbody>{policies.map((policy) => <PolicyRow key={policy.version} policy={policy} current={policy.version === current?.version} />)}</tbody>
            </table>
            {policies.length === 0 && <p className="empty">Publish a policy to start the version history.</p>}
          </div>
        </section>

        <section className="panel table-panel" id="browsers" aria-labelledby="browsers-heading">
          <div className="panel-heading"><h2 id="browsers-heading">Browser health</h2><span className="table-note">Latest 100 installations</span></div>
          <div className="table-scroll" tabIndex={0} role="region" aria-labelledby="browsers-heading">
            <table aria-labelledby="browsers-heading">
              <thead><tr><th>Installation</th><th>Policy status</th><th>Applied version</th><th>ChatGPT composer</th><th>Last seen (UTC)</th><th>Action</th></tr></thead>
              <tbody>{installations.map((installation) => <BrowserRow key={installation.installationId}
                installation={installation} latestVersion={current?.version} />)}</tbody>
            </table>
            {installations.length === 0 && <p className="empty">No browsers enrolled yet. Create an enrollment grant to add one.</p>}
          </div>
        </section>

        <section className="panel table-panel" id="events" aria-labelledby="events-heading">
          <div className="panel-heading"><h2 id="events-heading">Security events</h2><span className="table-note">Latest 100 matching events</span></div>
          <form action="/#events" method="get" className="filters">
            <div><label htmlFor="event-application">Application</label>
              <select id="event-application" name="app" defaultValue={filters.app}>
                <option value="">All applications</option><option value={fixtureApp}>Local prompt fixture</option>
                <option value={chatGptApp}>ChatGPT</option>
              </select>
            </div>
            <div><label htmlFor="event-decision">Decision</label>
              <select id="event-decision" name="decision" defaultValue={filters.decision}>
                <option value="">All decisions</option>
                {decisions.map((decision) => <option key={decision} value={decision}>{decisionLabels[decision]}</option>)}
              </select>
            </div>
            <div><label htmlFor="event-period">Time range</label>
              <select id="event-period" name="period" defaultValue={filters.period}>
                <option value="">All time</option><option value="day">Past 24 hours</option><option value="week">Past 7 days</option>
              </select>
            </div>
            <button className="button">Apply filters</button>
            {filters.query.size > 0 && <a className="clear-link" href="/#events">Clear filters</a>}
          </form>
          <div className="table-scroll" tabIndex={0} role="region" aria-labelledby="events-heading">
            <table aria-labelledby="events-heading">
              <thead><tr><th>Occurred (UTC)</th><th>Application</th><th>Decision</th><th>Detector</th><th>Policy</th><th>Installation</th></tr></thead>
              <tbody>{events.map((event) => <EventRow key={`${event.installationId}:${event.eventId}`} event={event} />)}</tbody>
            </table>
            {events.length === 0 && <p className="empty">{filters.query.size ? 'No events match these filters.' : 'No security events recorded yet.'}</p>}
          </div>
        </section>
      </main>
    </div>;
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) return <SignIn invalid />;
    if (!(error instanceof ApiError)) throw error;
    return <main className="auth-shell">
      <section className="auth-card">
        <Brand />
        <h1>Control API unavailable</h1>
        <p className="muted">Start the local Control API and PostgreSQL, then reload the dashboard.</p>
        <a className="button primary" href="/">Reload dashboard</a>
        <form action={signOut}><button className="button">Sign out</button></form>
      </section>
    </main>;
  }
}

function Brand() {
  return <div className="brand"><span className="brand-mark" aria-hidden="true">Z</span>
    <span><strong>ZEKVAR</strong><span>CONTROL</span></span>
  </div>;
}

function SignIn({ invalid }: { invalid?: boolean }) {
  return <main className="auth-shell">
    <section className="auth-card" aria-labelledby="sign-in-heading">
      <Brand />
      <div><h1 id="sign-in-heading">Sign in to Control</h1>
        <p className="muted">Use the admin token configured for your local Control API.</p></div>
      <SignInForm invalid={invalid} />
    </section>
  </main>;
}

function Timestamp({ value }: { value: string }) {
  return <time dateTime={value}>{utc.format(new Date(value))}</time>;
}

function DecisionBadge({ decision }: { decision: Decision }) {
  return <span className={`badge decision ${decision}`}>{decisionLabels[decision]}</span>;
}

function InstallationId({ value }: { value: string }) {
  return <code title={value}>{value.slice(0, 13)}</code>;
}

function PolicyRow({ policy, current }: { policy: Policy; current: boolean }) {
  return <tr>
    <td className="emphasis">v{policy.version}</td><td><DecisionBadge decision={policy.mode} /></td>
    <td><Timestamp value={policy.publishedAt} /></td>
    <td>{policy.restoredFrom ? `v${policy.restoredFrom}` : '—'}</td>
    <td>{current ? <span className="badge current">Current</span> :
      <MutationForm action={restorePolicy} label="Restore" appearance="small" accessibleLabel={`Restore version ${policy.version}`}>
        <input type="hidden" name="version" value={policy.version} />
      </MutationForm>}
    </td>
  </tr>;
}

function BrowserRow({ installation, latestVersion }: { installation: Installation; latestVersion?: number }) {
  const status = installation.revokedAt ? 'Revoked' : installation.appliedPolicyVersion === null ? 'Awaiting policy' :
    installation.appliedPolicyVersion === latestVersion ? 'Current' : 'Update pending';
  return <tr>
    <td><InstallationId value={installation.installationId} /></td>
    <td><span className={`badge ${status === 'Current' ? 'current' : ''}`}>{status}</span></td>
    <td>{installation.appliedPolicyVersion ? `v${installation.appliedPolicyVersion}` : '—'}</td>
    <td><span className={`badge ${installation.chatGptCoverage === 'unsupported' ? 'warn' : ''}`}>
      {installation.chatGptCoverage === 'ready' ? 'Detected' : installation.chatGptCoverage === 'unsupported' ? 'Unsupported' : 'Unobserved'}
    </span>{installation.chatGptCheckedAt && <div className="muted"><Timestamp value={installation.chatGptCheckedAt} /> UTC</div>}</td>
    <td><Timestamp value={installation.lastSeenAt} /></td>
    <td>{installation.revokedAt ? '—' :
      <MutationForm action={revokeInstallation} label="Revoke" appearance="small danger"
        accessibleLabel={`Revoke installation ${installation.installationId}`}
        confirmation="Revoke this browser’s access to Control? It will need a new enrollment grant.">
        <input type="hidden" name="installationId" value={installation.installationId} />
      </MutationForm>}
    </td>
  </tr>;
}

function EventRow({ event }: { event: SecurityEvent }) {
  return <tr>
    <td><Timestamp value={event.timestamp} /></td>
    <td className="emphasis">{event.appId === fixtureApp ? 'Local prompt fixture' : event.appId === chatGptApp ? 'ChatGPT' : event.appId}</td>
    <td><DecisionBadge decision={event.decision} /></td>
    <td>{event.detectorCategory === 'synthetic-secret' ? 'Synthetic secret' : event.detectorCategory}</td>
    <td>v{event.policyVersion}</td>
    <td><InstallationId value={event.installationId} /></td>
  </tr>;
}
