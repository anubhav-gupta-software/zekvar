import { ApiError, controlApi } from '../lib/api';
import {
  aiApps, classifications, classificationLabels, decisionLabels, decisions, isPromptApp, promptAppLabels, ruleLabels, utc,
  type BrowserReleaseCount, type Decision, type DiscoveredApp, type Installation, type SecurityEvent,
} from '../lib/control';
import { eventFilters, setEventCursor } from '../lib/events';
import { canChangePolicy, canWrite } from '../lib/access';
import { sessionToken } from '../lib/session';
import { ssoOptions } from '../lib/sso';
import { classifyAiApp, revokeInstallation, signOut } from './actions';
import { DomainRulesForm, EnrollmentForm, MutationForm, RefreshSection, SignInForm } from './forms';
import { PolicyVersionTable, PublishPolicyForm } from './policies';
import { Brand, DeploymentBadge, Sidebar } from './workspace';
import { uploadMethods } from '../../../contracts/policy/uploads';

type Search = Record<string, string | string[] | undefined>;

export default async function Control({ searchParams }: { searchParams: Promise<Search> }) {
  const token = await sessionToken();
  const search = await searchParams;
  if (!token) return <SignIn invalid={search.session === 'ended'} ssoError={search.signIn === 'sso-error'} />;
  const filters = eventFilters(search);
  const historyQuery = new URLSearchParams(filters.query);
  if (filters.cursor) setEventCursor(historyQuery, filters.cursor);

  try {
    const [session, policies, installations, releases, history, discoveredApps] = await Promise.all([
      controlApi.session(token), controlApi.policies(token),
      controlApi.installations(token),
      controlApi.browserReleases(token),
      filters.invalidInstallation || filters.invalidCursor ? undefined : controlApi.events(token, historyQuery),
      controlApi.aiApps(token),
    ]);
    const events = history?.entries ?? [];
    const older = new URLSearchParams(filters.page);
    if (history?.next) setEventCursor(older, history.next);
    const current = policies[0];
    const writable = canWrite(session);
    const policyWritable = canChangePolicy(session);
    const active = releases?.reduce((total, row) => total + row.installations, 0) ?? installations.filter(({ revokedAt }) => !revokedAt).length;
    return <div className="workspace" id="overview">
      <Sidebar session={session} />
      <main className="dashboard">
        <header className="page-heading">
          <div>
            <p className="eyebrow">{session.organization}</p>
            <h1>Security overview</h1>
          </div>
          <DeploymentBadge />
        </header>

        <div className="metrics" aria-label="Control summary">
          <div className="metric"><p>Test marker policy</p>
            <strong>{current ? decisionLabels[current.mode] : 'None'}</strong>
            <span>{current ? `Version ${current.version}` : 'Publish a policy to get started'}</span>
          </div>
          <div className="metric"><p>Active installations</p><strong>{active}</strong>
            <span>{!releases && installations.length === 100 ? 'Among the latest 100' : 'With valid credentials'}</span>
          </div>
          <div className="metric"><p>Events shown</p><strong>{events.length}</strong>
            <span>{filters.cursor ? 'Older events' : filters.query.size ? 'Filtered view' : 'Latest 100 events'}</span>
          </div>
        </div>

        {writable && <><div className="controls-grid">
          <section className="panel" id="policies" aria-labelledby="policies-heading">
            <div className="panel-heading"><h2 id="policies-heading">{session.reviewRequired ? 'Policy changes' : 'Publish a policy'}</h2>
              <span className="badge">Organization-wide</span></div>
            {policyWritable ? <><p className="muted">Set prompt protection, app discovery, and extension inventory for enrolled browsers.</p>
              <PublishPolicyForm policy={current} review={session.reviewRequired} /></> :
              <p className="muted">Sign in as a named administrator to request policy changes.</p>}
          </section>
          <section className="panel" aria-labelledby="enrollment-heading">
            <div className="panel-heading"><h2 id="enrollment-heading">Browser enrollment</h2></div>
            <p className="muted">Create a single-use grant for a browser. It expires in 10 minutes.</p>
            <EnrollmentForm />
          </section>
        </div>

        {policyWritable && <section className="panel" id="domain-rules" aria-labelledby="domain-rules-heading">
          <div className="panel-heading"><h2 id="domain-rules-heading">Navigation rules</h2><span className="badge">Organization-wide</span></div>
          <DomainRulesForm rules={current?.domainRules} paths={current?.pathRules} version={current?.version} review={session.reviewRequired} />
        </section>}</>}

        <PolicyVersionTable policies={policies} writable={policyWritable} review={session.reviewRequired} />

        <section className="panel table-panel" id="ai-apps" aria-labelledby="ai-apps-heading">
          <div className="panel-heading"><h2 id="ai-apps-heading">App inventory</h2><div className="form-row">
            {policyWritable && <a className="button small" href="/preview#draft-app-catalog">Edit app catalog</a>}
            <RefreshSection label="Refresh app inventory" /></div></div>
          <div className="table-scroll" tabIndex={0} role="region" aria-labelledby="ai-apps-heading">
            <table aria-labelledby="ai-apps-heading">
              <thead><tr><th>Application</th><th>Browsers seen (30 days)</th><th>Last observed (UTC)</th><th>Classification</th></tr></thead>
              <tbody>{discoveredApps.map((app) => <DiscoveredAppRow key={app.appId} app={app} writable={writable} />)}</tbody>
            </table>
          </div>
          <p className="empty">Cataloged sites opened in enrolled Chrome browsers. Use classification labels to review adoption and configure enforcement in policies.</p>
        </section>

        <section className="panel table-panel" id="browsers" aria-labelledby="browsers-heading">
          <div className="panel-heading"><h2 id="browsers-heading">Browser health</h2><RefreshSection label="Refresh browser health" /></div>
          {releases && releases.length > 0 && <BrowserReleases releases={releases} />}
          <div className="table-scroll" tabIndex={0} role="region" aria-labelledby="browsers-heading">
            <table aria-labelledby="browsers-heading">
              <thead><tr><th>Installation</th><th>Rollout group</th><th>Reporting</th><th>Extension version</th><th>Policy status</th><th>Applied policy</th><th>ChatGPT composer</th><th>Gemini composer</th><th>Claude composer</th><th>Last seen (UTC)</th><th>Action</th></tr></thead>
              <tbody>{installations.map((installation) => <BrowserRow key={installation.installationId}
                installation={installation} latestVersion={current?.version} writable={writable} />)}</tbody>
            </table>
            {installations.length === 0 && <p className="empty">No browsers enrolled yet. Create an enrollment grant to add one.</p>}
          </div>
          {installations.length === 100 && <div className="table-footer"><p className="table-note">Latest 100 installations.</p></div>}
        </section>

        <section className="panel table-panel" id="events" aria-labelledby="events-heading">
          <div className="panel-heading">
            <h2 id="events-heading">Security events</h2>
            {history && <a className="button small" href={`/events/export?${filters.query}`} download>Export security events (JSON)</a>}
          </div>
          <form action="/#events" method="get" className="filters">
            <div><label htmlFor="event-application">Application</label>
              <select id="event-application" name="app" defaultValue={filters.app}>
                <option value="">All applications</option>
                {Object.entries(promptAppLabels).map(([app, label]) => <option value={app} key={app}>{label}</option>)}
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
            <div><label htmlFor="event-installation">Browser installation ID</label>
              <input id="event-installation" name="installation" defaultValue={filters.installation} maxLength={36}
                autoCapitalize="none" autoComplete="off" spellCheck={false} placeholder="All browsers" />
            </div>
            <button className="button">Apply filters</button>
            {(filters.query.size > 0 || filters.cursor || !history) && <a className="clear-link" href="/#events">Clear filters</a>}
          </form>
          {!history ? <p className="empty" role="alert">{filters.invalidInstallation
            ? 'Enter a complete browser installation ID.' : 'This event history link is invalid. Clear the filters to open the newest events.'}</p>
            : <>
              <div className="table-scroll" tabIndex={0} role="region" aria-labelledby="events-heading">
                <table aria-labelledby="events-heading">
                  <thead><tr><th>Occurred (UTC)</th><th>Application</th><th>Decision</th><th>Detector</th><th>Policy</th><th>Installation</th></tr></thead>
                  <tbody>{events.map((event) => <EventRow key={`${event.installationId}:${event.eventId}`} event={event} filters={filters.page} />)}</tbody>
                </table>
                {events.length === 0 && <p className="empty">{filters.query.size ? 'No events match these filters.' : 'No security events recorded yet.'}</p>}
              </div>
              <div className="table-footer">
                <p className="table-note">Up to 100 per page, newest first by time received. Export includes all matching retained events.</p>
                <div className="form-row">
                  {filters.cursor && <a className="button small" href={`/?${filters.page}#events`}>Newest events</a>}
                  {history.next && <a className="button small" href={`/?${older}#events`}>Older events</a>}
                </div>
              </div>
            </>}
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
        <p className="muted">Check the Control API and database connection, then reload the dashboard.</p>
        <a className="button primary" href="/">Reload dashboard</a>
        <form action={signOut}><button className="button">Sign out</button></form>
      </section>
    </main>;
  }
}

function SignIn({ invalid, ssoError }: { invalid?: boolean; ssoError?: boolean }) {
  const sso = Boolean(ssoOptions());
  return <main className="auth-shell">
    <section className="auth-card" aria-labelledby="sign-in-heading">
      <Brand />
      <div><h1 id="sign-in-heading">Sign in to Control</h1>
        <p className="muted">{sso ? 'Use your organization’s identity provider or a Control token.' :
          'Use your delegated token or the owner token configured for this deployment.'}</p></div>
      {ssoError && <p className="feedback error" role="alert">Single sign-on could not complete. Try again or contact your Control administrator.</p>}
      {sso && <a className="button primary" href="/auth/sso/start">Sign in with single sign-on</a>}
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

function DiscoveredAppRow({ app, writable }: { app: DiscoveredApp; writable: boolean }) {
  const name = app.name ?? aiApps[app.appId as keyof typeof aiApps];
  const caption = app.host ? `${name} at ${app.host}` : name;
  return <tr>
    <th scope="row" className="emphasis">{name}{app.host && <div className="muted">{app.host}</div>}</th>
    <td>{app.browsersSeen}</td>
    <td>{app.lastObservedAt ? <Timestamp value={app.lastObservedAt} /> : '—'}</td>
    <td>
      {writable ? <MutationForm action={classifyAiApp} label="Save" appearance="small" accessibleLabel={`Save ${caption} classification`}>
        <input type="hidden" name="appId" value={app.appId} />
        <select key={app.status} name="status" aria-label={`${caption} classification`} defaultValue={app.status}>
          {classifications.map((status) => <option key={status} value={status}>{classificationLabels[status]}</option>)}
        </select>
      </MutationForm> : classificationLabels[app.status]}
    </td>
  </tr>;
}

function BrowserReleases({ releases }: { releases: BrowserReleaseCount[] }) {
  return <details className="browser-releases" open>
    <summary id="browser-releases-heading">Extension rollout</summary>
    <div className="table-scroll" tabIndex={0} role="region" aria-labelledby="browser-releases-heading">
      <table aria-labelledby="browser-releases-heading">
        <thead><tr><th scope="col">Extension version</th><th scope="col">Active installations</th><th scope="col">Version reported in last 90 seconds</th></tr></thead>
        <tbody>{releases.map(({ kind, extensionVersion, installations, recentReports }) =>
          <tr key={extensionVersion ?? kind}><th scope="row">{kind === 'release' ? extensionVersion : kind === 'other' ? 'Other versions' : 'Unreported'}</th>
            <td>{installations}</td><td>{recentReports}</td></tr>)}</tbody>
      </table>
    </div>
  </details>;
}

function BrowserRow({ installation, latestVersion, writable }: { installation: Installation; latestVersion?: number; writable: boolean }) {
  const status = installation.revokedAt ? 'Revoked' : installation.appliedPolicyVersion === null ? 'Awaiting policy' :
    installation.appliedPolicyVersion === (installation.expectedPolicyVersion ?? latestVersion) ? 'Current' : 'Update pending';
  const stale = Date.now() - Date.parse(installation.lastSeenAt) >= 90_000;
  return <tr>
    <td><InstallationId value={installation.installationId} /></td>
    <td>{installation.policyGroupName ?? 'Organization baseline'}</td>
    <td>{installation.revokedAt ? '—' : <span className={`badge ${stale ? 'warn' : 'current'}`}>{stale ? 'Stale' : 'Reporting'}</span>}</td>
    <td>{installation.extensionVersion ? <><code>{installation.extensionVersion}</code>
      {installation.extensionVersionReportedAt && <div className="muted"><Timestamp value={installation.extensionVersionReportedAt} /> UTC</div>}</>
      : 'Unreported'}</td>
    <td><span className={`badge ${status === 'Current' ? 'current' : ''}`}>{status}</span></td>
    <td>{installation.appliedPolicyVersion ? `v${installation.appliedPolicyVersion}` : '—'}</td>
    <CoverageCell coverage={installation.chatGptCoverage} checkedAt={installation.chatGptCheckedAt} />
    <CoverageCell coverage={installation.geminiCoverage} checkedAt={installation.geminiCheckedAt} />
    <CoverageCell coverage={installation.claudeCoverage} checkedAt={installation.claudeCheckedAt} enabled={installation.claudePromptEnabled === true} />
    <td><Timestamp value={installation.lastSeenAt} /></td>
    <td>{installation.revokedAt || !writable ? '—' :
      <MutationForm action={revokeInstallation} label="Revoke" appearance="small danger"
        accessibleLabel={`Revoke installation ${installation.installationId}`}
        confirmation="Revoke this browser’s access to Control? It will need a new enrollment grant.">
        <input type="hidden" name="installationId" value={installation.installationId} />
      </MutationForm>}
    </td>
  </tr>;
}

function CoverageCell({ coverage, checkedAt, enabled = true }: { coverage?: 'ready' | 'unsupported' | null; checkedAt?: string | null; enabled?: boolean }) {
  return <td><span className={`badge ${coverage === 'unsupported' ? 'warn' : ''}`}>
    {!enabled ? 'Off' : coverage === 'ready' ? 'Detected' : coverage === 'unsupported' ? 'Unsupported' : 'Unobserved'}
  </span>{checkedAt && <div className="muted"><Timestamp value={checkedAt} /> UTC</div>}</td>;
}

function EventRow({ event, filters }: { event: SecurityEvent; filters: URLSearchParams }) {
  const browser = new URLSearchParams(filters);
  browser.set('installation', event.installationId);
  return <tr>
    <td><Timestamp value={event.timestamp} /></td>
    <td className="emphasis">{isPromptApp(event.appId) ? promptAppLabels[event.appId] : event.appId}</td>
    <td><DecisionBadge decision={event.decision} /></td>
    <td>{event.uploadMethod ? <>File upload <div className="muted">{uploadMethods[event.uploadMethod]}</div></> :
      ruleLabels[event.ruleId as keyof typeof ruleLabels] ?? event.detectorCategory}</td>
    <td>v{event.policyVersion}</td>
    <td><a className="underline" href={`/?${browser}#events`}
      aria-label={`Filter events for installation ${event.installationId}`}><InstallationId value={event.installationId} /></a></td>
  </tr>;
}
