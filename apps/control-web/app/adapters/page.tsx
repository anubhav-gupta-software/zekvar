import { redirect } from 'next/navigation';
import { canChangePolicy } from '../../lib/access';
import { ApiError, controlApi } from '../../lib/api';
import { aiPromptApps, isId, promptAppLabels, type ComposerReadinessReport } from '../../lib/control';
import { sessionToken } from '../../lib/session';
import { adapterFallbackLabels, adapterHosts, adapterScopeLabels, type AdapterControl } from '../../../../contracts/policy/adapter-controls';
import { publishAdapterControl } from '../actions';
import { MutationForm } from '../forms';
import { DeploymentBadge, Sidebar } from '../workspace';

function controlLabel(control?: AdapterControl) {
  if (!control) return 'Active';
  return `${adapterScopeLabels[control.scope]} · ${control.fallback === 'closed' ? 'Fail closed' : 'Fail open'}`;
}

export default async function AdaptersPage({ searchParams }: { searchParams: Promise<{ group?: string | string[] }> }) {
  const token = await sessionToken();
  if (!token) redirect('/');
  const { group } = await searchParams;
  const data = await loadAdapters(token, group).catch((error) => {
    if (error instanceof ApiError && error.status === 401) redirect('/');
    if (error instanceof ApiError) return undefined;
    throw error;
  });
  const reference = data?.reference;
  const controls = reference?.adapterControls;
  const scopeName = data?.selected?.name ?? 'Organization baseline';
  const writable = data && canChangePolicy(data.session);
  return <div className="workspace">
    <Sidebar active="adapters" session={data?.session} />
    <main className="dashboard">
      <header className="page-heading">
        <div>{data && <p className="eyebrow">{data.session.organization}</p>}<h1>Adapter controls</h1></div>
        <DeploymentBadge />
      </header>
      {data && <section className="panel" aria-labelledby="adapter-scope-heading">
        <h2 id="adapter-scope-heading">Policy scope</h2>
        <form action="/adapters" method="get" className="form-row preview-scope">
          <div className="grid gap-1">
            <label htmlFor="adapter-scope">Scope</label>
            <select id="adapter-scope" name="group" defaultValue={data.selected?.id ?? ''}>
              <option value="">Organization baseline</option>
              {data.groups.map(({ id, name }) => <option key={id} value={id}>{name}</option>)}
            </select>
          </div>
          <button className="button">Open scope</button>
        </form>
      </section>}
      {data && reference && controls ? <>
        <section className="panel table-panel" aria-labelledby="adapter-status-heading">
          <div className="panel-heading">
            <h2 id="adapter-status-heading">Adapter status</h2>
            <span className="badge">Version {reference.version}</span>
          </div>
          <p className="empty">{scopeName}{data.inherited && ' · Inherited from the baseline'}. A rise in Unsupported composers after an
            AI app changes its page usually means the adapter is broken. Disable it here, notify affected users, and restore it after a
            fixed Browser release reports Detected composers.</p>
          <div className="table-scroll" tabIndex={0} role="region" aria-labelledby="adapter-status-heading">
            <table aria-labelledby="adapter-status-heading">
              <thead><tr><th scope="col">AI app</th><th scope="col">Administrator control</th><th scope="col">Detected</th>
                <th scope="col">Unsupported</th><th scope="col">Disabled by administrator</th><th scope="col">Attachments disabled</th>
                <th scope="col">Policy pending</th><th scope="col">Stale</th></tr></thead>
              <tbody>{aiPromptApps.map((app) => {
                const counts = data.readiness?.apps.find(({ appId }) => appId === app);
                const unsupported = counts?.counts.unsupported ?? 0;
                return <tr key={app}>
                  <th scope="row">{promptAppLabels[app]}{unsupported > 0 && !controls[app] &&
                    <> <span className="badge warn">Possible broken adapter</span></>}</th>
                  <td>{controlLabel(controls[app])}</td>
                  <td>{counts?.counts.detected ?? '—'}</td>
                  <td>{counts ? unsupported : '—'}</td>
                  <td>{counts?.counts.disabled_by_admin ?? '—'}</td>
                  <td>{counts?.attachmentsDisabled ?? '—'}</td>
                  <td>{counts?.counts.policy_pending ?? '—'}</td>
                  <td>{counts?.counts.stale ?? '—'}</td>
                </tr>;
              })}</tbody>
            </table>
          </div>
          <p className="table-footer table-note">Browser v0.42.0 or later applies these controls. Older releases keep intercepting and stay Policy pending.
            Fail closed blocks the app hosts on every release that supports AI app access.</p>
        </section>
        {writable && aiPromptApps.map((app) => {
          const current = controls[app];
          return <section key={app} className="panel" aria-labelledby={`adapter-${app}-heading`}>
            <h2 id={`adapter-${app}-heading`}>{promptAppLabels[app]} adapter</h2>
            <p className="muted">Current: {controlLabel(current)}. Fail closed blocks {adapterHosts[app].map((host, index) =>
              <span key={host}>{index ? ', ' : ''}<code>{host}</code></span>)} for this scope.</p>
            <MutationForm action={publishAdapterControl} label={`Publish ${promptAppLabels[app]} adapter control`} appearance="primary"
              confirmation={`Publish the ${promptAppLabels[app]} adapter control to ${scopeName}?`}>
              <input type="hidden" name="app" value={app} />
              <input type="hidden" name="expectedVersion" value={reference.version} />
              <input type="hidden" name="current" value={JSON.stringify(controls)} />
              {data.selected && <input type="hidden" name="groupId" value={data.selected.id} />}
              {data.session.reviewRequired && <input type="hidden" name="expectReview" value="on" />}
              <div className="grid gap-1">
                <label htmlFor={`adapter-${app}-scope`}>{promptAppLabels[app]} interception</label>
                <select id={`adapter-${app}-scope`} name="scope" defaultValue={current?.scope ?? 'active'}>
                  <option value="active">Active (protected)</option>
                  <option value="attachments">{adapterScopeLabels.attachments}</option>
                  <option value="adapter">{adapterScopeLabels.adapter}</option>
                </select>
              </div>
              <div className="grid gap-1">
                <label htmlFor={`adapter-${app}-fallback`}>{promptAppLabels[app]} when disabled</label>
                <select id={`adapter-${app}-fallback`} name="fallback" defaultValue={current?.fallback ?? 'open'}>
                  <option value="open">{adapterFallbackLabels.open}</option>
                  <option value="closed">{adapterFallbackLabels.closed}</option>
                </select>
              </div>
            </MutationForm>
          </section>;
        })}
      </> : <section className="panel" role="alert">{reference ? 'Update Control API to use adapter controls.'
        : data ? 'The selected policy scope is unavailable.' : 'Control could not load adapter controls.'}</section>}
    </main>
  </div>;
}

async function loadAdapters(token: string, group: string | string[] | undefined) {
  const [session, groups, baseline] = await Promise.all([controlApi.session(token), controlApi.groups(token), controlApi.policies(token)]);
  const selected = typeof group === 'string' && isId(group) ? groups.find(({ id }) => id === group.toLowerCase()) : undefined;
  if (group && !selected) return { session, groups };
  const scoped = selected ? (await controlApi.policies(token, selected.id))[0] : undefined;
  const readiness: ComposerReadinessReport | undefined = await controlApi.composerReadiness(token,
    new URLSearchParams({ rolloutGroup: selected?.id ?? 'baseline' })).catch((error) => {
    if (error instanceof ApiError && error.status !== 401) return undefined;
    throw error;
  });
  return { session, groups, selected, reference: scoped ?? baseline[0], inherited: Boolean(selected && !scoped), readiness };
}
