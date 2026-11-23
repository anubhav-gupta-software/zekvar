import { redirect } from 'next/navigation';
import { canChangePolicy } from '../../../lib/access';
import { ApiError, controlApi } from '../../../lib/api';
import { isId } from '../../../lib/control';
import { extensionModeLabels, unlistedLabels } from '../../../lib/extension-deployment';
import { sessionToken } from '../../../lib/session';
import { DeploymentBadge, Sidebar } from '../../workspace';
import { DeploymentEditor, DeploymentDownload } from './deployment-form';

export default async function ExtensionDeploymentPage({ searchParams }: { searchParams: Promise<{ group?: string | string[] }> }) {
  const token = await sessionToken();
  if (!token) redirect('/');
  const { group } = await searchParams;
  const data = await loadDeployment(token, group).catch((error) => {
    if (error instanceof ApiError && error.status === 401) redirect('/');
    if (error instanceof ApiError) return undefined;
    throw error;
  });
  const reference = data?.reference;
  const current = reference?.extensionDeployment;
  return <div className="workspace">
    <Sidebar active="extensions" session={data?.session} />
    <main className="dashboard">
      <header className="page-heading">
        <div>{data && <p className="eyebrow">{data.session.organization}</p>}<h1>Chrome extension deployment</h1></div>
        <DeploymentBadge />
      </header>
      {data && <section className="panel" aria-labelledby="deployment-scope-heading">
        <h2 id="deployment-scope-heading">Policy scope</h2>
        <form action="/extensions/deployment" method="get" className="form-row preview-scope">
          <div className="grid gap-1">
            <label htmlFor="deployment-scope">Scope</label>
            <select id="deployment-scope" name="group" defaultValue={data.selected?.id ?? ''}>
              <option value="">Organization baseline</option>
              {data.groups.map(({ id, name }) => <option key={id} value={id}>{name}</option>)}
            </select>
          </div>
          <button className="button">Open scope</button>
          <a className="clear-link" href="/extensions">View extension inventory</a>
        </form>
      </section>}
      {data && reference && current ? <>
        <section className="panel table-panel" aria-labelledby="current-deployment">
          <div className="panel-heading">
            <h2 id="current-deployment">Published plan</h2>
            <span className="badge">Version {reference.version}</span>
          </div>
          <p className="empty">{data.selected ? data.selected.name : 'Organization baseline'} · {unlistedLabels[current.unlisted]}
            {data.inherited && ' · Inherited from the baseline'}</p>
          {current.rules.length > 0 && <div className="table-scroll" tabIndex={0} role="region" aria-labelledby="current-deployment">
            <table aria-labelledby="current-deployment">
              <thead><tr><th>Extension ID</th><th>Action</th><th>Update manifest</th></tr></thead>
              <tbody>{current.rules.map(({ id, mode, updateUrl }) => <tr key={id}>
                <th scope="row"><code>{id}</code></th><td>{extensionModeLabels[mode]}</td><td>{updateUrl ?? '—'}</td>
              </tr>)}</tbody>
            </table>
          </div>}
        </section>
        {canChangePolicy(data.session) && <DeploymentEditor key={`${data.selected?.id}:${reference.version}`} version={reference.version}
          groupId={data.selected?.id} plan={current} review={data.session.reviewRequired} />}
        <DeploymentDownload key={`${data.selected?.id}:${reference.version}`} version={reference.version} plan={current} />
      </> : <section className="panel" role="alert">{reference
        ? 'Update Control API to use Chrome extension deployment.'
        : data ? 'The selected policy scope is unavailable.' : 'Control could not load the deployment plan.'}</section>}
    </main>
  </div>;
}

async function loadDeployment(token: string, group: string | string[] | undefined) {
  const [session, groups, baseline] = await Promise.all([controlApi.session(token), controlApi.groups(token), controlApi.policies(token)]);
  if (!group) return { session, groups, reference: baseline[0] };
  const selected = isId(group) ? groups.find(({ id }) => id === group.toLowerCase()) : undefined;
  if (!selected) return { session, groups };
  const [scoped] = await controlApi.policies(token, selected.id);
  return { session, groups, selected, reference: scoped ?? baseline[0], inherited: !scoped };
}
