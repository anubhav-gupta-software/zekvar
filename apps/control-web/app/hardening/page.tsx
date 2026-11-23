import { redirect } from 'next/navigation';
import { canChangePolicy } from '../../lib/access';
import { ApiError, controlApi } from '../../lib/api';
import { hardeningFields, hardeningValue, type BrowserHardening } from '../../lib/browser-hardening';
import { isId } from '../../lib/control';
import { sessionToken } from '../../lib/session';
import { DeploymentBadge, Sidebar } from '../workspace';
import { HardeningEditor, HardeningDownload } from './hardening-form';

export default async function HardeningPage({ searchParams }: { searchParams: Promise<{ group?: string | string[] }> }) {
  const token = await sessionToken();
  if (!token) redirect('/');
  const { group } = await searchParams;
  const data = await loadHardening(token, group).catch((error) => {
    if (error instanceof ApiError && error.status === 401) redirect('/');
    if (error instanceof ApiError) return undefined;
    throw error;
  });
  const reference = data?.reference;
  const current = reference?.browserHardening;
  return <div className="workspace">
    <Sidebar active="hardening" session={data?.session} />
    <main className="dashboard">
      <header className="page-heading">
        <div>{data && <p className="eyebrow">{data.session.organization}</p>}<h1>Chrome hardening</h1></div>
        <DeploymentBadge />
      </header>
      {data && <section className="panel" aria-labelledby="hardening-scope-heading">
        <h2 id="hardening-scope-heading">Policy scope</h2>
        <form action="/hardening" method="get" className="form-row preview-scope">
          <div className="grid gap-1">
            <label htmlFor="hardening-scope">Scope</label>
            <select id="hardening-scope" name="group" defaultValue={data.selected?.id ?? ''}>
              <option value="">Organization baseline</option>
              {data.groups.map(({ id, name }) => <option key={id} value={id}>{name}</option>)}
            </select>
          </div>
          <button className="button">Open scope</button>
        </form>
      </section>}
      {data && reference && current ? <>
        <section className="panel table-panel" aria-labelledby="hardening-current-heading">
          <div className="panel-heading">
            <h2 id="hardening-current-heading">Published hardening plan</h2>
            <span className="badge">Version {reference.version}</span>
          </div>
          <p className="empty">{data.selected?.name ?? 'Organization baseline'}{data.inherited && ' · Inherited from the baseline'}.
            {' '}Apply the export through your device manager and verify the result on the target browsers.</p>
          <div className="table-scroll" tabIndex={0} role="region" aria-labelledby="hardening-current-heading">
            <table aria-labelledby="hardening-current-heading">
              <thead><tr><th>Chrome setting</th><th>Plan</th></tr></thead>
              <tbody>{(Object.keys(hardeningFields) as (keyof BrowserHardening)[]).map((key) => <tr key={key}>
                <th scope="row">{hardeningFields[key].label}</th>
                <td>{hardeningFields[key].options[hardeningValue(current[key])]}</td>
              </tr>)}</tbody>
            </table>
          </div>
        </section>
        {canChangePolicy(data.session) && <HardeningEditor key={`${data.selected?.id}:${reference.version}`}
          version={reference.version} groupId={data.selected?.id} plan={current} review={data.session.reviewRequired} />}
        <HardeningDownload key={`${data.selected?.id}:${reference.version}`} version={reference.version} plan={current} />
      </> : <section className="panel" role="alert">{reference ? 'Update Control API to use Chrome hardening.'
        : data ? 'The selected policy scope is unavailable.' : 'Control could not load the hardening plan.'}</section>}
    </main>
  </div>;
}

async function loadHardening(token: string, group: string | string[] | undefined) {
  const [session, groups, baseline] = await Promise.all([controlApi.session(token), controlApi.groups(token), controlApi.policies(token)]);
  if (!group) return { session, groups, reference: baseline[0] };
  const selected = isId(group) ? groups.find(({ id }) => id === group.toLowerCase()) : undefined;
  if (!selected) return { session, groups };
  const [scoped] = await controlApi.policies(token, selected.id);
  return { session, groups, selected, reference: scoped ?? baseline[0], inherited: !scoped };
}
