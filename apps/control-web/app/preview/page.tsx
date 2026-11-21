import { redirect } from 'next/navigation';
import { ApiError, controlApi } from '../../lib/api';
import { canChangePolicy } from '../../lib/access';
import { previewSnapshot } from '../../lib/preview';
import { sessionToken } from '../../lib/session';
import { Sidebar } from '../workspace';
import { PolicyPreview } from './preview';

export default async function PreviewPage({ searchParams }: { searchParams: Promise<{ group?: string | string[] }> }) {
  const token = await sessionToken();
  if (!token) redirect('/');
  const { group: selectedId } = await searchParams;
  const data = await loadPreview(token, selectedId).catch((error) => {
    if (error instanceof ApiError && error.status === 401) redirect('/');
    if (error instanceof ApiError) return undefined;
    throw error;
  });

  return <div className="workspace">
    <Sidebar active="preview" session={data?.session} />
    <main className="dashboard">
      <header className="page-heading">
        <div>{data && <p className="eyebrow">{data.session.organization}</p>}<h1>Policy preview</h1></div>
        <span className="badge local"><span aria-hidden="true" />Local demo</span>
      </header>
      {data ? <>
        {data.groups.length > 0 && <section className="panel" aria-labelledby="preview-scope-heading">
          <h2 id="preview-scope-heading">Policy scope</h2>
          <form action="/preview" method="get" className="form-row preview-scope">
            <div className="grid gap-1">
              <label htmlFor="preview-scope">Scope</label>
              <select id="preview-scope" name="group" defaultValue={data.selected?.id ?? ''}>
                <option value="">Organization baseline</option>
                {data.groups.map((group) => <option key={group.id} value={group.id}>{group.name}</option>)}
              </select>
            </div>
            <button className="button">Open scope</button>
          </form>
        </section>}
        {data.reference ? <PolicyPreview key={data.selected?.id ?? 'baseline'} reference={data.reference}
          snapshots={data.snapshots} groupId={data.selected?.id} scopeName={data.selected?.name ?? 'Organization baseline'}
          writable={canChangePolicy(data.session)} review={data.session.reviewRequired} /> :
          <section className="panel" role="alert">This policy scope is unavailable. <a className="underline" href="/preview">Open the organization baseline</a></section>}
      </> : <section className="panel" role="alert">Control could not load policy snapshots. Try reloading this page.</section>}
    </main>
  </div>;
}

async function loadPreview(token: string, selectedId: string | string[] | undefined) {
  const [session, groups, baseline] = await Promise.all([controlApi.session(token), controlApi.groups(token), controlApi.policies(token)]);
  const selected = groups.find((group) => group.id === selectedId);
  const baselineSnapshots = baseline.map((policy) => previewSnapshot(policy, 'Baseline'));
  if (selectedId && !selected) return { session, groups, snapshots: [] };
  if (!selected) return { session, groups, reference: baselineSnapshots[0], snapshots: baselineSnapshots };
  const inherited = baselineSnapshots.map((snapshot) => ({ ...snapshot, promptExceptions: [] }));
  const history = await controlApi.policies(token, selected.id);
  const scoped = history.map((policy) => previewSnapshot(policy, selected.name));
  return { session, groups, selected, reference: scoped[0] ?? inherited[0], snapshots: [...scoped, ...inherited] };
}
