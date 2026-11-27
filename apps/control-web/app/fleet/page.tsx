import { redirect } from 'next/navigation';
import { canWrite, type ControlSession } from '../../lib/access';
import { ApiError, controlApi } from '../../lib/api';
import type { PolicyGroup } from '../../lib/control';
import type { FleetPage } from '../../lib/fleet';
import type { EnrollmentKey } from '../../lib/enrollment-keys';
import { sessionToken } from '../../lib/session';
import { RefreshSection } from '../forms';
import { DeploymentBadge, Sidebar } from '../workspace';
import { FleetEditor } from './fleet-editor';

type Search = Record<string, string | string[] | undefined>;
type FleetView = {
  session: ControlSession; groups: PolicyGroup[]; baselineVersion?: number; filters: URLSearchParams; fleet?: FleetPage; error?: string;
  enrollmentKey?: EnrollmentKey;
};

export default async function Fleet({ searchParams }: { searchParams: Promise<Search> }) {
  const token = await sessionToken();
  if (!token) redirect('/');
  const search = await searchParams;
  const data = await loadFleet(token, search).catch((error) => {
    if (error instanceof ApiError && error.status === 401) redirect('/');
    if (error instanceof ApiError) return undefined;
    throw error;
  });
  const next = data?.fleet?.next;
  const nextQuery = new URLSearchParams(data?.filters);
  if (next) {
    nextQuery.set('beforeAt', next.enrolledAt);
    nextQuery.set('beforeId', next.installationId);
  }
  const scope = new URLSearchParams();
  const group = data?.filters.get('rolloutGroup');
  if (group) scope.set('rolloutGroup', group);
  const keyId = data?.filters.get('enrollmentKey');
  if (keyId) scope.set('enrollmentKey', keyId);

  return <div className="workspace">
    <Sidebar active="fleet" session={data?.session} />
    <main className="dashboard">
      <header className="page-heading">
        <div>{data && <p className="eyebrow">{data.session.organization}</p>}<h1>Browser fleet</h1></div>
        <DeploymentBadge />
      </header>
      {data && <section className="panel" aria-labelledby="fleet-filter-heading">
        <div className="panel-heading"><h2 id="fleet-filter-heading">Filter browsers</h2><RefreshSection label="Refresh browser fleet" /></div>
        <form action="/fleet" method="get" className="form-row">
          <div className="grid gap-1">
            <label htmlFor="fleet-scope">Rollout group</label>
            <select id="fleet-scope" name="rolloutGroup" defaultValue={group ?? ''}>
              <option value="">All active browsers</option>
              <option value="baseline">Organization baseline</option>
              {data.groups.map(({ id, name }) => <option key={id} value={id}>{name}</option>)}
            </select>
          </div>
          {keyId && <input type="hidden" name="enrollmentKey" value={keyId} />}
          <button className="button">Filter fleet</button>
        </form>
        {keyId && <p className="feedback" role="status">Showing active browsers enrolled by key
          {' '}<strong>{data.enrollmentKey?.label ?? keyId.slice(0, 13)}</strong>.
          {' '}To contain a leaked key, select these browsers and revoke them, then revoke the key.
          {' '}<a className="underline" href={group ? `/fleet?rolloutGroup=${group}` : '/fleet'}>Show all browsers</a></p>}
      </section>}
      {data?.fleet ? <>
        <FleetEditor key={data.filters.toString()} entries={data.fleet.entries} writable={canWrite(data.session)}
          groups={data.groups} baselineVersion={data.baselineVersion} />
        {(next || data.filters.has('beforeId')) && <nav className="form-row" aria-label="Browser fleet pages">
          {data.filters.has('beforeId') && <a className="button small" href={scope.size ? `/fleet?${scope}` : '/fleet'}>Newest browsers</a>}
          {next && <a className="button small" href={`/fleet?${nextQuery}`}>Older browsers</a>}
        </nav>}
      </> : <section className="panel" role="alert">{data?.error ?? 'Control could not load the browser fleet. Try refreshing.'}</section>}
    </main>
  </div>;
}

async function loadFleet(token: string, search: Search): Promise<FleetView> {
  const [session, groups, baseline] = await Promise.all([controlApi.session(token), controlApi.groups(token), controlApi.policies(token)]);
  const filters = new URLSearchParams();
  const result = { session, groups, baselineVersion: baseline[0]?.version, filters };
  for (const key of ['rolloutGroup', 'beforeAt', 'beforeId', 'enrollmentKey']) {
    const value = search[key];
    if (Array.isArray(value)) return { ...result, error: 'Choose one rollout group and use a fleet page link.' };
    if (value) filters.set(key, value);
  }
  const keyId = filters.get('enrollmentKey');
  const enrollmentKey = keyId ? (await controlApi.enrollmentKeys(token)).find(({ id }) => id === keyId) : undefined;
  try { return { ...result, enrollmentKey, fleet: await controlApi.fleet(token, filters) }; }
  catch (error) {
    if (error instanceof ApiError && (error.status === 400 || error.status === 404)) {
      return { ...result, error: 'This rollout group, enrollment key, or fleet page is unavailable. Filter the fleet again.' };
    }
    throw error;
  }
}
