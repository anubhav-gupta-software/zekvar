import { signOut } from './actions';
import { canChangePolicy, canWrite, roleLabels, type ControlSession } from '../lib/access';
import type { PolicyGroup } from '../lib/control';

export function RecordedRolloutOptions({ groups, selected }: { groups: PolicyGroup[]; selected: string }) {
  return <>
    <option value="">All rollout groups</option>
    <option value="baseline">Organization baseline</option>
    <option value="unattributed">Unattributed</option>
    {groups.map((group) => <option key={group.id} value={group.id}>{group.name}</option>)}
    {selected && !['baseline', 'unattributed'].includes(selected) && !groups.some(({ id }) => id === selected) &&
      <option value={selected}>Unavailable rollout group</option>}
  </>;
}

export function Brand() {
  return <div className="brand"><span className="brand-mark" aria-hidden="true">Z</span>
    <span><strong>ZEKVAR</strong><span>CONTROL</span></span>
  </div>;
}

export function DeploymentBadge() {
  return <span className="badge local"><span aria-hidden="true" />
    {process.env.ZEKVAR_HOSTED_PILOT === '1' ? 'Hosted pilot' : 'Local demo'}
  </span>;
}

export function Sidebar({ active, session }: {
  active?: 'audit' | 'retention' | 'groups' | 'preview' | 'access' | 'reviews' | 'extensions' | 'enrollment' | 'reports' | 'events' | 'cases' | 'alerts' | 'hardening' | 'fleet' | 'templates';
  session?: ControlSession;
}) {
  const root = active ? '/' : '';
  const writable = canWrite(session);
  return <aside className="sidebar">
    <Brand />
    <nav aria-label="Dashboard sections">
      <a href={`${root}#overview`}>Overview</a>
      <a href={`${root}#${writable ? 'policies' : 'policy-history'}`}>Policies</a>
      <a href="/preview" aria-current={active === 'preview' ? 'page' : undefined}>Policy preview</a>
      <a href="/templates" aria-current={active === 'templates' ? 'page' : undefined}>Policy templates</a>
      <a href="/reviews" aria-current={active === 'reviews' ? 'page' : undefined}>Policy reviews</a>
      <a href="/groups" aria-current={active === 'groups' ? 'page' : undefined}>Rollout groups</a>
      {canChangePolicy(session) && <a href={`${root}#domain-rules`}>Navigation rules</a>}
      <a href={`${root}#ai-apps`}>App inventory</a>
      <a href={`${root}#browsers`}>Browsers</a>
      <a href="/fleet" aria-current={active === 'fleet' ? 'page' : undefined}>Browser fleet</a>
      <a href="/enrollment" aria-current={active === 'enrollment' ? 'page' : undefined}>Enrollment batches</a>
      <a href="/extensions" aria-current={active === 'extensions' ? 'page' : undefined}>Browser extensions</a>
      <a href="/hardening" aria-current={active === 'hardening' ? 'page' : undefined}>Chrome hardening</a>
      <a href={`${root}#events`} aria-current={active === 'events' ? 'page' : undefined}>Events</a>
      <a href="/alerts" aria-current={active === 'alerts' ? 'page' : undefined}>Alerts</a>
      <a href="/cases" aria-current={active === 'cases' ? 'page' : undefined}>Incident cases</a>
      <a href="/reports" aria-current={active === 'reports' ? 'page' : undefined}>Reports</a>
      <a href="/audit" aria-current={active === 'audit' ? 'page' : undefined}>Audit log</a>
      <a href="/retention" aria-current={active === 'retention' ? 'page' : undefined}>Data retention</a>
      {session?.role === 'owner' && <a href="/access" aria-current={active === 'access' ? 'page' : undefined}>Control access</a>}
    </nav>
    <div className="sidebar-footer">
      {session && <p className="table-note">{session.access ? `${session.access.name} · ` : ''}{roleLabels[session.role]}</p>}
      <form action={signOut}><button className="button small">Sign out</button></form>
    </div>
  </aside>;
}
