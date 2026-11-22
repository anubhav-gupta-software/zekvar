import { signOut } from './actions';
import { canChangePolicy, canWrite, roleLabels, type ControlSession } from '../lib/access';

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
  active?: 'audit' | 'retention' | 'groups' | 'preview' | 'access' | 'reviews' | 'extensions' | 'enrollment'; session?: ControlSession;
}) {
  const root = active ? '/' : '';
  const writable = canWrite(session);
  return <aside className="sidebar">
    <Brand />
    <nav aria-label="Dashboard sections">
      <a href={`${root}#overview`}>Overview</a>
      <a href={`${root}#${writable ? 'policies' : 'policy-history'}`}>Policies</a>
      <a href="/preview" aria-current={active === 'preview' ? 'page' : undefined}>Policy preview</a>
      <a href="/reviews" aria-current={active === 'reviews' ? 'page' : undefined}>Policy reviews</a>
      <a href="/groups" aria-current={active === 'groups' ? 'page' : undefined}>Rollout groups</a>
      {canChangePolicy(session) && <a href={`${root}#domain-rules`}>Navigation rules</a>}
      <a href={`${root}#ai-apps`}>App inventory</a>
      <a href={`${root}#browsers`}>Browsers</a>
      <a href="/enrollment" aria-current={active === 'enrollment' ? 'page' : undefined}>Enrollment batches</a>
      <a href="/extensions" aria-current={active === 'extensions' ? 'page' : undefined}>Browser extensions</a>
      <a href={`${root}#events`}>Events</a>
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
