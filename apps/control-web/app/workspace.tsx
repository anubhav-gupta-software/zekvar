import { signOut } from './actions';

export function Brand() {
  return <div className="brand"><span className="brand-mark" aria-hidden="true">Z</span>
    <span><strong>ZEKVAR</strong><span>CONTROL</span></span>
  </div>;
}

export function Sidebar({ onAudit = false }: { onAudit?: boolean }) {
  const root = onAudit ? '/' : '';
  return <aside className="sidebar">
    <Brand />
    <nav aria-label="Dashboard sections">
      <a href={`${root}#overview`}>Overview</a>
      <a href={`${root}#policies`}>Policies</a>
      <a href={`${root}#domain-rules`}>Domain rules</a>
      <a href={`${root}#ai-apps`}>AI apps</a>
      <a href={`${root}#browsers`}>Browsers</a>
      <a href={`${root}#events`}>Events</a>
      <a href="/audit" aria-current={onAudit ? 'page' : undefined}>Audit log</a>
    </nav>
    <div className="sidebar-footer">
      <form action={signOut}><button className="button small">Sign out</button></form>
    </div>
  </aside>;
}
