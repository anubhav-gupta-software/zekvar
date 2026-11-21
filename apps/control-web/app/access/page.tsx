import { redirect } from 'next/navigation';
import { ApiError, controlApi } from '../../lib/api';
import { roleLabels, type ControlAccess } from '../../lib/access';
import { utc } from '../../lib/control';
import { sessionToken } from '../../lib/session';
import { revokeControlAccess } from '../actions';
import { MutationForm, RefreshSection } from '../forms';
import { Sidebar } from '../workspace';
import { IssueAccessForm } from './issue-form';

export default async function AccessPage() {
  const token = await sessionToken();
  if (!token) redirect('/');
  const result = await loadAccess(token).catch((error) => {
    if (error instanceof ApiError && error.status === 401) redirect('/');
    if (error instanceof ApiError) return undefined;
    throw error;
  });
  const credentials = result?.credentials;
  return <div className="workspace">
    <Sidebar active="access" session={result?.session} />
    <main className="dashboard">
      <header className="page-heading">
        <div>{result && <p className="eyebrow">{result.session.organization}</p>}<h1>Control access</h1></div>
        <span className="badge local"><span aria-hidden="true" />Local demo</span>
      </header>
      {credentials ? <>
        <section className="panel" aria-labelledby="issue-heading">
          <h2 id="issue-heading">Issue a named token</h2>
          <p className="muted">Administrators manage policies, enrollment, and retention. Auditors can review and export records.</p>
          <IssueAccessForm activeIds={credentials.filter(({ status }) => status === 'active').map(({ id }) => id)} />
        </section>
        <section className="panel table-panel" aria-labelledby="access-heading">
          <div className="panel-heading"><h2 id="access-heading">Delegated credentials</h2><RefreshSection label="Refresh credentials" /></div>
          <div className="table-scroll" role="region" tabIndex={0} aria-labelledby="access-heading">
            <table aria-labelledby="access-heading">
              <thead><tr><th>Name</th><th>Credential ID</th><th>Role</th><th>Status</th><th>Issued (UTC)</th><th>Expires (UTC)</th><th>Action</th></tr></thead>
              <tbody>{credentials.map((credential) => <CredentialRow key={credential.id} credential={credential} />)}</tbody>
            </table>
          </div>
          {credentials.length === 0 && <p className="empty">No delegated credentials have been issued.</p>}
        </section>
      </> : <section className="panel" role="alert">{result ? 'Only the organization owner can manage Control access.' :
        'Control could not load credentials. Try reloading this page.'}</section>}
    </main>
  </div>;
}

async function loadAccess(token: string) {
  const session = await controlApi.session(token);
  const credentials = session.role === 'owner' ? await controlApi.access(token) : undefined;
  return { session, credentials };
}

const statuses = { active: 'Active', expired: 'Expired', revoked: 'Revoked' };

function CredentialRow({ credential }: { credential: ControlAccess }) {
  return <tr>
    <th scope="row" className="emphasis">{credential.name}</th>
    <td><code title={credential.id}>{credential.id.slice(0, 13)}</code></td>
    <td>{roleLabels[credential.role]}</td>
    <td><span className={`badge ${credential.status === 'active' ? 'current' : ''}`}>{statuses[credential.status]}</span></td>
    <td><time dateTime={credential.issuedAt}>{utc.format(new Date(credential.issuedAt))}</time></td>
    <td><time dateTime={credential.expiresAt}>{utc.format(new Date(credential.expiresAt))}</time></td>
    <td>{credential.status === 'active' ? <MutationForm action={revokeControlAccess} label="Revoke" appearance="small danger"
      accessibleLabel={`Revoke token for ${credential.name}`}
      confirmation={`Revoke the token for ${credential.name} (${credential.id.slice(0, 13)})?`}>
      <input type="hidden" name="id" value={credential.id} />
    </MutationForm> : '—'}</td>
  </tr>;
}
