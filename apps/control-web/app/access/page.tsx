import { redirect } from 'next/navigation';
import { ApiError, controlApi } from '../../lib/api';
import { roleLabels, type ControlAccess } from '../../lib/access';
import { utc } from '../../lib/control';
import { sessionToken } from '../../lib/session';
import { addSsoIdentity, revokeControlAccess } from '../actions';
import { MutationForm, RefreshSection } from '../forms';
import { DeploymentBadge, Sidebar } from '../workspace';
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
        <DeploymentBadge />
      </header>
      {credentials ? <>
        <section className="panel" aria-labelledby="issue-heading">
          <h2 id="issue-heading">Issue a named token</h2>
          <p className="muted">Administrators manage policies, enrollment, and retention. Auditors can review and export records.</p>
          <IssueAccessForm activeIds={credentials.filter(({ status }) => status === 'active').map(({ id }) => id)} />
        </section>
        {result?.sso && <section className="panel" aria-labelledby="sso-heading">
          <h2 id="sso-heading">Single sign-on access</h2>
          <p className="muted">Use the exact OIDC subject for the account in this application’s identity provider. Issuer <code>{result.sso.issuer}</code></p>
          <MutationForm action={addSsoIdentity} label="Add SSO identity" appearance="primary">
            <div className="grid gap-1">
              <label htmlFor="sso-name">SSO name</label>
              <input id="sso-name" name="name" required minLength={2} maxLength={64} />
            </div>
            <div className="grid gap-1">
              <label htmlFor="sso-subject">OIDC subject</label>
              <input id="sso-subject" name="subject" required maxLength={255} autoComplete="off" spellCheck={false} />
            </div>
            <div className="grid gap-1">
              <label htmlFor="sso-role">SSO role</label>
              <select id="sso-role" name="role"><option value="auditor">Auditor</option><option value="administrator">Administrator</option></select>
            </div>
          </MutationForm>
        </section>}
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
  const sso = session.role === 'owner' ? await controlApi.ssoSettings(token) : undefined;
  return { session, credentials, sso };
}

const statuses = { active: 'Active', expired: 'Expired', revoked: 'Revoked' };

function CredentialRow({ credential }: { credential: ControlAccess }) {
  const sso = credential.subject !== undefined;
  return <tr>
    <th scope="row" className="emphasis">{credential.name}{sso && <div className="muted">Single sign-on <code>{credential.subject}</code></div>}</th>
    <td><code title={credential.id}>{credential.id.slice(0, 13)}</code></td>
    <td>{roleLabels[credential.role]}</td>
    <td><span className={`badge ${credential.status === 'active' ? 'current' : ''}`}>{statuses[credential.status]}</span></td>
    <td><time dateTime={credential.issuedAt}>{utc.format(new Date(credential.issuedAt))}</time></td>
    <td>{credential.expiresAt ? <time dateTime={credential.expiresAt}>{utc.format(new Date(credential.expiresAt))}</time> : 'Until revoked'}</td>
    <td>{credential.status === 'active' ? <MutationForm action={revokeControlAccess} label="Revoke" appearance="small danger"
      accessibleLabel={`Revoke ${sso ? 'SSO access' : 'token'} for ${credential.name}`}
      confirmation={`Revoke ${sso ? 'SSO access' : 'the token'} for ${credential.name} (${credential.id.slice(0, 13)})?`}>
      <input type="hidden" name="id" value={credential.id} />
    </MutationForm> : '—'}</td>
  </tr>;
}
