import { randomUUID } from 'node:crypto';
import { redirect } from 'next/navigation';
import { ApiError, controlApi } from '../../lib/api';
import { canWrite } from '../../lib/access';
import { utc } from '../../lib/control';
import { keyAttention, keyStatusLabels, type EnrollmentKey } from '../../lib/enrollment-keys';
import { sessionToken } from '../../lib/session';
import { RefreshSection } from '../forms';
import { DeploymentBadge, Sidebar } from '../workspace';
import { CreateKeyForm, KeyActions, PolicySnippetBuilder, RotateKeyForm } from './key-forms';

export default async function EnrollmentKeys() {
  const token = await sessionToken();
  if (!token) redirect('/');
  const result = await Promise.all([controlApi.session(token), controlApi.groups(token), controlApi.enrollmentKeys(token)]).catch((error) => {
    if (error instanceof ApiError && error.status === 401) redirect('/');
    if (error instanceof ApiError) return undefined;
    throw error;
  });
  const [session, groups, keys] = result ?? [];
  const writable = canWrite(session);
  const flagged = keys?.filter((key) => keyAttention(key)) ?? [];
  const rotatable = keys?.filter(({ status }) => status === 'active' || status === 'exhausted') ?? [];
  return <div className="workspace">
    <Sidebar active="enrollment-keys" session={session} />
    <main className="dashboard">
      <header className="page-heading">
        <div>{session && <p className="eyebrow">{session.organization}</p>}<h1>Enrollment keys</h1></div>
        <DeploymentBadge />
      </header>
      <section className="panel" aria-labelledby="keys-about-heading">
        <h2 id="keys-about-heading">Enroll a device group with one key</h2>
        <p className="muted">Push one key to a Google Admin organizational unit, Intune device group, or Jamf scope through the
          extension&apos;s managed storage. Each Chrome profile redeems it once for its own credential and joins the key&apos;s rollout group.
          The key can only enroll browsers. Anyone who holds it can enroll a browser into your organization until it expires, reaches its
          limit, or is revoked, so keep a limit close to the device count. Requires Browser v0.43.0 or later.</p>
      </section>
      {flagged.length > 0 && <section className="panel" role="status" aria-labelledby="keys-attention-heading">
        <h2 id="keys-attention-heading">Review key redemptions</h2>
        <ul className="preview-changes">{flagged.map((key) => <li key={key.id}>
          <strong>{key.label}</strong> · {keyAttention(key)} · {key.redeemed} redeemed.{' '}
          <a className="underline" href={`/fleet?enrollmentKey=${key.id}`}>Review its browsers</a>
        </li>)}</ul>
        <p className="muted">If a key leaked, revoke it, rotate a replacement to your device manager, and revoke the browsers it enrolled from the fleet view.</p>
      </section>}
      {groups && writable && <section className="panel" aria-labelledby="create-key-heading">
        <h2 id="create-key-heading">Create an enrollment key</h2>
        <CreateKeyForm groups={groups} requestId={randomUUID()} />
      </section>}
      {writable && rotatable.length > 0 && <section className="panel" aria-labelledby="rotate-key-heading">
        <h2 id="rotate-key-heading">Rotate a key</h2>
        <RotateKeyForm keys={rotatable.map(({ id, label }) => ({ id, label }))} requestId={randomUUID()} />
      </section>}
      <section className="panel table-panel" aria-labelledby="keys-heading">
        <div className="panel-heading"><h2 id="keys-heading">Keys</h2><RefreshSection label="Refresh enrollment keys" /></div>
        {keys ? <>
          <div className="table-scroll" tabIndex={0} role="region" aria-labelledby="keys-heading">
            <table aria-labelledby="keys-heading">
              <thead><tr><th scope="col">Key</th><th scope="col">Rollout group</th><th scope="col">Status</th><th scope="col">Redemptions</th>
                <th scope="col">Last redemption (UTC)</th><th scope="col">Rejected</th><th scope="col">Expires (UTC)</th><th scope="col">Browsers</th>
                {writable && <th scope="col">Actions</th>}</tr></thead>
              <tbody>{keys.map((key) => <KeyRow key={key.id} entry={key} writable={writable} />)}</tbody>
            </table>
          </div>
          {keys.length === 0 && <p className="empty">No enrollment keys yet.</p>}
        </> : <p className="empty" role="alert">Control could not load enrollment keys. Try refreshing this page.</p>}
      </section>
      <section className="panel" aria-labelledby="snippet-heading">
        <h2 id="snippet-heading">Managed policy snippets</h2>
        <p className="muted">Build the device manager policy from a key. The snippets are generated in this browser and are not sent to Control.</p>
        <PolicySnippetBuilder idPrefix="builder" />
      </section>
    </main>
  </div>;
}

function KeyRow({ entry, writable }: { entry: EnrollmentKey; writable: boolean }) {
  const short = entry.id.slice(0, 13);
  return <tr>
    <th scope="row"><span className="emphasis">{entry.label}</span><div className="muted"><code title={entry.id}>{short}</code>
      {entry.rotatedFrom && <> · rotated from <code title={entry.rotatedFrom}>{entry.rotatedFrom.slice(0, 13)}</code></>}</div></th>
    <td>{entry.groupName ?? 'Organization baseline'}</td>
    <td>{keyStatusLabels[entry.status]}{keyAttention(entry) && <div className="muted">{keyAttention(entry)}</div>}</td>
    <td>{entry.redeemed} of {entry.maxRedemptions ?? 'no limit'}</td>
    <td>{entry.lastRedeemedAt ? <time dateTime={entry.lastRedeemedAt}>{utc.format(new Date(entry.lastRedeemedAt))}</time> : 'Never'}</td>
    <td>{entry.rejected}</td>
    <td><time dateTime={entry.expiresAt}>{utc.format(new Date(entry.expiresAt))}</time></td>
    <td><a className="underline" href={`/fleet?enrollmentKey=${entry.id}`} aria-label={`Review ${entry.activeInstallations} active browsers enrolled by ${entry.label}`}>
      {entry.activeInstallations} active</a></td>
    {writable && <td>{entry.status === 'active' || entry.status === 'exhausted' ? <KeyActions id={entry.id} label={entry.label} /> : '—'}</td>}
  </tr>;
}
