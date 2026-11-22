import { redirect } from 'next/navigation';
import { ApiError, controlApi } from '../../lib/api';
import { canChangePolicy, canWrite } from '../../lib/access';
import type { Installation, PolicyGroup } from '../../lib/control';
import { sessionToken } from '../../lib/session';
import { assignPolicyGroup, createPolicyGroup, promotePolicyGroup } from '../actions';
import { DomainRulesForm, MutationForm } from '../forms';
import { PolicyVersionTable, PublishPolicyForm } from '../policies';
import { DeploymentBadge, Sidebar } from '../workspace';

export default async function Groups({ searchParams }: { searchParams: Promise<{ group?: string | string[] }> }) {
  const token = await sessionToken();
  if (!token) redirect('/');
  const { group: selectedId } = await searchParams;
  const result = await loadGroups(token, selectedId).catch((error) => {
    if (error instanceof ApiError && error.status === 401) redirect('/');
    if (error instanceof ApiError) return undefined;
    throw error;
  });
  const writable = canWrite(result?.session);
  const policyWritable = canChangePolicy(result?.session);
  const review = result?.session.reviewRequired ?? false;
  return <div className="workspace">
    <Sidebar active="groups" session={result?.session} />
    <main className="dashboard">
      <header className="page-heading">
        <div>{result && <p className="eyebrow">{result.session.organization}</p>}<h1>Rollout groups</h1></div>
        <DeploymentBadge />
      </header>
      {result ? <>
        <section className="panel" aria-labelledby="groups-heading">
          <div className="panel-heading"><h2 id="groups-heading">Policy groups</h2></div>
          <p className="muted">A new group follows the organization baseline until you publish a policy for it.</p>
          {result.groups.length > 0 && <nav className="form-row group-menu" aria-label="Policy groups">
            {result.groups.map((group) => <a className={`button small ${result.selected?.id === group.id ? 'primary' : ''}`}
              key={group.id} aria-current={result.selected?.id === group.id ? 'page' : undefined} href={`/groups?group=${group.id}`}>
              {group.name}<span className="group-count">{group.browsers}</span>
            </a>)}
          </nav>}
          {writable && <MutationForm action={createPolicyGroup} label="Create group" appearance="small">
            <div className="grid gap-1">
              <label htmlFor="group-name">Group name</label>
              <input id="group-name" name="name" required minLength={2} maxLength={64} />
            </div>
          </MutationForm>}
        </section>
        {!result.selected && selectedId !== undefined && <section className="panel" role="alert">This rollout group is unavailable. Choose a group from the list.</section>}
        {result.selected && <div key={result.selected.id}>
          <div className="controls-grid">
            <section className="panel" aria-labelledby="group-settings-heading">
              <div className="panel-heading"><h2 id="group-settings-heading">{result.selected.name}</h2>
                <span className="badge">{result.selected.publishedVersion ? 'Group policy' : 'Follows baseline'} · v{result.selected.effectiveVersion}</span></div>
              {policyWritable && <><p className="muted">Manage policy for the browsers assigned to this group.</p>
                <PublishPolicyForm policy={result.current} groupId={result.selected.id} review={review} /></>}
              <div className="form-row mt-3">
                <a className="button small" href={`/preview?group=${result.selected.id}`}>Preview group policy</a>
                <a className="button small" href={`/?rolloutGroup=${result.selected.id}#browsers`}>Review browser rollout</a>
              </div>
            </section>
            {policyWritable && <section className="panel" aria-labelledby="promotion-heading">
              <h2 id="promotion-heading">Promote to organization baseline</h2>
              <p className="muted">{result.history[0] ? `Publish reviewed group version v${result.history[0].version} as a new baseline version.` :
                'Publish a group policy before promoting it.'}</p>
              {result.history[0] && <MutationForm action={promotePolicyGroup} label={review ? 'Request promotion review' : 'Promote group policy'}
                confirmation={review ? `Request promotion of group version v${result.history[0].version}?` :
                  `Publish group version v${result.history[0].version} as the organization baseline?`}>
                <input type="hidden" name="groupId" value={result.selected.id} />
                <input type="hidden" name="expectedVersion" value={result.history[0].version} />
                {review && <input type="hidden" name="expectReview" value="on" />}
              </MutationForm>}
            </section>}
          </div>
          {policyWritable && <section className="panel" aria-labelledby="group-domains-heading">
            <h2 id="group-domains-heading">Group navigation rules</h2>
            <DomainRulesForm rules={result.current?.domainRules} paths={result.current?.pathRules}
              version={result.current?.version} groupId={result.selected.id} review={review} />
          </section>}
          <PolicyVersionTable policies={result.history} groupId={result.selected.id} writable={policyWritable} review={review} />
        </div>}
        {result.groups.length > 0 && <section className="panel table-panel" aria-labelledby="assignments-heading">
          <div className="panel-heading"><h2 id="assignments-heading">Browser assignments</h2><span className="table-note">Recent active installations</span></div>
          <div className="table-scroll" tabIndex={0} role="region" aria-labelledby="assignments-heading">
            <table aria-labelledby="assignments-heading">
              <thead><tr><th>Installation</th><th>Assigned group</th><th>Expected policy</th><th>Assignment</th></tr></thead>
              <tbody>{result.installations.filter((installation) => !installation.revokedAt).map((installation) =>
                <AssignmentRow key={installation.installationId} installation={installation} groups={result.groups} writable={writable} />)}</tbody>
            </table>
          </div>
        </section>}
      </> : <section className="panel" role="alert">Control could not load rollout groups. Try reloading this page.</section>}
    </main>
  </div>;
}

async function loadGroups(token: string, selectedId: string | string[] | undefined) {
  const [session, groups, baseline, installations] = await Promise.all([
    controlApi.session(token), controlApi.groups(token), controlApi.policies(token), controlApi.installations(token),
  ]);
  const selected = selectedId === undefined ? groups[0] : groups.find((group) => group.id === selectedId);
  const history = selected ? await controlApi.policies(token, selected.id) : [];
  return { session, groups, selected, installations, history, current: history[0] ?? baseline[0] };
}

function AssignmentRow({ installation, groups, writable }: { installation: Installation; groups: PolicyGroup[]; writable: boolean }) {
  const shortId = installation.installationId.slice(0, 13);
  return <tr>
    <td><code title={installation.installationId}>{shortId}</code></td>
    <td>{installation.policyGroupName ?? 'Organization baseline'}</td>
    <td>v{installation.expectedPolicyVersion}</td>
    <td>{writable && (installation.assignmentAware ?
      <MutationForm action={assignPolicyGroup} label="Save" appearance="small" accessibleLabel={`Save assignment for ${shortId}`}>
        <input type="hidden" name="installationId" value={installation.installationId} />
        <select name="groupId" key={installation.policyGroupId ?? 'baseline'} defaultValue={installation.policyGroupId ?? ''}
          aria-label={`Assignment for ${shortId}`}>
          <option value="">Organization baseline</option>
          {groups.map((group) => <option key={group.id} value={group.id}>{group.name}</option>)}
        </select>
      </MutationForm> : <span className="muted">Requires Browser v0.8.0 and a sync</span>)}
    </td>
  </tr>;
}
