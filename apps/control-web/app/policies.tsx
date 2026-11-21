import { aiPromptApps, decisionLabels, detectorModeLabels, detectorModes, modes, promptAppLabels, utc, type Policy } from '../lib/control';
import { uploadModes } from '../../../contracts/policy/uploads';
import { publishPolicy, restorePolicy } from './actions';
import { MutationForm } from './forms';

export function PublishPolicyForm({ policy, groupId }: { policy?: Policy; groupId?: string }) {
  return <MutationForm action={publishPolicy} label={groupId ? 'Publish group policy' : 'Publish policy'} appearance="primary">
    {groupId && <input type="hidden" name="groupId" value={groupId} />}
    <div className="grid gap-1">
      <label htmlFor="publish-mode">Test marker</label>
      <select key={policy?.version} id="publish-mode" name="mode" defaultValue={policy?.mode ?? 'monitor'}>
        {modes.map((mode) => <option key={mode} value={mode}>{decisionLabels[mode]}</option>)}
      </select>
    </div>
    <div className="grid gap-1">
      <label htmlFor="github-pat-mode">GitHub classic PAT</label>
      <select key={policy?.version} id="github-pat-mode" name="githubPatMode" defaultValue={policy?.githubPatMode ?? 'off'}>
        {detectorModes.map((mode) => <option key={mode} value={mode}>{detectorModeLabels[mode]}</option>)}
      </select>
    </div>
    <div className="grid gap-1">
      <label htmlFor="payment-card-mode">Payment card number</label>
      <select key={policy?.version} id="payment-card-mode" name="paymentCardMode" defaultValue={policy?.paymentCardMode ?? 'off'}>
        {detectorModes.map((mode) => <option key={mode} value={mode}>{detectorModeLabels[mode]}</option>)}
      </select>
    </div>
    <div className="grid gap-1">
      <label htmlFor="discovery-mode">AI app discovery</label>
      <select key={policy?.version} id="discovery-mode" name="discoveryEnabled" defaultValue={policy?.discoveryEnabled ? 'on' : 'off'}>
        <option value="off">Off</option><option value="on">On</option>
      </select>
    </div>
    {aiPromptApps.map((app) => <div className="grid gap-1" key={app}>
      <label htmlFor={`upload-${app}`}>{promptAppLabels[app]} file uploads</label>
      <select key={policy?.version} id={`upload-${app}`} name={`upload-${app}`} defaultValue={policy?.uploadModes?.[app] ?? 'off'}>
        {uploadModes.map((mode) => <option key={mode} value={mode}>{detectorModeLabels[mode]}</option>)}
      </select>
    </div>)}
  </MutationForm>;
}

export function PolicyVersionTable({ policies, groupId }: { policies: Policy[]; groupId?: string }) {
  return <section className="panel table-panel" aria-labelledby="history-heading">
    <div className="panel-heading"><h2 id="history-heading">{groupId ? 'Group policy history' : 'Policy history'}</h2>
      <span className="table-note">Latest 100 versions</span></div>
    <div className="table-scroll" tabIndex={0} role="region" aria-labelledby="history-heading">
      <table aria-labelledby="history-heading">
        <thead><tr><th>Version</th><th>Test marker</th><th>GitHub classic PAT</th><th>Payment card number</th><th>AI app discovery</th>
          <th>File uploads</th><th>Domain rules</th><th>Published (UTC)</th><th>Restore source</th><th>Action</th></tr></thead>
        <tbody>{policies.map((policy, index) => <PolicyRow key={policy.version} policy={policy} current={index === 0} groupId={groupId} />)}</tbody>
      </table>
      {policies.length === 0 && <p className="empty">Publish a policy to start the version history.</p>}
    </div>
  </section>;
}

function PolicyRow({ policy, current, groupId }: { policy: Policy; current: boolean; groupId?: string }) {
  const { allow = [], block = [] } = policy.domainRules ?? {};
  return <tr>
    <td className="emphasis">v{policy.version}</td><td><span className={`badge decision ${policy.mode}`}>{decisionLabels[policy.mode]}</span></td>
    <td>{detectorModeLabels[policy.githubPatMode ?? 'off']}</td>
    <td>{detectorModeLabels[policy.paymentCardMode ?? 'off']}</td>
    <td>{policy.discoveryEnabled ? 'On' : 'Off'}</td>
    <td>{aiPromptApps.map((app) => <div key={app}>{promptAppLabels[app]} · {detectorModeLabels[policy.uploadModes?.[app] ?? 'off']}</div>)}</td>
    <td>{allow.length || block.length ? <details className="domain-rule-history">
      <summary>{allow.length} allow · {block.length} block</summary>
      {allow.length > 0 && <p>Allow <code>{allow.join(', ')}</code></p>}
      {block.length > 0 && <p>Block <code>{block.join(', ')}</code></p>}
    </details> : '—'}</td>
    <td><time dateTime={policy.publishedAt}>{utc.format(new Date(policy.publishedAt))}</time></td>
    <td>{policy.restoredFrom ? `v${policy.restoredFrom}` : '—'}</td>
    <td>{current ? <span className="badge current">Current</span> :
      <MutationForm action={restorePolicy} label="Restore" appearance="small" accessibleLabel={`Restore version ${policy.version}`}>
        <input type="hidden" name="version" value={policy.version} />
        {groupId && <input type="hidden" name="groupId" value={groupId} />}
      </MutationForm>}
    </td>
  </tr>;
}
