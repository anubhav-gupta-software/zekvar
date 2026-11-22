import { decisionLabels, detectorModeLabels, detectorModes, modes, promptAppLabels, ruleLabels, utc, type Policy } from '../lib/control';
import { uploadApps, uploadModes, uploadTypesHint } from '../../../contracts/policy/uploads';
import { exceptionKey } from '../../../contracts/policy/prompt-exceptions';
import { fixtureRule } from '../../../contracts/policy/prompt';
import { publishPolicy, restorePolicy } from './actions';
import { MutationForm } from './forms';

export function PublishPolicyForm({ policy, groupId, review }: { policy?: Policy; groupId?: string; review: boolean }) {
  return <MutationForm action={publishPolicy}
    label={review ? 'Request policy review' : groupId ? 'Publish group policy' : 'Publish policy'} appearance="primary">
    {groupId && <input type="hidden" name="groupId" value={groupId} />}
    {review && <input type="hidden" name="expectReview" value="on" />}
    <input type="hidden" name="expectedVersion" value={policy?.version ?? ''} />
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
    {policy?.privateKeyMode !== undefined && <div className="grid gap-1">
      <label htmlFor="private-key-mode">Private key</label>
      <select key={policy.version} id="private-key-mode" name="privateKeyMode" defaultValue={policy.privateKeyMode}>
        {detectorModes.map((mode) => <option key={mode} value={mode}>{detectorModeLabels[mode]}</option>)}
      </select>
    </div>}
    <div className="grid gap-1">
      <label htmlFor="discovery-mode">App discovery</label>
      <select key={policy?.version} id="discovery-mode" name="discoveryEnabled" defaultValue={policy?.discoveryEnabled ? 'on' : 'off'}>
        <option value="off">Off</option><option value="on">On</option>
      </select>
    </div>
    <div className="grid gap-1">
      <label htmlFor="extension-inventory-mode">Extension inventory</label>
      <select key={policy?.version} id="extension-inventory-mode" name="extensionInventoryEnabled"
        defaultValue={policy?.extensionInventoryEnabled ? 'on' : 'off'}>
        <option value="off">Off</option><option value="on">On</option>
      </select>
    </div>
    <div className="grid gap-1">
      <label htmlFor="claude-prompt-mode">Claude prompt protection</label>
      <select key={policy?.version} id="claude-prompt-mode" name="claudePromptEnabled"
        defaultValue={policy?.claudePromptEnabled ? 'on' : 'off'}>
        <option value="off">Off</option><option value="on">On · experimental</option>
      </select>
    </div>
    {uploadApps.map((app) => <div className="grid gap-1" key={app}>
      <label htmlFor={`upload-${app}`}>{promptAppLabels[app]} file uploads</label>
      <select key={policy?.version} id={`upload-${app}`} name={`upload-${app}`} defaultValue={policy?.uploadModes?.[app] ?? 'off'}>
        {uploadModes.map((mode) => <option key={mode} value={mode}>{detectorModeLabels[mode]}</option>)}
      </select>
      <label htmlFor={`upload-types-${app}`}>{promptAppLabels[app]} file types</label>
      <textarea key={`types-${policy?.version}`} id={`upload-types-${app}`} name={`upload-types-${app}`}
        rows={2} maxLength={1700} spellCheck={false} autoCapitalize="none" autoComplete="off"
        aria-describedby="upload-types-hint" defaultValue={policy?.uploadTypes?.[app]?.join(', ') ?? ''} />
    </div>)}
    <p className="muted" id="upload-types-hint">{uploadTypesHint}</p>
  </MutationForm>;
}

export function PolicyVersionTable({ policies, groupId, writable, review }: {
  policies: Policy[]; groupId?: string; writable: boolean; review: boolean;
}) {
  return <section className="panel table-panel" id="policy-history" aria-labelledby="history-heading">
    <div className="panel-heading"><h2 id="history-heading">{groupId ? 'Group policy history' : 'Policy history'}</h2>
      <span className="table-note">Latest 100 versions</span></div>
    <div className="table-scroll" tabIndex={0} role="region" aria-labelledby="history-heading">
      <table aria-labelledby="history-heading">
        <thead><tr><th>Version</th><th>Test marker</th><th>GitHub classic PAT</th><th>Payment card number</th><th>Private key</th><th>App discovery</th>
          <th>Extension inventory</th><th>Claude prompt protection</th><th>File uploads</th><th>Navigation rules</th><th>Published (UTC)</th><th>Restore source</th>
          <th>Prompt exceptions</th><th>Action</th></tr></thead>
        <tbody>{policies.map((policy, index) => <PolicyRow key={policy.version} policy={policy} current={index === 0}
          groupId={groupId} writable={writable} review={review} />)}</tbody>
      </table>
      {policies.length === 0 && <p className="empty">No policy versions have been published in this scope.</p>}
    </div>
  </section>;
}

function PolicyRow({ policy, current, groupId, writable, review }: {
  policy: Policy; current: boolean; groupId?: string; writable: boolean; review: boolean;
}) {
  const { allow = [], block = [] } = policy.domainRules ?? {};
  const { allow: allowPaths = [], block: blockPaths = [] } = policy.pathRules ?? {};
  return <tr>
    <td className="emphasis">v{policy.version}</td><td><span className={`badge decision ${policy.mode}`}>{decisionLabels[policy.mode]}</span></td>
    <td>{detectorModeLabels[policy.githubPatMode ?? 'off']}</td>
    <td>{detectorModeLabels[policy.paymentCardMode ?? 'off']}</td>
    <td>{detectorModeLabels[policy.privateKeyMode ?? 'off']}</td>
    <td>{policy.discoveryEnabled ? 'On' : 'Off'}
      {!!policy.customApps?.length && <details className="domain-rule-history">
        <summary>{policy.customApps.length} custom {policy.customApps.length === 1 ? 'site' : 'sites'}</summary>
        {policy.customApps.map(({ id, host, name }) => <p key={id}>{name} · <code>{host}</code></p>)}
      </details>}</td>
    <td>{policy.extensionInventoryEnabled ? 'On' : 'Off'}</td>
    <td>{policy.claudePromptEnabled ? 'On' : 'Off'}</td>
    <td>{uploadApps.map((app) => {
      const types = policy.uploadTypes?.[app] ?? [];
      return <div key={app}>{promptAppLabels[app]} · {detectorModeLabels[policy.uploadModes?.[app] ?? 'off']}
        {types.length > 0 && <details className="domain-rule-history"><summary>{types.length} selected types</summary>
          <code>{types.join(', ')}</code></details>}
      </div>;
    })}</td>
    <td>
      {allow.length + block.length + allowPaths.length + blockPaths.length === 0 && '—'}
      <NavigationHistory allow={allow} block={block} label="domains" />
      <NavigationHistory allow={allowPaths} block={blockPaths} label="paths" />
    </td>
    <td><time dateTime={policy.publishedAt}>{utc.format(new Date(policy.publishedAt))}</time></td>
    <td>{policy.restoredFrom ? `v${policy.restoredFrom}` : '—'}</td>
    <td>{policy.promptExceptions?.length ? <details className="domain-rule-history">
      <summary>{policy.promptExceptions.length} configured</summary>
      {policy.promptExceptions.map((entry) => <p key={exceptionKey(entry)}>
        {promptAppLabels[entry.appId]} · {entry.ruleId === fixtureRule ? 'Test marker' : ruleLabels[entry.ruleId]}<br />
        Expires <time dateTime={entry.expiresAt}>{utc.format(new Date(entry.expiresAt))}</time> UTC<br />{entry.reason}
      </p>)}</details> : '—'}</td>
    <td>{current && <span className="badge current">Current</span>}
      {!current && !writable && '—'}
      {!current && writable && <MutationForm action={restorePolicy} label={review ? 'Request restore' : 'Restore'} appearance="small"
        accessibleLabel={`${review ? 'Request restore of' : 'Restore'} version ${policy.version}`}>
        <input type="hidden" name="version" value={policy.version} />
        {groupId && <input type="hidden" name="groupId" value={groupId} />}
        {review && <input type="hidden" name="expectReview" value="on" />}
      </MutationForm>}
    </td>
  </tr>;
}

function NavigationHistory({ allow, block, label }: { allow: string[]; block: string[]; label: string }) {
  if (!allow.length && !block.length) return null;
  return <details className="domain-rule-history">
    <summary>{allow.length} allow · {block.length} block {label}</summary>
    {allow.length > 0 && <p>Allow <code>{allow.join(', ')}</code></p>}
    {block.length > 0 && <p>Block <code>{block.join(', ')}</code></p>}
  </details>;
}
