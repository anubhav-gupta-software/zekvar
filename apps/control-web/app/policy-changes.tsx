import { decisionLabels, detectorModeLabels, promptAppLabels, ruleLabels, utc } from '../lib/control';
import { fileContentMode, uploadApps } from '../../../contracts/policy/uploads';
import type { PreviewPolicy } from '../lib/preview';
import { exceptionKey, samePromptExceptions } from '../../../contracts/policy/prompt-exceptions';
import { fixtureRule } from '../../../contracts/policy/prompt';
import { extensionDeploymentChanges, extensionModeLabels, unlistedLabels, type ExtensionDeployment, type ExtensionRule } from '../lib/extension-deployment';

export function ExtensionDeploymentChanges({ reference, candidate }: { reference?: ExtensionDeployment; candidate?: ExtensionDeployment }) {
  const before = reference?.unlisted ?? 'preserve';
  const after = candidate?.unlisted ?? 'preserve';
  const format = (rule?: ExtensionRule) => rule
    ? `${extensionModeLabels[rule.mode]}${rule.updateUrl ? ` · ${rule.updateUrl}` : ''}`
    : 'No rule';
  return <>
    {before !== after && <li>Unlisted extensions · {unlistedLabels[before]} → {unlistedLabels[after]}</li>}
    {extensionDeploymentChanges(reference, candidate).map(({ id, prior, next }) =>
      <li key={id}><code>{id}</code> · {format(prior)} → {format(next)}</li>)}
  </>;
}

export function PolicyChanges({ reference, candidate }: { reference: PreviewPolicy; candidate: PreviewPolicy }) {
  const toggle = (value: boolean) => value ? 'On' : 'Off';
  const fields = [
    ['Test marker', decisionLabels[reference.mode], decisionLabels[candidate.mode]],
    ['GitHub classic PAT', detectorModeLabels[reference.githubPatMode], detectorModeLabels[candidate.githubPatMode]],
    ['Payment card number', detectorModeLabels[reference.paymentCardMode], detectorModeLabels[candidate.paymentCardMode]],
    ['Private key', detectorModeLabels[reference.privateKeyMode ?? 'off'], detectorModeLabels[candidate.privateKeyMode ?? 'off']],
    ['U.S. Social Security number', detectorModeLabels[reference.ssnMode ?? 'off'], detectorModeLabels[candidate.ssnMode ?? 'off']],
    ['Organization identifier detection', detectorModeLabels[reference.identifierProtection?.mode ?? 'off'],
      detectorModeLabels[candidate.identifierProtection?.mode ?? 'off']],
    ['Identifier formats', identifierFormats(reference), identifierFormats(candidate)],
    ['App discovery', toggle(reference.discoveryEnabled), toggle(candidate.discoveryEnabled)],
    ['AI app preset discovery', toggle(reference.presetDiscoveryEnabled ?? false), toggle(candidate.presetDiscoveryEnabled ?? false)],
    ['Extension inventory', toggle(reference.extensionInventoryEnabled), toggle(candidate.extensionInventoryEnabled)],
    ['Claude prompt protection', toggle(reference.claudePromptEnabled), toggle(candidate.claudePromptEnabled)],
    ...uploadApps.map((app) => [`${promptAppLabels[app]} file uploads`, detectorModeLabels[reference.uploadModes[app]],
      detectorModeLabels[candidate.uploadModes[app]]]),
    ...uploadApps.map((app) => [`${promptAppLabels[app]} file content protection`, detectorModeLabels[fileContentMode(reference, app)],
      detectorModeLabels[fileContentMode(candidate, app)]]),
    ...uploadApps.map((app) => [`${promptAppLabels[app]} file types`, reference.uploadTypes[app].join(', ') || 'All files',
      candidate.uploadTypes[app].join(', ') || 'All files']),
  ];
  return <ul className="preview-changes" aria-label="Policy setting changes">
    {fields.filter(([, before, after]) => before !== after).map(([field, before, after]) =>
      <li key={field}>{field} · {before} → {after}</li>)}
    <ExtensionDeploymentChanges reference={reference.extensionDeployment} candidate={candidate.extensionDeployment} />
    {(candidate.blockedAiAppHosts ?? []).filter((host) => !reference.blockedAiAppHosts?.includes(host))
      .map((host) => <li key={`block-${host}`}>Block AI app host <code>{host}</code></li>)}
    {(reference.blockedAiAppHosts ?? []).filter((host) => !candidate.blockedAiAppHosts?.includes(host))
      .map((host) => <li key={`restore-${host}`}>Return <code>{host}</code> to navigation rules</li>)}
    {candidate.customApps.map(({ host, name }) => {
      const before = reference.customApps.find((app) => app.host === host);
      if (!before) return <li key={host}>Add {name} · <code>{host}</code></li>;
      if (before.name !== name) return <li key={host}>{before.name} → {name} · <code>{host}</code></li>;
      return null;
    })}
    {reference.customApps.filter(({ host }) => !candidate.customApps.some((app) => app.host === host))
      .map(({ host, name }) => <li key={host}>Remove {name} · <code>{host}</code></li>)}
    {candidate.promptExceptions.map((entry) => {
      const key = exceptionKey(entry);
      const before = reference.promptExceptions.find((prior) => exceptionKey(prior) === key);
      if (before && samePromptExceptions([before], [entry])) return null;
      return <li key={key}>{before ? 'Update' : 'Add'} {promptAppLabels[entry.appId]} exception for
        {' '}{entry.ruleId === fixtureRule ? 'Test marker' : ruleLabels[entry.ruleId]} · Expires {utc.format(new Date(entry.expiresAt))} UTC · {entry.reason}</li>;
    })}
    {reference.promptExceptions.filter((entry) => !candidate.promptExceptions.some((after) => exceptionKey(after) === exceptionKey(entry)))
      .map((entry) => <li key={exceptionKey(entry)}>Remove {promptAppLabels[entry.appId]} exception for
        {' '}{entry.ruleId === fixtureRule ? 'Test marker' : ruleLabels[entry.ruleId]}</li>)}
    {(['domainRules', 'pathRules'] as const).flatMap((field) => (['allow', 'block'] as const).flatMap((action) => {
      const before = reference[field][action];
      const after = candidate[field][action];
      const added = after.filter((entry) => !before.includes(entry));
      const removed = before.filter((entry) => !after.includes(entry));
      const label = `${field === 'domainRules' ? 'domain' : 'path'} ${action} list`;
      return [added.length > 0 && <li key={`${field}-${action}-add`}>Add to {label} <code>{added.join(', ')}</code></li>,
        removed.length > 0 && <li key={`${field}-${action}-remove`}>Remove from {label} <code>{removed.join(', ')}</code></li>];
    }))}
  </ul>;
}

function identifierFormats(policy: PreviewPolicy) {
  return policy.identifierProtection?.formats.map(({ prefix, digits }) => `${prefix} ${digits}`).join(', ') || 'None';
}
