import { aiPromptApps, decisionLabels, detectorModeLabels, promptAppLabels, ruleLabels, utc } from '../lib/control';
import type { PreviewPolicy } from '../lib/preview';
import { exceptionKey, samePromptExceptions } from '../../../contracts/policy/prompt-exceptions';
import { fixtureRule } from '../../../contracts/policy/prompt';

export function PolicyChanges({ reference, candidate }: { reference: PreviewPolicy; candidate: PreviewPolicy }) {
  const toggle = (value: boolean) => value ? 'On' : 'Off';
  const fields = [
    ['Test marker', decisionLabels[reference.mode], decisionLabels[candidate.mode]],
    ['GitHub classic PAT', detectorModeLabels[reference.githubPatMode], detectorModeLabels[candidate.githubPatMode]],
    ['Payment card number', detectorModeLabels[reference.paymentCardMode], detectorModeLabels[candidate.paymentCardMode]],
    ['App discovery', toggle(reference.discoveryEnabled), toggle(candidate.discoveryEnabled)],
    ['Extension inventory', toggle(reference.extensionInventoryEnabled), toggle(candidate.extensionInventoryEnabled)],
    ...aiPromptApps.map((app) => [`${promptAppLabels[app]} file uploads`, detectorModeLabels[reference.uploadModes[app]],
      detectorModeLabels[candidate.uploadModes[app]]]),
    ...aiPromptApps.map((app) => [`${promptAppLabels[app]} file types`, reference.uploadTypes[app].join(', ') || 'All files',
      candidate.uploadTypes[app].join(', ') || 'All files']),
  ];
  return <ul className="preview-changes" aria-label="Policy setting changes">
    {fields.filter(([, before, after]) => before !== after).map(([field, before, after]) =>
      <li key={field}>{field} · {before} → {after}</li>)}
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
