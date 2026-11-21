import { aiPromptApps, decisionLabels, detectorModeLabels, promptAppLabels } from '../lib/control';
import type { PreviewPolicy } from '../lib/preview';

export function PolicyChanges({ reference, candidate }: { reference: PreviewPolicy; candidate: PreviewPolicy }) {
  const toggle = (value: boolean) => value ? 'On' : 'Off';
  const fields = [
    ['Test marker', decisionLabels[reference.mode], decisionLabels[candidate.mode]],
    ['GitHub classic PAT', detectorModeLabels[reference.githubPatMode], detectorModeLabels[candidate.githubPatMode]],
    ['Payment card number', detectorModeLabels[reference.paymentCardMode], detectorModeLabels[candidate.paymentCardMode]],
    ['AI app discovery', toggle(reference.discoveryEnabled), toggle(candidate.discoveryEnabled)],
    ['Extension inventory', toggle(reference.extensionInventoryEnabled), toggle(candidate.extensionInventoryEnabled)],
    ...aiPromptApps.map((app) => [`${promptAppLabels[app]} file uploads`, detectorModeLabels[reference.uploadModes[app]],
      detectorModeLabels[candidate.uploadModes[app]]]),
  ];
  return <ul className="preview-changes" aria-label="Policy setting changes">
    {fields.filter(([, before, after]) => before !== after).map(([field, before, after]) =>
      <li key={field}>{field} · {before} → {after}</li>)}
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
