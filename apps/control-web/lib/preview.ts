import { evaluateNavigation, parseWebAddress, sameDomainRules, emptyDomainRules, emptyPathRules,
  type DomainRules, type PathRules } from '../../../contracts/policy/domains';
import { evaluatePrompt, fixtureRule, ruleLabels, testMarker, type DetectorMode, type PolicyMode } from '../../../contracts/policy/prompt';
import { aiPromptApps, promptAppLabels } from '../../../contracts/policy/apps';
import { allUploadTypes, matchesUploadType, sameUploadTypes, uploadsOff, type UploadFile, type UploadMode,
  type UploadModes, type UploadTypes } from '../../../contracts/policy/uploads';
import type { Policy } from './control';

export type PreviewPolicy = {
  mode: PolicyMode; githubPatMode: DetectorMode; paymentCardMode: DetectorMode; discoveryEnabled: boolean;
  extensionInventoryEnabled: boolean;
  domainRules: DomainRules; pathRules: PathRules; uploadModes: UploadModes; uploadTypes: UploadTypes;
};
export type PreviewSnapshot = PreviewPolicy & { version: number; label: string };
export type PreviewDecision = { action: 'allow' | PolicyMode; rule?: string };
export type PreviewRow = { name: string; current: PreviewDecision; draft: PreviewDecision };
export type PreviewResult = { reference: PreviewSnapshot; candidate: PreviewPolicy; rows: PreviewRow[] };

export function previewSnapshot(policy: Policy, scope: string): PreviewSnapshot {
  return {
    version: policy.version, label: `${scope} v${policy.version}`,
    mode: policy.mode, githubPatMode: policy.githubPatMode ?? 'off', paymentCardMode: policy.paymentCardMode ?? 'off',
    discoveryEnabled: policy.discoveryEnabled ?? false,
    extensionInventoryEnabled: policy.extensionInventoryEnabled ?? false,
    domainRules: policy.domainRules ?? emptyDomainRules,
    pathRules: policy.pathRules ?? emptyPathRules,
    uploadModes: policy.uploadModes ?? uploadsOff,
    uploadTypes: policy.uploadTypes ?? allUploadTypes,
  };
}

export function samePolicy(a: PreviewPolicy, b: PreviewPolicy) {
  return a.mode === b.mode && a.githubPatMode === b.githubPatMode && a.paymentCardMode === b.paymentCardMode &&
    a.discoveryEnabled === b.discoveryEnabled && a.extensionInventoryEnabled === b.extensionInventoryEnabled &&
    aiPromptApps.every((app) => a.uploadModes[app] === b.uploadModes[app] && sameUploadTypes(a.uploadTypes[app], b.uploadTypes[app])) &&
    sameDomainRules(a.domainRules, b.domainRules) && sameDomainRules(a.pathRules, b.pathRules);
}

export function changedDecision(row: PreviewRow) {
  return row.current.action !== row.draft.action || row.current.rule !== row.draft.rule;
}

const fakePat = `ghp_${'0'.repeat(36)}`;
const prompts = [
  { name: 'Clean prompt', content: 'Summarize the quarterly planning notes.' },
  { name: 'Synthetic test marker', content: testMarker },
  { name: 'Synthetic GitHub token', content: `token=${fakePat}` },
  { name: 'Both detectors match', content: `${testMarker} ${fakePat}` },
  { name: 'Token embedded in a longer string', content: `prefix_${fakePat}_suffix` },
  { name: 'Synthetic payment card', content: 'Test card 4242 4242 4242 4242' },
  { name: 'Payment card with invalid checksum', content: 'Test card 4242 4242 4242 4243' },
];
const navigations = [
  { name: 'Sample domain', content: 'https://pilot.example.test/start' },
  { name: 'Sample subdomain', content: 'https://work.pilot.example.test/' },
  { name: 'Similar domain', content: 'https://pilot.example.test.other.test/' },
];

function promptOutcome(content: string, policy: PreviewPolicy): PreviewDecision {
  const outcome = evaluatePrompt(content, policy);
  if (outcome.action === 'allow') return outcome;
  return { action: outcome.action, rule: outcome.ruleId === fixtureRule ? 'Test marker' : ruleLabels[outcome.ruleId] };
}

function navigationOutcome(url: URL, policy: PreviewPolicy): PreviewDecision {
  const outcome = evaluateNavigation(url, policy.domainRules, policy.pathRules);
  return { action: outcome.action, rule: outcome.pathRule ?? outcome.domain };
}

function uploadOutcome(mode: UploadMode, types: string[], file: UploadFile): PreviewDecision {
  if (mode === 'off' || (types.length && !matchesUploadType(file, types))) return { action: 'allow' };
  return { action: mode, rule: 'File upload policy' };
}

export function runComparison(reference: PreviewSnapshot, candidate: PreviewPolicy, prompt: string, address?: URL, file?: UploadFile): PreviewResult {
  const rows: PreviewRow[] = prompts.map(({ name, content }) => ({
    name, current: promptOutcome(content, reference), draft: promptOutcome(content, candidate),
  }));
  if (prompt.trim()) rows.push({ name: 'Custom prompt', current: promptOutcome(prompt, reference), draft: promptOutcome(prompt, candidate) });
  for (const { name, content } of navigations) {
    const url = new URL(content);
    rows.push({ name, current: navigationOutcome(url, reference), draft: navigationOutcome(url, candidate) });
  }
  if (address) rows.push({ name: 'Custom navigation', current: navigationOutcome(address, reference), draft: navigationOutcome(address, candidate) });
  for (const app of aiPromptApps) {
    for (const [name, sample] of [
      ['TXT upload', { name: 'example.txt', type: 'text/plain' }],
      ['PNG upload', { name: 'example.png', type: 'image/png' }],
      ['custom file upload', file],
    ] as const) {
      if (!sample) continue;
      rows.push({ name: `${promptAppLabels[app]} ${name}`,
        current: uploadOutcome(reference.uploadModes[app], reference.uploadTypes[app], sample),
        draft: uploadOutcome(candidate.uploadModes[app], candidate.uploadTypes[app], sample) });
    }
  }
  return { reference, candidate, rows };
}

export { parseWebAddress };
