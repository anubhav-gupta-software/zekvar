import { evaluateNavigation, parseWebAddress, sameDomainRules, emptyDomainRules, type DomainRules } from '../../../contracts/policy/domains';
import { evaluatePrompt, fixtureRule, ruleLabels, testMarker, type DetectorMode, type PolicyMode } from '../../../contracts/policy/prompt';
import type { Policy } from './control';

export type PreviewPolicy = {
  mode: PolicyMode; githubPatMode: DetectorMode; paymentCardMode: DetectorMode; discoveryEnabled: boolean; domainRules: DomainRules;
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
    domainRules: policy.domainRules ?? emptyDomainRules,
  };
}

export function samePolicy(a: PreviewPolicy, b: PreviewPolicy) {
  return a.mode === b.mode && a.githubPatMode === b.githubPatMode && a.paymentCardMode === b.paymentCardMode &&
    a.discoveryEnabled === b.discoveryEnabled &&
    sameDomainRules(a.domainRules, b.domainRules);
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
  const outcome = evaluateNavigation(url, policy.domainRules);
  return { action: outcome.action, rule: outcome.domain };
}

export function runComparison(reference: PreviewSnapshot, candidate: PreviewPolicy, prompt: string, address?: URL): PreviewResult {
  const rows: PreviewRow[] = prompts.map(({ name, content }) => ({
    name, current: promptOutcome(content, reference), draft: promptOutcome(content, candidate),
  }));
  if (prompt.trim()) rows.push({ name: 'Custom prompt', current: promptOutcome(prompt, reference), draft: promptOutcome(prompt, candidate) });
  for (const { name, content } of navigations) {
    const url = new URL(content);
    rows.push({ name, current: navigationOutcome(url, reference), draft: navigationOutcome(url, candidate) });
  }
  if (address) rows.push({ name: 'Custom navigation', current: navigationOutcome(address, reference), draft: navigationOutcome(address, candidate) });
  return { reference, candidate, rows };
}

export { parseWebAddress };
