import { evaluateNavigation, parseWebAddress, sameDomainRules, emptyDomainRules, emptyPathRules,
  type DomainRules, type PathRules } from '../../../contracts/policy/domains';
import { fixtureRule, ruleLabels, testMarker, type DetectorMode, type PolicyMode } from '../../../contracts/policy/prompt';
import { chatGptApp, claudeApp, promptAppLabels, type AiPromptApp } from '../../../contracts/policy/apps';
import { evaluateFileInspection, fileInspectionDetectors } from '../../../contracts/policy/file-inspection';
import { allUploadTypes, matchesUploadType, sameUploadTypes, uploadApps, uploadsOff, type UploadFile, type UploadMode,
  type FileInspection, type UploadModes, type UploadTypes } from '../../../contracts/policy/uploads';
import type { Policy } from './control';
import { sameCustomApps, type CustomAppSetting } from '../../../contracts/policy/discovery';
import { evaluatePromptWithExceptions, exceptionDecision, samePromptExceptions, type PromptException } from '../../../contracts/policy/prompt-exceptions';

export type PreviewPolicy = {
  mode: PolicyMode; githubPatMode: DetectorMode; paymentCardMode: DetectorMode; privateKeyMode?: DetectorMode; discoveryEnabled: boolean;
  extensionInventoryEnabled: boolean;
  claudePromptEnabled: boolean;
  fileInspection?: FileInspection;
  domainRules: DomainRules; pathRules: PathRules; uploadModes: UploadModes; uploadTypes: UploadTypes;
  customApps: CustomAppSetting[];
  promptExceptions: PromptException[];
};
export type PreviewSnapshot = PreviewPolicy & { version: number; label: string };
export type PreviewDecision = { action: 'allow' | PolicyMode | typeof exceptionDecision; rule?: string };
export type PreviewRow = { name: string; current: PreviewDecision; draft: PreviewDecision };
export type PreviewResult = { reference: PreviewSnapshot; candidate: PreviewPolicy; rows: PreviewRow[] };

export function previewSnapshot(policy: Policy, scope: string): PreviewSnapshot {
  return {
    version: policy.version, label: `${scope} v${policy.version}`,
    mode: policy.mode, githubPatMode: policy.githubPatMode ?? 'off', paymentCardMode: policy.paymentCardMode ?? 'off',
    privateKeyMode: policy.privateKeyMode,
    discoveryEnabled: policy.discoveryEnabled ?? false,
    customApps: (policy.customApps ?? []).map(({ host, name }) => ({ host, name })),
    promptExceptions: policy.promptExceptions ?? [],
    extensionInventoryEnabled: policy.extensionInventoryEnabled ?? false,
    claudePromptEnabled: policy.claudePromptEnabled ?? false,
    domainRules: policy.domainRules ?? emptyDomainRules,
    pathRules: policy.pathRules ?? emptyPathRules,
    uploadModes: policy.uploadModes ?? uploadsOff,
    uploadTypes: policy.uploadTypes ?? allUploadTypes,
    fileInspection: policy.fileInspection,
  };
}

export function samePolicy(a: PreviewPolicy, b: PreviewPolicy) {
  return a.mode === b.mode && a.githubPatMode === b.githubPatMode && a.paymentCardMode === b.paymentCardMode &&
    a.privateKeyMode === b.privateKeyMode &&
    a.discoveryEnabled === b.discoveryEnabled && a.extensionInventoryEnabled === b.extensionInventoryEnabled &&
    a.claudePromptEnabled === b.claudePromptEnabled &&
    uploadApps.every((app) => a.uploadModes[app] === b.uploadModes[app] && sameUploadTypes(a.uploadTypes[app], b.uploadTypes[app]) &&
      a.fileInspection?.[app] === b.fileInspection?.[app]) &&
    sameCustomApps(a.customApps, b.customApps) && samePromptExceptions(a.promptExceptions, b.promptExceptions) &&
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
  { name: 'Synthetic private key block', content: ['-----BEGIN PRIVATE KEY-----', 'A'.repeat(64), '-----END PRIVATE KEY-----'].join('\n') },
];
const navigations = [
  { name: 'Sample domain', content: 'https://pilot.example.test/start' },
  { name: 'Sample subdomain', content: 'https://work.pilot.example.test/' },
  { name: 'Similar domain', content: 'https://pilot.example.test.other.test/' },
];

function promptOutcome(content: string, policy: PreviewPolicy, app: AiPromptApp, now: number): PreviewDecision {
  if (app === claudeApp && !policy.claudePromptEnabled) return { action: 'allow' };
  const grants = policy.promptExceptions.filter(({ appId, expiresAt }) => appId === app && Date.parse(expiresAt) > now);
  const { match, exception } = evaluatePromptWithExceptions(content, policy, new Set(grants.map(({ ruleId }) => ruleId)));
  const outcome = exception ?? match;
  if (outcome.action === 'allow') return outcome;
  return { action: exception ? exceptionDecision : outcome.action,
    rule: outcome.ruleId === fixtureRule ? 'Test marker' : ruleLabels[outcome.ruleId] };
}

function navigationOutcome(url: URL, policy: PreviewPolicy): PreviewDecision {
  const outcome = evaluateNavigation(url, policy.domainRules, policy.pathRules);
  return { action: outcome.action, rule: outcome.pathRule ?? outcome.domain };
}

function uploadOutcome(mode: UploadMode, types: string[], file: UploadFile): PreviewDecision {
  if (mode === 'off' || (types.length && !matchesUploadType(file, types))) return { action: 'allow' };
  return { action: mode, rule: 'File upload policy' };
}

function fileInspectionOutcome(policy: PreviewPolicy, app: typeof uploadApps[number]): PreviewDecision {
  const beforeInspection = uploadOutcome(policy.uploadModes[app], policy.uploadTypes[app], { name: 'synthetic.txt', type: 'text/plain' });
  if (beforeInspection.action === 'block') return beforeInspection;
  const match = policy.fileInspection?.[app] ? evaluateFileInspection(testMarker, fileInspectionDetectors(policy)) : undefined;
  return match ? { action: 'monitor', rule: 'Test marker in file content' } : beforeInspection;
}

export function runComparison(reference: PreviewSnapshot, candidate: PreviewPolicy, prompt: string, address?: URL,
  file?: UploadFile, app: AiPromptApp = chatGptApp): PreviewResult {
  const now = Date.now();
  const rows: PreviewRow[] = prompts.map(({ name, content }) => ({
    name, current: promptOutcome(content, reference, app, now), draft: promptOutcome(content, candidate, app, now),
  }));
  if (prompt.trim()) rows.push({ name: 'Custom prompt', current: promptOutcome(prompt, reference, app, now),
    draft: promptOutcome(prompt, candidate, app, now) });
  for (const { name, content } of navigations) {
    const url = new URL(content);
    rows.push({ name, current: navigationOutcome(url, reference), draft: navigationOutcome(url, candidate) });
  }
  if (address) rows.push({ name: 'Custom navigation', current: navigationOutcome(address, reference), draft: navigationOutcome(address, candidate) });
  for (const app of uploadApps) {
    if (reference.fileInspection !== undefined || candidate.fileInspection !== undefined) {
      rows.push({ name: `${promptAppLabels[app]} synthetic text file`, current: fileInspectionOutcome(reference, app),
        draft: fileInspectionOutcome(candidate, app) });
    }
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
