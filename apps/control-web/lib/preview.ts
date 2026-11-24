import { evaluateNavigation, parseWebAddress, sameDomainRules, emptyDomainRules, emptyPathRules,
  type DomainRules, type PathRules } from '../../../contracts/policy/domains';
import { fixtureRule, ruleLabels, sameIdentifierProtection, testMarker,
  type DetectorMode, type IdentifierProtection, type PolicyMode } from '../../../contracts/policy/prompt';
import { chatGptApp, claudeApp, promptAppLabels, type AiPromptApp } from '../../../contracts/policy/apps';
import { evaluateFileInspection, fileInspectionDetectors } from '../../../contracts/policy/file-inspection';
import { allUploadTypes, fileContentMode, matchesUploadType, sameUploadTypes, uploadApps, uploadsOff, type UploadFile, type UploadMode,
  type FileInspection, type UploadModes, type UploadTypes } from '../../../contracts/policy/uploads';
import type { Policy } from './control';
import { sameCustomApps, type CustomAppSetting } from '../../../contracts/policy/discovery';
import { evaluatePromptWithExceptions, exceptionDecision, samePromptExceptions, type PromptException } from '../../../contracts/policy/prompt-exceptions';
import { sameExtensionDeployment, type ExtensionDeployment } from './extension-deployment';
import { hardeningDifferences, type BrowserHardening } from './browser-hardening';
import { blockedAiAppAt } from '../../../contracts/policy/ai-app-access';
import { inspectClipboard, type ClipboardMode } from '../../../contracts/policy/clipboard';
import { ruleLabels as decisionRuleLabels } from './control';

export type PreviewPolicy = {
  mode: PolicyMode; githubPatMode: DetectorMode; paymentCardMode: DetectorMode; privateKeyMode?: DetectorMode; discoveryEnabled: boolean;
  presetDiscoveryEnabled?: boolean;
  identifierProtection?: IdentifierProtection;
  ssnMode?: DetectorMode;
  extensionInventoryEnabled: boolean;
  extensionDeployment?: ExtensionDeployment;
  browserHardening?: BrowserHardening;
  blockedAiAppHosts?: string[];
  claudePromptEnabled: boolean;
  fileInspection?: FileInspection;
  fileContentModes?: UploadModes;
  clipboardMode?: ClipboardMode;
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
    ssnMode: policy.ssnMode,
    identifierProtection: policy.identifierProtection,
    discoveryEnabled: policy.discoveryEnabled ?? false,
    presetDiscoveryEnabled: policy.presetDiscoveryEnabled,
    customApps: (policy.customApps ?? []).map(({ host, name }) => ({ host, name })),
    promptExceptions: policy.promptExceptions ?? [],
    extensionInventoryEnabled: policy.extensionInventoryEnabled ?? false,
    extensionDeployment: policy.extensionDeployment,
    browserHardening: policy.browserHardening,
    blockedAiAppHosts: policy.blockedAiAppHosts,
    claudePromptEnabled: policy.claudePromptEnabled ?? false,
    domainRules: policy.domainRules ?? emptyDomainRules,
    pathRules: policy.pathRules ?? emptyPathRules,
    uploadModes: policy.uploadModes ?? uploadsOff,
    uploadTypes: policy.uploadTypes ?? allUploadTypes,
    fileInspection: policy.fileInspection,
    fileContentModes: policy.fileContentModes,
    clipboardMode: policy.clipboardMode,
  };
}

export function samePolicy(a: PreviewPolicy, b: PreviewPolicy) {
  return a.mode === b.mode && a.githubPatMode === b.githubPatMode && a.paymentCardMode === b.paymentCardMode &&
    (a.clipboardMode ?? 'off') === (b.clipboardMode ?? 'off') &&
    a.privateKeyMode === b.privateKeyMode && a.ssnMode === b.ssnMode &&
    sameIdentifierProtection(a.identifierProtection, b.identifierProtection) &&
    a.discoveryEnabled === b.discoveryEnabled && a.extensionInventoryEnabled === b.extensionInventoryEnabled &&
    a.presetDiscoveryEnabled === b.presetDiscoveryEnabled &&
    sameExtensionDeployment(a.extensionDeployment, b.extensionDeployment) &&
    hardeningDifferences(a.browserHardening, b.browserHardening).length === 0 &&
    (a.blockedAiAppHosts ?? []).join(',') === (b.blockedAiAppHosts ?? []).join(',') &&
    a.claudePromptEnabled === b.claudePromptEnabled &&
    uploadApps.every((app) => a.uploadModes[app] === b.uploadModes[app] && sameUploadTypes(a.uploadTypes[app], b.uploadTypes[app]) &&
      fileContentMode(a, app) === fileContentMode(b, app)) &&
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
  { name: 'Synthetic U.S. SSN', content: 'Social Security number: 899 97 4321' },
];
const navigations = [
  { name: 'Sample domain', content: 'https://pilot.example.test/start' },
  { name: 'Sample subdomain', content: 'https://work.pilot.example.test/' },
  { name: 'Similar domain', content: 'https://pilot.example.test.other.test/' },
];

export function promptOutcome(content: string, policy: PreviewPolicy, app: AiPromptApp, now: number): PreviewDecision {
  if (app === claudeApp && !policy.claudePromptEnabled) return { action: 'allow' };
  const grants = policy.promptExceptions.filter(({ appId, expiresAt }) => appId === app && Date.parse(expiresAt) > now);
  const { match, exception } = evaluatePromptWithExceptions(content, policy, new Set(grants.map(({ ruleId }) => ruleId)));
  const outcome = exception ?? match;
  if (outcome.action === 'allow') return outcome;
  return { action: exception ? exceptionDecision : outcome.action,
    rule: outcome.ruleId === fixtureRule ? 'Test marker' : ruleLabels[outcome.ruleId] };
}

export function navigationOutcome(url: URL, policy: PreviewPolicy): PreviewDecision {
  const blockedHost = blockedAiAppAt(url, policy.blockedAiAppHosts ?? []);
  if (blockedHost) return { action: 'block', rule: `AI app access · ${blockedHost}` };
  const outcome = evaluateNavigation(url, policy.domainRules, policy.pathRules);
  return { action: outcome.action, rule: outcome.pathRule ?? outcome.domain };
}

export function clipboardOutcome(text: string | undefined, policy: PreviewPolicy, app: AiPromptApp): PreviewDecision {
  if (app === claudeApp && !policy.claudePromptEnabled) return { action: 'allow' };
  const result = inspectClipboard(text, policy, policy.clipboardMode ?? 'off');
  return result ? { action: result.decision, rule: result.ruleId === fixtureRule ? 'Test marker' : decisionRuleLabels[result.ruleId] } : { action: 'allow' };
}

function uploadOutcome(mode: UploadMode, types: string[], file: UploadFile): PreviewDecision {
  if (mode === 'off' || (types.length && !matchesUploadType(file, types))) return { action: 'allow' };
  return { action: mode, rule: 'File upload policy' };
}

export function fileInspectionOutcome(policy: PreviewPolicy, app: typeof uploadApps[number], file: UploadFile, text?: string): PreviewDecision {
  const beforeInspection = uploadOutcome(policy.uploadModes[app], policy.uploadTypes[app], file);
  if (beforeInspection.action === 'block') return beforeInspection;
  const mode = fileContentMode(policy, app);
  if (mode === 'off') return beforeInspection;
  if (text === undefined && mode === 'block') return { action: 'block', rule: 'File check unavailable' };
  const match = text !== undefined && evaluateFileInspection(text, fileInspectionDetectors(policy));
  return match ? { action: mode, rule: `${match.ruleId === fixtureRule ? 'Test marker' : ruleLabels[match.ruleId]} in file content` } : beforeInspection;
}

export function runComparison(reference: PreviewSnapshot, candidate: PreviewPolicy, prompt: string, address?: URL,
  file?: UploadFile, app: AiPromptApp = chatGptApp, now = Date.now()): PreviewResult {
  const rows: PreviewRow[] = prompts.map(({ name, content }) => ({
    name, current: promptOutcome(content, reference, app, now), draft: promptOutcome(content, candidate, app, now),
  }));
  const identifierExamples = new Map<string, string>();
  for (const { prefix, digits } of [...(reference.identifierProtection?.formats ?? []), ...(candidate.identifierProtection?.formats ?? [])]) {
    identifierExamples.set(`${prefix} · ${digits} digits`, prefix + '0'.repeat(digits));
  }
  for (const [label, sample] of identifierExamples) {
    rows.push({ name: `Organization identifier ${label}`, current: promptOutcome(sample, reference, app, now),
      draft: promptOutcome(sample, candidate, app, now) });
  }
  if (prompt.trim()) rows.push({ name: 'Custom prompt', current: promptOutcome(prompt, reference, app, now),
    draft: promptOutcome(prompt, candidate, app, now) });
  if ((reference.clipboardMode ?? 'off') !== 'off' || (candidate.clipboardMode ?? 'off') !== 'off') {
    for (const [name, sample] of [
      ['test marker paste', testMarker], ['clean text paste', 'Quarterly planning notes.'], ['paste without inspectable text', undefined],
      ...(prompt.trim() ? [['custom text paste', prompt] as const] : []),
    ] as const) {
      rows.push({ name: `${promptAppLabels[app]} ${name}`, current: clipboardOutcome(sample, reference, app), draft: clipboardOutcome(sample, candidate, app) });
    }
  }
  for (const { name, content } of navigations) {
    const url = new URL(content);
    rows.push({ name, current: navigationOutcome(url, reference), draft: navigationOutcome(url, candidate) });
  }
  const appHosts = new Set([...(reference.blockedAiAppHosts ?? []), ...(candidate.blockedAiAppHosts ?? [])]);
  for (const host of appHosts) {
    const url = new URL(`https://${host}/`);
    rows.push({ name: `AI access · ${host}`, current: navigationOutcome(url, reference), draft: navigationOutcome(url, candidate) });
  }
  if (address) rows.push({ name: 'Custom navigation', current: navigationOutcome(address, reference), draft: navigationOutcome(address, candidate) });
  for (const app of uploadApps) {
    if (reference.fileInspection !== undefined || candidate.fileInspection !== undefined || candidate.fileContentModes) {
      const textFile = { name: 'synthetic.txt', type: 'text/plain' };
      const samples = [{ name: 'synthetic text file', file: textFile, text: testMarker },
        { name: 'clean text file', file: textFile, text: 'Quarterly planning notes.' },
        { name: 'synthetic SSN file', file: textFile, text: 'SSN: 899-97-4321' },
        { name: 'unscannable PDF sample', file: { name: 'synthetic.pdf', type: 'application/pdf' }, text: undefined }];
      for (const { name, file, text } of samples) rows.push({ name: `${promptAppLabels[app]} ${name}`,
        current: fileInspectionOutcome(reference, app, file, text), draft: fileInspectionOutcome(candidate, app, file, text) });
      for (const [label, sample] of identifierExamples) {
        rows.push({ name: `${promptAppLabels[app]} identifier file ${label}`,
          current: fileInspectionOutcome(reference, app, textFile, sample), draft: fileInspectionOutcome(candidate, app, textFile, sample) });
      }
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
