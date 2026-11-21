import { containsPaymentCard, redactPaymentCards } from './payment-card';

export const modes = ['monitor', 'warn', 'block'] as const;
export type PolicyMode = typeof modes[number];
export const detectorModes = ['off', ...modes] as const;
export type DetectorMode = typeof detectorModes[number];

export const fixtureRule = 'fixture-secret';
export const fixtureDetector = 'synthetic-secret';
export const githubPatRule = 'github-classic-pat';
export const credentialDetector = 'credential';
export const paymentCardRule = 'payment-card-number';
export const paymentDetector = 'payment-card';
export const testMarker = 'ZEKVAR_TEST_SECRET';
export const ruleLabels = {
  [fixtureRule]: 'Synthetic secret', [githubPatRule]: 'GitHub classic PAT', [paymentCardRule]: 'Payment card number',
} as const;

export type RuleMetadata = { ruleId: typeof fixtureRule; detectorCategory: typeof fixtureDetector } |
  { ruleId: typeof githubPatRule; detectorCategory: typeof credentialDetector } |
  { ruleId: typeof paymentCardRule; detectorCategory: typeof paymentDetector };
export type PromptRuleId = RuleMetadata['ruleId'];
export type PromptPolicy = { mode: PolicyMode; githubPatMode?: DetectorMode; paymentCardMode?: DetectorMode };
export type PromptMatch = { action: PolicyMode; reason: string } & RuleMetadata;

const severity: Record<PolicyMode, number> = { monitor: 1, warn: 2, block: 3 };
const classicGithubPat = /(?<![A-Za-z0-9_])ghp_[A-Za-z0-9]{36}(?![A-Za-z0-9_])/;
const allClassicGithubPats = new RegExp(classicGithubPat.source, 'g');
const redacted = '[REDACTED]';

export function isMode(value: unknown): value is PolicyMode {
  return value === 'monitor' || value === 'warn' || value === 'block';
}

export function isDetectorMode(value: unknown): value is DetectorMode {
  return value === 'off' || isMode(value);
}

export function evaluatePrompt(prompt: string, policy: PromptPolicy, except?: ReadonlySet<PromptRuleId>): { action: 'allow' } | PromptMatch {
  let match: PromptMatch | undefined = !except?.has(fixtureRule) && prompt.includes(testMarker) ? {
    action: policy.mode, ruleId: fixtureRule, detectorCategory: fixtureDetector,
    reason: 'This prompt contains a test secret.',
  } : undefined;
  if (!except?.has(githubPatRule) && isMode(policy.githubPatMode) && (!match || severity[policy.githubPatMode] >= severity[match.action]) &&
      classicGithubPat.test(prompt)) {
    match = {
      action: policy.githubPatMode, ruleId: githubPatRule, detectorCategory: credentialDetector,
      reason: 'This prompt contains text that looks like a GitHub classic personal access token.',
    };
  }
  if (!except?.has(paymentCardRule) && isMode(policy.paymentCardMode) && (!match || severity[policy.paymentCardMode] >= severity[match.action]) &&
      containsPaymentCard(prompt)) {
    return {
      action: policy.paymentCardMode, ruleId: paymentCardRule, detectorCategory: paymentDetector,
      reason: 'This prompt contains a possible payment card number.',
    };
  }
  return match ?? { action: 'allow' };
}

export function redactPrompt(prompt: string, policy: PromptPolicy): string {
  const withoutMarkers = prompt.replaceAll(testMarker, redacted);
  const withoutCredentials = isMode(policy.githubPatMode) ? withoutMarkers.replaceAll(allClassicGithubPats, redacted) : withoutMarkers;
  return isMode(policy.paymentCardMode) ? redactPaymentCards(withoutCredentials, redacted) : withoutCredentials;
}
