export const modes = ['monitor', 'warn', 'block'] as const;
export type PolicyMode = typeof modes[number];
export const detectorModes = ['off', ...modes] as const;
export type DetectorMode = typeof detectorModes[number];

export const fixtureRule = 'fixture-secret';
export const fixtureDetector = 'synthetic-secret';
export const githubPatRule = 'github-classic-pat';
export const credentialDetector = 'credential';
export const testMarker = 'ZEKVAR_TEST_SECRET';

export type RuleMetadata = { ruleId: typeof fixtureRule; detectorCategory: typeof fixtureDetector } |
  { ruleId: typeof githubPatRule; detectorCategory: typeof credentialDetector };
export type PromptPolicy = { mode: PolicyMode; githubPatMode?: DetectorMode };
export type PromptMatch = { action: PolicyMode; reason: string } & RuleMetadata;

const severity: Record<PolicyMode, number> = { monitor: 1, warn: 2, block: 3 };
const classicGithubPat = /(?<![A-Za-z0-9_])ghp_[A-Za-z0-9]{36}(?![A-Za-z0-9_])/;

export function isMode(value: unknown): value is PolicyMode {
  return value === 'monitor' || value === 'warn' || value === 'block';
}

export function isDetectorMode(value: unknown): value is DetectorMode {
  return value === 'off' || isMode(value);
}

export function evaluatePrompt(prompt: string, policy: PromptPolicy): { action: 'allow' } | PromptMatch {
  const fixtureMatch = prompt.includes(testMarker);
  if (isMode(policy.githubPatMode) && (!fixtureMatch || severity[policy.githubPatMode] >= severity[policy.mode]) &&
      classicGithubPat.test(prompt)) {
    return {
      action: policy.githubPatMode, ruleId: githubPatRule, detectorCategory: credentialDetector,
      reason: 'This prompt contains text that looks like a GitHub classic personal access token.',
    };
  }
  return fixtureMatch ? {
    action: policy.mode, ruleId: fixtureRule, detectorCategory: fixtureDetector,
    reason: 'This prompt contains a test secret.',
  } : { action: 'allow' };
}
