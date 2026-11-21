import { credentialDetector, fixtureDetector, fixtureRule, githubPatRule, isMode, type Policy, type PolicyMode, type RuleMetadata } from './protocol';

const standaloneVersions: Record<PolicyMode, number> = { monitor: 1, warn: 2, block: 3 };

export function standalonePolicy(mode: PolicyMode): Policy {
  return { mode, version: standaloneVersions[mode] };
}

export type MatchedDecision = { action: PolicyMode; policyVersion: number; reason: string } & RuleMetadata;
type PolicyDecision = { action: 'allow' } | MatchedDecision;
const severity: Record<PolicyMode, number> = { monitor: 1, warn: 2, block: 3 };
const classicGithubPat = /(?<![A-Za-z0-9_])ghp_[A-Za-z0-9]{36}(?![A-Za-z0-9_])/;

export function evaluatePrompt(prompt: string, policy: Policy): PolicyDecision {
  const fixtureMatch = prompt.includes('ZEKVAR_TEST_SECRET');
  if (isMode(policy.githubPatMode) && (!fixtureMatch || severity[policy.githubPatMode] >= severity[policy.mode]) &&
      classicGithubPat.test(prompt)) {
    return {
      action: policy.githubPatMode, ruleId: githubPatRule, detectorCategory: credentialDetector,
      policyVersion: policy.version, reason: 'This prompt contains text that looks like a GitHub classic personal access token.',
    };
  }
  if (!fixtureMatch) return { action: 'allow' };

  return {
    action: policy.mode,
    ruleId: fixtureRule,
    detectorCategory: fixtureDetector,
    policyVersion: policy.version,
    reason: 'This prompt contains a test secret.',
  };
}
