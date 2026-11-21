import { fixtureDetector, fixtureRule, type Policy, type PolicyMode } from './protocol';

const standaloneVersions: Record<PolicyMode, number> = { monitor: 1, warn: 2, block: 3 };

export function standalonePolicy(mode: PolicyMode): Policy {
  return { mode, version: standaloneVersions[mode] };
}

export type PolicyDecision =
  | { action: 'allow' }
  | {
      action: PolicyMode;
      ruleId: typeof fixtureRule;
      detectorCategory: typeof fixtureDetector;
      policyVersion: number;
      reason: string;
    };

export type MatchedDecision = Exclude<PolicyDecision, { action: 'allow' }>;

export function evaluatePrompt(prompt: string, policy: Policy): PolicyDecision {
  if (!prompt.includes('ZEKVAR_TEST_SECRET')) {
    return { action: 'allow' };
  }

  return {
    action: policy.mode,
    ruleId: fixtureRule,
    detectorCategory: fixtureDetector,
    policyVersion: policy.version,
    reason: 'This prompt contains a test secret.',
  };
}
