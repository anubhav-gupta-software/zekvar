export type PolicyMode = 'monitor' | 'warn' | 'block';
const fixturePolicyVersions: Record<PolicyMode, number> = { monitor: 1, warn: 2, block: 3 };

export type PolicyDecision =
  | { action: 'allow' }
  | {
      action: PolicyMode;
      ruleId: 'fixture-secret';
      detectorCategory: 'synthetic-secret';
      policyVersion: number;
      reason: string;
    };

export type MatchedDecision = Exclude<PolicyDecision, { action: 'allow' }>;

export function evaluatePrompt(prompt: string, mode: PolicyMode): PolicyDecision {
  if (!prompt.includes('ZEKVAR_TEST_SECRET')) {
    return { action: 'allow' };
  }

  return {
    action: mode,
    ruleId: 'fixture-secret',
    detectorCategory: 'synthetic-secret',
    policyVersion: fixturePolicyVersions[mode],
    reason: 'This prompt contains a test secret.',
  };
}
