export type PolicyMode = 'monitor' | 'warn' | 'block';

export type PolicyDecision =
  | { action: 'allow' }
  | {
      action: PolicyMode;
      ruleId: 'fixture-secret';
      detectorCategory: 'synthetic-secret';
      policyVersion: string;
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
    policyVersion: `fixture-v1-${mode}`,
    reason: 'This prompt contains a test secret.',
  };
}
