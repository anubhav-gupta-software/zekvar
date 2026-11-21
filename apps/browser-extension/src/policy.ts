import { evaluatePrompt as evaluateRules, type PromptMatch } from '../../../contracts/policy/prompt';
import type { Policy, PolicyMode } from './protocol';

const standaloneVersions: Record<PolicyMode, number> = { monitor: 1, warn: 2, block: 3 };

export function standalonePolicy(mode: PolicyMode): Policy {
  return { mode, version: standaloneVersions[mode] };
}

export type MatchedDecision = PromptMatch & { policyVersion: number; assignmentVersion?: number };
type PolicyDecision = { action: 'allow' } | MatchedDecision;

export function evaluatePrompt(prompt: string, policy: Policy): PolicyDecision {
  const match = evaluateRules(prompt, policy);
  return match.action === 'allow' ? match : withPolicyVersion(match, policy);
}

export function withPolicyVersion(match: PromptMatch, policy: Policy): MatchedDecision {
  return { ...match, policyVersion: policy.version, assignmentVersion: policy.assignmentVersion };
}
