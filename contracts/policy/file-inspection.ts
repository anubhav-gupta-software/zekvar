import { classificationRule, evaluatePrompt, fixtureRule, githubPatRule, githubTokenRule, identifierRule, isMode, paymentCardRule,
  privateKeyRule, ssnRule, type PromptPolicy, type PromptRuleId, type RuleMetadata } from './prompt';
import { cloudCredentialRules } from './cloud-credentials';
import { healthRules } from './health-identifiers';

const priority: readonly PromptRuleId[] = [fixtureRule, classificationRule, identifierRule, githubPatRule, githubTokenRule, ...cloudCredentialRules,
  ...healthRules, ssnRule, paymentCardRule, privateKeyRule];

export function preferredFileMatch(current: RuleMetadata | undefined, candidate: RuleMetadata | undefined) {
  if (candidate && (!current || priority.indexOf(candidate.ruleId) > priority.indexOf(current.ruleId))) return candidate;
  return current;
}

export function fileInspectionDetectors(policy: PromptPolicy): PromptPolicy {
  return { mode: 'monitor', githubPatMode: isMode(policy.githubPatMode) ? 'monitor' : 'off',
    githubTokenMode: isMode(policy.githubTokenMode) ? 'monitor' : 'off',
    paymentCardMode: isMode(policy.paymentCardMode) ? 'monitor' : 'off',
    privateKeyMode: isMode(policy.privateKeyMode) ? 'monitor' : 'off',
    ssnMode: isMode(policy.ssnMode) ? 'monitor' : 'off',
    cloudCredentialMode: isMode(policy.cloudCredentialMode) ? 'monitor' : 'off',
    healthProtection: isMode(policy.healthProtection?.mode) ?
      { mode: 'monitor', recordFormats: policy.healthProtection.recordFormats } : undefined,
    classificationProtection: isMode(policy.classificationProtection?.mode) ?
      { mode: 'monitor', terms: policy.classificationProtection.terms } : undefined,
    identifierProtection: isMode(policy.identifierProtection?.mode) ?
      { mode: 'monitor', formats: policy.identifierProtection.formats } : undefined };
}

export function evaluateFileInspection(text: string, detectors: PromptPolicy) {
  const match = evaluatePrompt(text, detectors);
  if (match.action === 'allow') return;
  const { action: _action, reason: _reason, ...rule } = match;
  return rule;
}
