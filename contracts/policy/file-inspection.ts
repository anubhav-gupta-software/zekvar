import { evaluatePrompt, isMode, type PromptPolicy } from './prompt';

export function fileInspectionDetectors(policy: PromptPolicy): PromptPolicy {
  return { mode: 'monitor', githubPatMode: isMode(policy.githubPatMode) ? 'monitor' : 'off',
    githubTokenMode: isMode(policy.githubTokenMode) ? 'monitor' : 'off',
    paymentCardMode: isMode(policy.paymentCardMode) ? 'monitor' : 'off',
    privateKeyMode: isMode(policy.privateKeyMode) ? 'monitor' : 'off',
    ssnMode: isMode(policy.ssnMode) ? 'monitor' : 'off',
    identifierProtection: isMode(policy.identifierProtection?.mode) ?
      { mode: 'monitor', formats: policy.identifierProtection.formats } : undefined };
}

export function evaluateFileInspection(text: string, detectors: PromptPolicy) {
  const match = evaluatePrompt(text, detectors);
  if (match.action === 'allow') return;
  const { action: _action, reason: _reason, ...rule } = match;
  return rule;
}
