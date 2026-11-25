import { aiPromptApps, type AiPromptApp } from './apps';
import { isMode, type PolicyMode, type PromptPolicy } from './prompt';

export type PromptAppModes = Partial<Record<AiPromptApp, PolicyMode>>;

export function readPromptAppModes(value: unknown): PromptAppModes | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return;
  const modes: PromptAppModes = {};
  for (const [app, mode] of Object.entries(value)) {
    const id = aiPromptApps.find((entry) => entry === app);
    if (!id || !isMode(mode)) return;
    modes[id] = mode;
  }
  return modes;
}

export function samePromptAppModes(left?: PromptAppModes, right?: PromptAppModes) {
  return aiPromptApps.every((app) => left?.[app] === right?.[app]);
}

export function promptPolicyForApp<T extends PromptPolicy>(policy: T, modes: PromptAppModes | undefined, app: AiPromptApp): T {
  const mode = modes?.[app];
  if (!mode) return policy;
  const override = (prior: T['githubPatMode']) => isMode(prior) ? mode : prior;
  const identifiers = policy.identifierProtection;
  const classification = policy.classificationProtection;
  return {
    ...policy, mode,
    githubPatMode: override(policy.githubPatMode), githubTokenMode: override(policy.githubTokenMode),
    paymentCardMode: override(policy.paymentCardMode), ssnMode: override(policy.ssnMode), privateKeyMode: override(policy.privateKeyMode),
    identifierProtection: identifiers && { ...identifiers, mode: isMode(identifiers.mode) ? mode : identifiers.mode },
    cloudCredentialMode: override(policy.cloudCredentialMode),
    classificationProtection: classification && { ...classification, mode: isMode(classification.mode) ? mode : classification.mode },
  };
}
