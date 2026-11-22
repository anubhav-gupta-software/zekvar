import { aiPromptApps, type AiPromptApp } from './apps';
import { evaluatePrompt, ruleLabels, type PromptPolicy, type PromptRuleId } from './prompt';

export const exceptionDecision = 'exception_applied';
export const exceptionWindowMs = 24 * 60 * 60_000;
export const promptExceptionLimit = aiPromptApps.length * Object.keys(ruleLabels).length;
export type PromptException = { appId: AiPromptApp; ruleId: PromptRuleId; expiresAt: string; reason: string };
export type PromptExceptionGrant = { appId: AiPromptApp; ruleId: PromptRuleId; expiresAtMs: number };
export type PromptExceptionLease = { serverTimeMs: number; grants: PromptExceptionGrant[] };
export const promptExceptionError = 'Choose one exception per app and detector, with an expiry and a reason of 3 to 120 characters.';

export function isExceptionTarget(app: unknown, rule: unknown): boolean {
  return typeof app === 'string' && aiPromptApps.some((item) => item === app) &&
    typeof rule === 'string' && Object.hasOwn(ruleLabels, rule);
}

export function exceptionKey({ appId, ruleId }: Pick<PromptException, 'appId' | 'ruleId'>) {
  return `${appId}/${ruleId}`;
}

export function samePromptExceptions(before: readonly PromptException[], after: readonly PromptException[]) {
  return before.length === after.length && before.every((entry) => after.some((candidate) =>
    exceptionKey(entry) === exceptionKey(candidate) && Date.parse(entry.expiresAt) === Date.parse(candidate.expiresAt) &&
    entry.reason === candidate.reason));
}

export function readPromptExceptions(input: unknown): PromptException[] | undefined {
  if (!Array.isArray(input) || input.length > promptExceptionLimit) return;
  const entries = new Map<string, PromptException>();
  for (const raw of input) {
    if (!raw || !isExceptionTarget(raw.appId, raw.ruleId) || typeof raw.expiresAt !== 'string' ||
        !Number.isFinite(Date.parse(raw.expiresAt)) || typeof raw.reason !== 'string') return;
    const reason = raw.reason.trim();
    if (reason.length < 3 || reason.length > 120 || /[\x00-\x1f\x7f-\x9f]/.test(reason)) return;
    const entry: PromptException = { appId: raw.appId, ruleId: raw.ruleId, expiresAt: new Date(raw.expiresAt).toISOString(), reason };
    const key = exceptionKey(entry);
    if (entries.has(key)) return;
    entries.set(key, entry);
  }
  return [...entries.values()];
}

export function evaluatePromptWithExceptions(prompt: string, policy: PromptPolicy, except?: ReadonlySet<PromptRuleId>) {
  const original = evaluatePrompt(prompt, policy);
  if (original.action === 'allow' || original.action === 'monitor' || !except?.has(original.ruleId)) return { match: original };
  const remaining = evaluatePrompt(prompt, policy, except);
  return remaining.action === 'warn' || remaining.action === 'block' ? { match: remaining } :
    { match: remaining, exception: original };
}
