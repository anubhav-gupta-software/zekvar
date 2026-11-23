import { containsPaymentCard, redactPaymentCards } from './payment-card';
import { containsPrivateKey, redactPrivateKeys } from './private-key';
import { containsIdentifier, readIdentifierFormats, redactIdentifiers, sameIdentifierFormats, type IdentifierFormat } from './organization-identifiers';

export const modes = ['monitor', 'warn', 'block'] as const;
export type PolicyMode = typeof modes[number];
export const detectorModes = ['off', ...modes] as const;
export type DetectorMode = typeof detectorModes[number];

export const fixtureRule = 'fixture-secret';
export const fixtureDetector = 'synthetic-secret';
export const githubPatRule = 'github-classic-pat';
export const credentialDetector = 'credential';
export const paymentCardRule = 'payment-card-number';
export const paymentDetector = 'payment-card';
export const privateKeyRule = 'pem-private-key';
export const identifierRule = 'organization-identifier';
export const identifierDetector = 'internal-identifier';
export const testMarker = 'ZEKVAR_TEST_SECRET';
export const ruleLabels = {
  [fixtureRule]: 'Synthetic secret', [githubPatRule]: 'GitHub classic PAT', [paymentCardRule]: 'Payment card number',
  [privateKeyRule]: 'Private key',
  [identifierRule]: 'Organization identifier',
} as const;

export type RuleMetadata = { ruleId: typeof fixtureRule; detectorCategory: typeof fixtureDetector } |
  { ruleId: typeof githubPatRule; detectorCategory: typeof credentialDetector } |
  { ruleId: typeof paymentCardRule; detectorCategory: typeof paymentDetector } |
  { ruleId: typeof privateKeyRule; detectorCategory: typeof credentialDetector } |
  { ruleId: typeof identifierRule; detectorCategory: typeof identifierDetector };
export type PromptRuleId = RuleMetadata['ruleId'];
export type IdentifierProtection = { mode: DetectorMode; formats: IdentifierFormat[] };
export type PromptPolicy = { mode: PolicyMode; githubPatMode?: DetectorMode; paymentCardMode?: DetectorMode; privateKeyMode?: DetectorMode;
  identifierProtection?: IdentifierProtection };
export type PromptMatch = { action: PolicyMode; reason: string } & RuleMetadata;

const severity: Record<PolicyMode, number> = { monitor: 1, warn: 2, block: 3 };
const classicGithubPat = /(?<![A-Za-z0-9_])ghp_[A-Za-z0-9]{36}(?![A-Za-z0-9_])/;
const allClassicGithubPats = new RegExp(classicGithubPat.source, 'g');
const redacted = '[REDACTED]';

export function isMode(value: unknown): value is PolicyMode {
  return value === 'monitor' || value === 'warn' || value === 'block';
}

export function isDetectorMode(value: unknown): value is DetectorMode {
  return value === 'off' || isMode(value);
}

export function readIdentifierProtection(value: unknown): IdentifierProtection | undefined {
  if (!value || typeof value !== 'object' || Object.keys(value).length !== 2 || !('mode' in value) || !('formats' in value) ||
      !isDetectorMode(value.mode)) return;
  const formats = readIdentifierFormats(value.formats);
  if (formats && (value.mode === 'off' || formats.length)) return { mode: value.mode, formats };
}

export function sameIdentifierProtection(left?: IdentifierProtection, right?: IdentifierProtection) {
  return left?.mode === right?.mode && sameIdentifierFormats(left?.formats ?? [], right?.formats ?? []);
}

export function evaluatePrompt(prompt: string, policy: PromptPolicy, except?: ReadonlySet<PromptRuleId>): { action: 'allow' } | PromptMatch {
  let match: PromptMatch | undefined = !except?.has(fixtureRule) && prompt.includes(testMarker) ? {
    action: policy.mode, ruleId: fixtureRule, detectorCategory: fixtureDetector,
    reason: 'This prompt contains a test secret.',
  } : undefined;
  const identifiers = policy.identifierProtection;
  if (!except?.has(identifierRule) && isMode(identifiers?.mode) && (!match || severity[identifiers.mode] >= severity[match.action]) &&
      containsIdentifier(prompt, identifiers.formats)) {
    match = {
      action: identifiers.mode, ruleId: identifierRule, detectorCategory: identifierDetector,
      reason: 'This prompt contains an organization identifier.',
    };
  }
  if (!except?.has(githubPatRule) && isMode(policy.githubPatMode) && (!match || severity[policy.githubPatMode] >= severity[match.action]) &&
      classicGithubPat.test(prompt)) {
    match = {
      action: policy.githubPatMode, ruleId: githubPatRule, detectorCategory: credentialDetector,
      reason: 'This prompt contains text that looks like a GitHub classic personal access token.',
    };
  }
  if (!except?.has(paymentCardRule) && isMode(policy.paymentCardMode) && (!match || severity[policy.paymentCardMode] >= severity[match.action]) &&
      containsPaymentCard(prompt)) {
    match = {
      action: policy.paymentCardMode, ruleId: paymentCardRule, detectorCategory: paymentDetector,
      reason: 'This prompt contains a possible payment card number.',
    };
  }
  if (!except?.has(privateKeyRule) && isMode(policy.privateKeyMode) && (!match || severity[policy.privateKeyMode] >= severity[match.action]) &&
      containsPrivateKey(prompt)) {
    return {
      action: policy.privateKeyMode, ruleId: privateKeyRule, detectorCategory: credentialDetector,
      reason: 'This prompt contains text that looks like a private key.',
    };
  }
  return match ?? { action: 'allow' };
}

export function redactPrompt(prompt: string, policy: PromptPolicy): string {
  const withoutPrivateKeys = isMode(policy.privateKeyMode) ? redactPrivateKeys(prompt, redacted) : prompt;
  const withoutMarkers = withoutPrivateKeys.replaceAll(testMarker, redacted);
  const withoutCredentials = isMode(policy.githubPatMode) ? withoutMarkers.replaceAll(allClassicGithubPats, redacted) : withoutMarkers;
  const withoutCards = isMode(policy.paymentCardMode) ? redactPaymentCards(withoutCredentials, redacted) : withoutCredentials;
  const identifiers = policy.identifierProtection;
  return isMode(identifiers?.mode) ? redactIdentifiers(withoutCards, identifiers.formats, redacted) : withoutCards;
}
