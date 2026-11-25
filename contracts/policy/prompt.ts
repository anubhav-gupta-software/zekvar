import { containsPaymentCard, redactPaymentCards } from './payment-card';
import { containsPrivateKey, redactPrivateKeys } from './private-key';
import { containsIdentifier, readIdentifierFormats, redactIdentifiers, sameIdentifierFormats, type IdentifierFormat } from './organization-identifiers';
import { containsSsn, redactSsns } from './social-security-number';
import { containsGithubToken, redactGithubTokens } from './github-token';
import { cloudCredentialLabels, findCloudCredential, redactCloudCredentials, type CloudCredentialRule } from './cloud-credentials';
import { containsClassificationTerm, readClassificationTerms, redactClassificationTerms, sameClassificationTerms } from './classification';

export const modes = ['monitor', 'warn', 'block'] as const;
export type PolicyMode = typeof modes[number];
export const detectorModes = ['off', ...modes] as const;
export type DetectorMode = typeof detectorModes[number];

export const fixtureRule = 'fixture-secret';
export const fixtureDetector = 'synthetic-secret';
export const githubPatRule = 'github-classic-pat';
export const githubTokenRule = 'github-app-or-fine-grained-token';
export const credentialDetector = 'credential';
export const paymentCardRule = 'payment-card-number';
export const paymentDetector = 'payment-card';
export const privateKeyRule = 'pem-private-key';
export const identifierRule = 'organization-identifier';
export const identifierDetector = 'internal-identifier';
export const ssnRule = 'us-social-security-number';
export const ssnDetector = 'government-identifier';
export const classificationRule = 'organization-classification-rule';
export const classificationDetector = 'classification';
export const testMarker = 'ZEKVAR_TEST_SECRET';
export const ruleLabels = {
  [fixtureRule]: 'Synthetic secret', [githubPatRule]: 'GitHub classic PAT', [paymentCardRule]: 'Payment card number',
  [githubTokenRule]: 'GitHub App, OAuth, or fine-grained token',
  [privateKeyRule]: 'Private key',
  [identifierRule]: 'Organization identifier',
  [ssnRule]: 'U.S. Social Security number',
} as const;
// Cloud credential and classification rules support Monitor, Warn, and Block but not temporary prompt exceptions.
export const detectionRuleLabels = {
  ...ruleLabels, ...cloudCredentialLabels, [classificationRule]: 'Organization classification rule',
} as const;

export type RuleMetadata = { ruleId: typeof fixtureRule; detectorCategory: typeof fixtureDetector } |
  { ruleId: typeof githubPatRule | typeof githubTokenRule; detectorCategory: typeof credentialDetector } |
  { ruleId: typeof paymentCardRule; detectorCategory: typeof paymentDetector } |
  { ruleId: typeof privateKeyRule; detectorCategory: typeof credentialDetector } |
  { ruleId: typeof identifierRule; detectorCategory: typeof identifierDetector } |
  { ruleId: typeof ssnRule; detectorCategory: typeof ssnDetector } |
  { ruleId: CloudCredentialRule; detectorCategory: typeof credentialDetector } |
  { ruleId: typeof classificationRule; detectorCategory: typeof classificationDetector };
export type PromptRuleId = RuleMetadata['ruleId'];
export type ExceptionRuleId = keyof typeof ruleLabels;
export type IdentifierProtection = { mode: DetectorMode; formats: IdentifierFormat[] };
export type ClassificationProtection = { mode: DetectorMode; terms: string[] };
export type PromptPolicy = { mode: PolicyMode; githubPatMode?: DetectorMode; paymentCardMode?: DetectorMode; privateKeyMode?: DetectorMode;
  identifierProtection?: IdentifierProtection; ssnMode?: DetectorMode; githubTokenMode?: DetectorMode;
  cloudCredentialMode?: DetectorMode; classificationProtection?: ClassificationProtection };
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

export function readClassificationProtection(value: unknown): ClassificationProtection | undefined {
  if (!value || typeof value !== 'object' || Object.keys(value).length !== 2 || !('mode' in value) || !('terms' in value) ||
      !isDetectorMode(value.mode)) return;
  const terms = readClassificationTerms(value.terms);
  if (terms && (value.mode === 'off' || terms.length)) return { mode: value.mode, terms };
}

export function sameClassificationProtection(left?: ClassificationProtection, right?: ClassificationProtection) {
  return left?.mode === right?.mode && sameClassificationTerms(left?.terms ?? [], right?.terms ?? []);
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
  const classification = policy.classificationProtection;
  if (!except?.has(classificationRule) && isMode(classification?.mode) && (!match || severity[classification.mode] >= severity[match.action]) &&
      containsClassificationTerm(prompt, classification.terms)) {
    match = { action: classification.mode, ruleId: classificationRule, detectorCategory: classificationDetector,
      reason: 'This prompt contains a label or phrase your organization classifies as sensitive.' };
  }
  if (!except?.has(githubPatRule) && isMode(policy.githubPatMode) && (!match || severity[policy.githubPatMode] >= severity[match.action]) &&
      classicGithubPat.test(prompt)) {
    match = {
      action: policy.githubPatMode, ruleId: githubPatRule, detectorCategory: credentialDetector,
      reason: 'This prompt contains text that looks like a GitHub classic personal access token.',
    };
  }
  if (!except?.has(githubTokenRule) && isMode(policy.githubTokenMode) && (!match || severity[policy.githubTokenMode] >= severity[match.action]) &&
      containsGithubToken(prompt)) {
    match = { action: policy.githubTokenMode, ruleId: githubTokenRule, detectorCategory: credentialDetector,
      reason: 'This prompt contains text that looks like a GitHub App, OAuth, or fine-grained token.' };
  }
  if (isMode(policy.cloudCredentialMode) && (!match || severity[policy.cloudCredentialMode] >= severity[match.action])) {
    const rule = findCloudCredential(prompt);
    if (rule && !except?.has(rule)) {
      match = { action: policy.cloudCredentialMode, ruleId: rule, detectorCategory: credentialDetector,
        reason: `This prompt contains text that looks like ${article(cloudCredentialLabels[rule])}.` };
    }
  }
  if (!except?.has(ssnRule) && isMode(policy.ssnMode) && (!match || severity[policy.ssnMode] >= severity[match.action]) && containsSsn(prompt)) {
    match = { action: policy.ssnMode, ruleId: ssnRule, detectorCategory: ssnDetector,
      reason: 'This prompt contains a possible U.S. Social Security number.' };
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
  const withoutGithubTokens = isMode(policy.githubTokenMode) ? redactGithubTokens(withoutCredentials, redacted) : withoutCredentials;
  const withoutCloud = isMode(policy.cloudCredentialMode) ? redactCloudCredentials(withoutGithubTokens, redacted) : withoutGithubTokens;
  const withoutCards = isMode(policy.paymentCardMode) ? redactPaymentCards(withoutCloud, redacted) : withoutCloud;
  const withoutSsns = isMode(policy.ssnMode) ? redactSsns(withoutCards, redacted) : withoutCards;
  const identifiers = policy.identifierProtection;
  const withoutIdentifiers = isMode(identifiers?.mode) ? redactIdentifiers(withoutSsns, identifiers.formats, redacted) : withoutSsns;
  const classification = policy.classificationProtection;
  return isMode(classification?.mode) ? redactClassificationTerms(withoutIdentifiers, classification.terms, redacted) : withoutIdentifiers;
}

function article(label: string) {
  return `${/^[AEIOU]/.test(label) ? 'an' : 'a'} ${label}`;
}
