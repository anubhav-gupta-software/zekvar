// Structural checks only. Zekvar never contacts a provider to validate a credential.
export const awsAccessKeyRule = 'aws-access-key-id';
export const slackTokenRule = 'slack-token';
export const stripeSecretKeyRule = 'stripe-live-secret-key';
export const googleApiKeyRule = 'google-api-key';
export const openAiApiKeyRule = 'openai-api-key';
export const anthropicApiKeyRule = 'anthropic-api-key';
export const cloudCredentialRules = [awsAccessKeyRule, slackTokenRule, stripeSecretKeyRule, googleApiKeyRule,
  openAiApiKeyRule, anthropicApiKeyRule] as const;
export type CloudCredentialRule = typeof cloudCredentialRules[number];
export const cloudCredentialLabels: Record<CloudCredentialRule, string> = {
  [awsAccessKeyRule]: 'AWS access key ID',
  [slackTokenRule]: 'Slack token',
  [stripeSecretKeyRule]: 'Stripe live secret or restricted key',
  [googleApiKeyRule]: 'Google API key',
  [openAiApiKeyRule]: 'OpenAI API key',
  [anthropicApiKeyRule]: 'Anthropic API key',
};

type Shape = { rule: CloudCredentialRule; source: string; body: (match: string) => string; minDistinct: number; accept?: (match: string) => boolean };
// OpenAI embeds this fixed marker in its keys. It is split here so source scanners do not mistake the pattern for a key.
const openAiMarker = 'T3Blbk' + 'FJ';
const before = '(?<![\\p{L}\\p{N}\\p{M}\\p{Pc}-])';
const after = '(?![\\p{L}\\p{N}\\p{M}\\p{Pc}-])';
// Key bodies are random. Repeated or patterned placeholders such as XXXX… or 0000… are documentation, not credentials.
const shapes: Shape[] = [
  { rule: awsAccessKeyRule, source: '(?:AKIA|ASIA)[A-Z2-7]{16}', body: (match) => match.slice(4), minDistinct: 8,
    accept: (match) => !match.endsWith('EXAMPLE') },
  { rule: slackTokenRule, source: 'xox[abpr]-(?:[0-9]{1,13}-){1,3}[A-Za-z0-9]{24,64}', body: (match) => match.slice(match.lastIndexOf('-') + 1),
    minDistinct: 10 },
  { rule: stripeSecretKeyRule, source: '[rs]k_live_[A-Za-z0-9]{24,247}', body: (match) => match.slice(8), minDistinct: 10 },
  { rule: googleApiKeyRule, source: 'AIza[0-9A-Za-z_-]{35}', body: (match) => match.slice(4), minDistinct: 12 },
  { rule: openAiApiKeyRule, source: `sk-(?:(?:proj|svcacct|admin)-)?[A-Za-z0-9_-]{20,200}${openAiMarker}[A-Za-z0-9_-]{20,200}`,
    body: (match) => match.replace(/^sk-(?:(?:proj|svcacct|admin)-)?/, '').replace(openAiMarker, ''), minDistinct: 12 },
  { rule: anthropicApiKeyRule, source: 'sk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{93}AA', body: (match) => match.slice(match.indexOf('-', 7) + 1, -2),
    minDistinct: 16 },
];
const compiled = shapes.map((shape) => ({ ...shape, pattern: new RegExp(`${before}${shape.source}${after}`, 'gu') }));
const prefilter = /AKIA|ASIA|xox[abpr]-|k_live_|AIza|sk-/;

function plausible(shape: Shape, match: string) {
  return new Set(shape.body(match)).size >= shape.minDistinct && (shape.accept?.(match) ?? true);
}

export function findCloudCredential(text: string): CloudCredentialRule | undefined {
  if (!prefilter.test(text)) return;
  let found: { rule: CloudCredentialRule; index: number } | undefined;
  for (const shape of compiled) {
    for (const match of text.matchAll(shape.pattern)) {
      if (!plausible(shape, match[0])) continue;
      if (!found || match.index < found.index) found = { rule: shape.rule, index: match.index };
      break;
    }
  }
  return found?.rule;
}

export function redactCloudCredentials(text: string, replacement: string) {
  if (!prefilter.test(text)) return text;
  return compiled.reduce((value, shape) => value.replace(shape.pattern, (match) => plausible(shape, match) ? replacement : match), text);
}
