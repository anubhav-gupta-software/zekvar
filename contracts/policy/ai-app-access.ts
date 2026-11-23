import { isCanonicalDomain } from './domains';

const presets = {
  'chatgpt.com': 'ChatGPT',
  'chat.openai.com': 'ChatGPT',
  'claude.ai': 'Claude',
  'gemini.google.com': 'Gemini',
  'copilot.microsoft.com': 'Microsoft Copilot',
  'copilot.com': 'Microsoft Copilot',
  'perplexity.ai': 'Perplexity',
  'www.perplexity.ai': 'Perplexity',
  'grok.com': 'Grok',
  'meta.ai': 'Meta AI',
  'www.meta.ai': 'Meta AI',
  'chat.deepseek.com': 'DeepSeek',
} as const;

export function aiAppAccessCatalog(customApps: readonly { host: string; name: string }[]) {
  return [...Object.entries(presets).map(([host, name]) => ({ host, name })),
    ...customApps.filter(({ host }) => !Object.hasOwn(presets, host))];
}

export function readBlockedAiAppHosts(value: unknown) {
  if (!Array.isArray(value) || value.length > 50 || !value.every(isCanonicalDomain) || new Set(value).size !== value.length) return;
  return [...value].sort();
}

export function blockedAiAppAt(url: URL, hosts: readonly string[]) {
  const host = url.hostname.toLowerCase().replace(/\.$/, '');
  return (url.protocol === 'http:' || url.protocol === 'https:') && hosts.includes(host) ? host : undefined;
}

export function aiAppBlockPattern(host: string) {
  return '^https?://(?:[^/?#]*@)?' + host.replaceAll('.', '\\.') + '\\.?(?::[0-9]+)?(?:[/?#]|$)';
}
