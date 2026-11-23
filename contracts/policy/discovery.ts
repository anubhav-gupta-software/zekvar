export const builtInDiscoveryApps = {
  'https://chatgpt.com': 'chatgpt',
  'https://claude.ai': 'claude',
  'https://gemini.google.com': 'gemini',
} as const;

export type BuiltInDiscoveryApp = typeof builtInDiscoveryApps[keyof typeof builtInDiscoveryApps];
export const discoveryPresets = {
  copilot: { name: 'Microsoft Copilot', hosts: ['copilot.microsoft.com', 'copilot.com'] },
  perplexity: { name: 'Perplexity', hosts: ['perplexity.ai', 'www.perplexity.ai'] },
  grok: { name: 'Grok', hosts: ['grok.com'] },
  'meta-ai': { name: 'Meta AI', hosts: ['meta.ai', 'www.meta.ai'] },
  deepseek: { name: 'DeepSeek', hosts: ['chat.deepseek.com'] },
} as const;
export type DiscoveryPreset = keyof typeof discoveryPresets;

export function isDiscoveryPreset(value: string): value is DiscoveryPreset {
  return Object.hasOwn(discoveryPresets, value);
}

const presetsByHost = new Map<string, DiscoveryPreset>();
for (const id of Object.keys(discoveryPresets).filter(isDiscoveryPreset)) {
  for (const host of discoveryPresets[id].hosts) presetsByHost.set(host, id);
}

export function discoveryPresetAt(host: string) {
  return presetsByHost.get(host);
}

export type CustomAppId = `saas:${string}`;
export type CustomAppSetting = { host: string; name: string };
export type CustomApp = CustomAppSetting & { id: CustomAppId };
export const customAppLimit = 25;
export const customAppError = `Enter up to ${customAppLimit} unique app domains and names. Use one exact hostname and name per line, separated by a comma.`;

const label = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
const topLevel = '[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?';
const hostPattern = new RegExp(`^(?:${label}\\.)+${topLevel}$`);
const controlCharacters = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/;

export function isCustomAppId(value: unknown): value is CustomAppId {
  return typeof value === 'string' && value.length === 69 && /^saas:[a-f0-9]+$/.test(value);
}

function normalizeCustomApp(host: string, displayName: string): CustomAppSetting | undefined {
  host = host.trim().toLowerCase().replace(/\.$/, '');
  const name = displayName.trim();
  if (!hostPattern.test(host) || host.length > 253 || Object.hasOwn(builtInDiscoveryApps, `https://${host}`) ||
      name.length < 2 || name.length > 64 || controlCharacters.test(name)) return;
  return { host, name };
}

export function parseCustomApps(text: string): CustomAppSetting[] | undefined {
  const lines = text.split(/\r?\n/).filter((line) => line.trim());
  if (lines.length > customAppLimit) return;
  const apps = new Map<string, CustomAppSetting>();
  for (const line of lines) {
    const separator = line.indexOf(',');
    if (separator < 0) return;
    const app = normalizeCustomApp(line.slice(0, separator), line.slice(separator + 1));
    if (!app || apps.has(app.host)) return;
    apps.set(app.host, app);
  }
  return [...apps.values()].sort((a, b) => a.host < b.host ? -1 : a.host > b.host ? 1 : 0);
}

export function readCustomApps(value: unknown): CustomApp[] | undefined {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > customAppLimit) return;
  const apps: CustomApp[] = [];
  const ids = new Set<CustomAppId>();
  for (const item of value) {
    if (!item || typeof item.host !== 'string' || typeof item.name !== 'string' || !isCustomAppId(item.id)) return;
    const app = normalizeCustomApp(item.host, item.name);
    if (!app || app.host !== item.host || app.name !== item.name || ids.has(item.id) ||
        (apps.length && apps.at(-1)!.host >= app.host)) return;
    ids.add(item.id);
    apps.push({ ...app, id: item.id });
  }
  return apps;
}

export function sameCustomApps(a: readonly CustomAppSetting[], b: readonly CustomAppSetting[]) {
  return a.length === b.length && a.every(({ host, name }, index) => host === b[index].host && name === b[index].name);
}
