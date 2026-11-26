import { aiPromptApps, type AiPromptApp } from './apps';

// An administrator switch for a broken adapter. "adapter" stops all Browser interception on that app.
// "attachments" stops only file intake checks. "open" leaves the app usable without that protection;
// "closed" also blocks the app's hosts through the AI app access host block.
export const adapterScopes = ['adapter', 'attachments'] as const;
export const adapterFallbacks = ['open', 'closed'] as const;
export type AdapterScope = typeof adapterScopes[number];
export type AdapterFallback = typeof adapterFallbacks[number];
export type AdapterControl = { scope: AdapterScope; fallback: AdapterFallback };
export type AdapterControls = Partial<Record<AiPromptApp, AdapterControl>>;

export const adapterHosts: Record<AiPromptApp, readonly string[]> = {
  chatgpt: ['chat.openai.com', 'chatgpt.com'],
  claude: ['claude.ai'],
  gemini: ['gemini.google.com'],
};

export const adapterScopeLabels: Record<AdapterScope, string> = {
  adapter: 'Whole adapter disabled', attachments: 'Attachments disabled',
};
export const adapterFallbackLabels: Record<AdapterFallback, string> = {
  open: 'Fail open (app stays usable)', closed: 'Fail closed (block the app)',
};

function readControl(value: unknown): AdapterControl | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return;
  const { scope, fallback, ...rest } = value as Record<string, unknown>;
  const knownScope = adapterScopes.find((entry) => entry === scope);
  const knownFallback = adapterFallbacks.find((entry) => entry === fallback);
  if (!knownScope || !knownFallback || Object.keys(rest).length) return;
  return { scope: knownScope, fallback: knownFallback };
}

export function readAdapterControls(value: unknown): AdapterControls | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return;
  const controls: AdapterControls = {};
  for (const [app, entry] of Object.entries(value)) {
    const id = aiPromptApps.find((candidate) => candidate === app);
    if (entry === null && id) continue;
    const control = readControl(entry);
    if (!id || !control) return;
    controls[id] = control;
  }
  return controls;
}

export function sameAdapterControls(left?: AdapterControls, right?: AdapterControls) {
  return aiPromptApps.every((app) => left?.[app]?.scope === right?.[app]?.scope && left?.[app]?.fallback === right?.[app]?.fallback);
}

export function hasAdapterControls(controls?: AdapterControls) {
  return aiPromptApps.some((app) => controls?.[app]);
}

export function adapterDisabled(controls: AdapterControls | undefined, app: AiPromptApp) {
  return controls?.[app]?.scope === 'adapter';
}

export function attachmentsDisabled(controls: AdapterControls | undefined, app: AiPromptApp) {
  return controls?.[app] !== undefined;
}

export function failClosedHosts(controls: AdapterControls | undefined) {
  return aiPromptApps.filter((app) => controls?.[app]?.fallback === 'closed').flatMap((app) => adapterHosts[app]);
}
