type ExtensionMode = 'allow' | 'block' | 'force';
export type ExtensionRule = { id: string; mode: ExtensionMode; updateUrl?: string };
export type ExtensionDeployment = { unlisted: 'preserve' | 'block'; rules: ExtensionRule[] };
const empty: ExtensionDeployment = { unlisted: 'preserve', rules: [] };
const nativeModes = { allow: 'allowed', block: 'blocked', force: 'force_installed' } as const;
export const extensionModeLabels = { allow: 'Allow', block: 'Block', force: 'Force install' } as const;
export const unlistedLabels = { preserve: 'Keep existing default', block: 'Block unlisted' } as const;

const extensionId = /^[a-p]{32}$/;
function validUpdateUrl(value: string) {
  if (value.length > 512 || !/^https:\/\/[^/@%]+(?:\/|$)/i.test(value) || !/^[!-~]+$/.test(value) || /[\\?#"<>]/.test(value)) return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'https:' && !parsed.username && !parsed.password;
  } catch {
    return false;
  }
}

export function parseExtensionDeployment(unlisted: unknown, input: unknown): { error: string } | { deployment: ExtensionDeployment } {
  if ((unlisted !== 'preserve' && unlisted !== 'block') || typeof input !== 'string' || input.length > 60_000) {
    return { error: 'Choose an unlisted setting and enter at most 100 rules.' } as const;
  }
  const rules: ExtensionRule[] = [];
  const seen = new Set<string>();
  const lines = input.split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    if (!line.trim()) continue;
    const fields = line.split(',').map((field) => field.trim());
    const [id, mode, ...urlFields] = fields;
    const updateUrl = urlFields.join(',');
    if (!extensionId.test(id) || (mode !== 'allow' && mode !== 'block' && mode !== 'force') ||
        (mode === 'force' ? !validUpdateUrl(updateUrl) : fields.length !== 2)) {
      return { error: `Line ${index + 1} needs a Chrome extension ID and allow, block, or force with an HTTPS update manifest URL.` } as const;
    }
    if (seen.has(id)) return { error: `Line ${index + 1} repeats an extension ID.` } as const;
    if (rules.length === 100) return { error: 'Enter at most 100 rules.' } as const;
    seen.add(id);
    rules.push({ id, mode, ...(updateUrl && { updateUrl }) });
  }
  if (rules.reduce((total, rule) => total + (rule.updateUrl?.length ?? 0), 0) > 7_000) {
    return { error: 'Use at most 7,000 characters across update manifest URLs.' };
  }
  rules.sort((a, b) => a.id.localeCompare(b.id, 'en'));
  return { deployment: { unlisted, rules } satisfies ExtensionDeployment } as const;
}

export function extensionRuleText(plan: ExtensionDeployment) {
  return plan.rules.map(({ id, mode, updateUrl }) => [id, mode, ...(updateUrl ? [updateUrl] : [])].join(', ')).join('\n');
}

export function extensionDeploymentChanges(reference = empty, candidate = empty) {
  const before = new Map(reference.rules.map((rule) => [rule.id, rule]));
  const after = new Map(candidate.rules.map((rule) => [rule.id, rule]));
  return Array.from(new Set([...before.keys(), ...after.keys()])).sort().flatMap((id) => {
    const prior = before.get(id);
    const next = after.get(id);
    return prior?.mode === next?.mode && prior?.updateUrl === next?.updateUrl ? [] : [{ id, prior, next }];
  });
}

export function sameExtensionDeployment(reference = empty, candidate = empty) {
  return reference.unlisted === candidate.unlisted && extensionDeploymentChanges(reference, candidate).length === 0;
}

type Settings = Record<string, unknown>;
type ChromeSettings = Record<string, Settings>;
export type DeploymentExport = {
  original: ChromeSettings; merged: ChromeSettings; changes: { id: string; before: string; after: string }[];
};
const isObject = (value: unknown): value is Settings => typeof value === 'object' && value !== null && !Array.isArray(value);
const inheritedFields = ['blocked_permissions', 'runtime_allowed_hosts', 'runtime_blocked_hosts', 'blocked_install_message'];

function parseChromeSettings(text: string) {
  if (text.length > 256_000) return;
  try {
    const input: unknown = JSON.parse(text);
    if (!isObject(input)) return;
    const value = Object.keys(input).length === 1 && Object.hasOwn(input, 'ExtensionSettings') ? input.ExtensionSettings : input;
    if (!isObject(value)) return;
    const original: ChromeSettings = Object.create(null);
    const perId = new Map<string, Settings>();
    for (const [key, settings] of Object.entries(value)) {
      if (!isObject(settings) || (settings.installation_mode !== undefined &&
          (typeof settings.installation_mode !== 'string' ||
            !['allowed', 'blocked', 'removed', 'normal_installed', 'force_installed'].includes(settings.installation_mode)))) return;
      if (key !== '*' && !/^update_url:https?:\/\/.+/.test(key)) {
        const ids = key.replace(/,$/, '').split(',');
        if (ids.some((id) => !extensionId.test(id) || perId.has(id))) return;
        for (const id of ids) perId.set(id, settings);
      }
      original[key] = settings;
    }
    return { original, perId };
  } catch {
    return;
  }
}

function nativeSummary(settings?: Settings) {
  const mode = typeof settings?.installation_mode === 'string' ? settings.installation_mode.replaceAll('_', ' ') : 'existing default';
  return settings?.update_url && typeof settings.update_url === 'string' ? `${mode} · ${settings.update_url}` : mode;
}

export function mergeExtensionDeployment(plan: ExtensionDeployment, base: string, protectedId: string): { error: string } | { result: DeploymentExport } {
  const input = parseChromeSettings(base);
  if (!input) return { error: 'Enter the Chrome ExtensionSettings dictionary with valid, non-overlapping selectors.' } as const;
  const { original, perId } = input;
  if (protectedId && !extensionId.test(protectedId)) return { error: 'Enter the pinned Zekvar Browser extension ID.' } as const;
  if (plan.rules.some(({ id }) => id === protectedId)) {
    return { error: 'Remove the pinned Zekvar Browser ID from the deployment rules to keep its existing settings.' } as const;
  }
  const protectedSettings = perId.get(protectedId);
  if (plan.unlisted === 'block' && (protectedSettings?.installation_mode !== 'force_installed' ||
      typeof protectedSettings.update_url !== 'string' || !validUpdateUrl(protectedSettings.update_url))) {
    return { error: 'To block unlisted extensions, enter the pinned Zekvar Browser ID and keep its force-install rule in the original Chrome policy.' } as const;
  }
  const changes: DeploymentExport['changes'] = [];
  const replacements = new Map<string, Settings>();
  const inherited = Object.fromEntries(inheritedFields.filter((key) => Object.hasOwn(original['*'] ?? {}, key))
    .map((key) => [key, original['*'][key]]));
  for (const { id, mode, updateUrl } of plan.rules) {
    const before = perId.get(id);
    const { update_url: _url, override_update_url: _override, ...other } = before ?? inherited;
    const after = { ...other, installation_mode: nativeModes[mode],
      ...(mode === 'force' && { update_url: updateUrl, override_update_url: true }) };
    if (before?.installation_mode === after.installation_mode && before?.update_url === after.update_url &&
        before?.override_update_url === after.override_update_url) continue;
    replacements.set(id, after);
    changes.push({ id, before: nativeSummary(before ?? original['*']), after: nativeSummary(after) });
  }
  const untouched = Object.entries(original).flatMap(([key, settings]) => {
    if (key === '*' || key.startsWith('update_url:')) return [[key, settings]] as const;
    const members = key.replace(/,$/, '').split(',');
    const retained = members.filter((id) => !replacements.has(id));
    if (retained.length === members.length) return [[key, settings]] as const;
    return retained.length ? [[retained.join(','), settings]] as const : [];
  });
  const merged = Object.fromEntries([...untouched, ...replacements]);
  if (plan.unlisted === 'block' && original['*']?.installation_mode !== 'blocked') {
    merged['*'] = { ...original['*'], installation_mode: 'blocked' };
    changes.unshift({ id: '*', before: nativeSummary(original['*']), after: nativeSummary(merged['*']) });
  }
  return { result: { original, merged, changes } satisfies DeploymentExport } as const;
}
