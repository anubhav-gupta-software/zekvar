const safeBrowsingModes = { preserve: 'Preserve existing', standard: 'At least Standard protection', enhanced: 'Enhanced protection' } as const;
const downloadModes = {
  preserve: 'Preserve existing', malicious: 'Block malicious files', dangerous: 'Block malicious and dangerous files',
  'potentially-dangerous': 'Also block uncommon or unwanted files', all: 'Block all supported downloads',
} as const;

function restriction(label: string, active: string, native: string, value: boolean | number) {
  return { label, options: { preserve: 'Preserve existing', restrict: active }, native, value };
}

const restrictions = {
  lockSafeBrowsingWarnings: restriction('Safe Browsing warning bypass', 'Prevent proceeding', 'DisableSafeBrowsingProceedAnyway', true),
  disableGuest: restriction('Guest profiles', 'Disable Guest mode', 'BrowserGuestModeEnabled', false),
  disableIncognito: restriction('Incognito windows', 'Disable Incognito', 'IncognitoModeAvailability', 1),
  disablePasswordSaving: restriction('Chrome password saving', 'Disable password saving', 'PasswordManagerEnabled', false),
  disableSync: restriction('Chrome Sync', 'Disable Sync', 'SyncDisabled', true),
};

type Restriction = keyof typeof restrictions;
export type BrowserHardening = Record<Restriction, boolean> & {
  safeBrowsing: keyof typeof safeBrowsingModes; downloads: keyof typeof downloadModes;
};

export const emptyHardening: BrowserHardening = {
  safeBrowsing: 'preserve', downloads: 'preserve', lockSafeBrowsingWarnings: false, disableGuest: false,
  disableIncognito: false, disablePasswordSaving: false, disableSync: false,
};

export const hardeningFields: Record<keyof BrowserHardening, { label: string; options: Readonly<Record<string, string>> }> = {
  safeBrowsing: { label: 'Safe Browsing protection', options: safeBrowsingModes },
  downloads: { label: 'Download restrictions', options: downloadModes },
  ...restrictions,
};

const hardeningKeys = Object.keys(emptyHardening) as (keyof BrowserHardening)[];

export function hardeningValue(value: string | boolean) {
  return typeof value === 'boolean' ? value ? 'restrict' : 'preserve' : value;
}

export function parseBrowserHardening(form: FormData): BrowserHardening | undefined {
  const values = new Map(hardeningKeys.map((key) => [key, form.get(key)]));
  if (hardeningKeys.some((key) => {
    const value = values.get(key);
    return typeof value !== 'string' || !Object.hasOwn(hardeningFields[key].options, value);
  })) return;
  return Object.fromEntries(hardeningKeys.map((key) => {
    const value = values.get(key);
    return [key, typeof emptyHardening[key] === 'boolean' ? value === 'restrict' : value];
  })) as BrowserHardening;
}

export function hardeningDifferences(reference = emptyHardening, candidate = emptyHardening) {
  return hardeningKeys.filter((key) => reference[key] !== candidate[key]).map((key) => {
    const { label, options } = hardeningFields[key];
    return { key, label, before: options[hardeningValue(reference[key])], after: options[hardeningValue(candidate[key])] };
  });
}

type NativePolicy = Record<string, unknown>;
type NativeValue = boolean | number;
export type HardeningExport = {
  merged: string; rollback: string;
  changes: { policy: string; before?: NativeValue; after: NativeValue }[];
};

const safeBrowsingLevels = { standard: 1, enhanced: 2 } as const;
const downloadLevels = { malicious: 4, dangerous: 1, 'potentially-dangerous': 2, all: 3 } as const;
// Chrome's numerical download values are not ordered by restrictiveness.
const downloadSeverity = [0, 4, 1, 2, 3];
const isObject = (input: unknown): input is NativePolicy => typeof input === 'object' && input !== null && !Array.isArray(input);

export function mergeBrowserHardening(plan: BrowserHardening, input: string): { error: string } | { result: HardeningExport } {
  let original: unknown;
  try { if (input.length <= 256_000) original = JSON.parse(input); } catch { /* Report an input error below. */ }
  if (!isObject(original) || Object.hasOwn(original, 'policyValues') || Object.hasOwn(original, 'chromeMetadata')) {
    return { error: 'Enter a flat Chrome policy JSON object from your device manager. Use {} for a new policy.' };
  }

  const safeBrowsing = original.SafeBrowsingProtectionLevel;
  const downloads = original.DownloadRestrictions;
  if (plan.disableGuest && original.BrowserGuestModeEnforced === true) {
    return { error: 'Resolve BrowserGuestModeEnforced in the device manager before disabling Guest mode.' };
  }
  if (plan.disableIncognito && (original.IncognitoModeAvailability === 2 ||
      (Object.hasOwn(original, 'IncognitoModeUrlAllowlist') &&
        !(Array.isArray(original.IncognitoModeUrlAllowlist) && original.IncognitoModeUrlAllowlist.length === 0)))) {
    return { error: 'Resolve forced Incognito or the Incognito URL allowlist in the device manager before disabling Incognito.' };
  }
  if (plan.safeBrowsing !== 'preserve' && safeBrowsing !== undefined && safeBrowsing !== 0 && safeBrowsing !== 1 && safeBrowsing !== 2) {
    return { error: 'Resolve the unsupported existing value for SafeBrowsingProtectionLevel.' };
  }
  const downloadRank = typeof downloads === 'number' ? downloadSeverity.indexOf(downloads) : -1;
  if (plan.downloads !== 'preserve' && downloads !== undefined && downloadRank < 0) {
    return { error: 'Resolve the unsupported existing value for DownloadRestrictions.' };
  }
  const usesVerdicts = plan.lockSafeBrowsingWarnings || (plan.downloads !== 'preserve' && plan.downloads !== 'all');
  if (usesVerdicts && plan.safeBrowsing === 'preserve' &&
      (safeBrowsing === 0 || (safeBrowsing === undefined && original.SafeBrowsingEnabled === false))) {
    return { error: 'The existing policy disables Safe Browsing. Publish a Safe Browsing level or resolve the device-manager setting.' };
  }

  const selected: Record<string, NativeValue> = {};
  if (plan.safeBrowsing !== 'preserve') {
    selected.SafeBrowsingProtectionLevel = Math.max(typeof safeBrowsing === 'number' ? safeBrowsing : 0, safeBrowsingLevels[plan.safeBrowsing]);
  }
  if (plan.downloads !== 'preserve') {
    selected.DownloadRestrictions = downloadSeverity[Math.max(downloadRank, downloadSeverity.indexOf(downloadLevels[plan.downloads]))];
  }
  for (const key of Object.keys(restrictions) as Restriction[]) {
    const { native, value } = restrictions[key];
    if (plan[key]) selected[native] = value;
  }
  const changes: HardeningExport['changes'] = [];
  for (const [policy, after] of Object.entries(selected)) {
    const before = original[policy];
    if (before !== undefined && (typeof before !== typeof after ||
        (policy === 'IncognitoModeAvailability' && before !== 0 && before !== 1))) {
      return { error: `Resolve the unsupported existing value for ${policy}.` };
    }
    if (before !== after) changes.push({ policy, before: before as NativeValue | undefined, after });
  }
  try {
    const merged = JSON.stringify({ ...original, ...selected }, null, 2) + '\n';
    return { result: { merged, rollback: input, changes } };
  } catch {
    return { error: 'The existing Chrome policy is nested too deeply to export.' };
  }
}
