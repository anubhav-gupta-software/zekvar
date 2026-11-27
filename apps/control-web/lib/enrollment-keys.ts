export type EnrollmentKeyStatus = 'active' | 'exhausted' | 'expired' | 'revoked';

export type EnrollmentKey = {
  id: string;
  label: string;
  groupId: string | null;
  groupName: string | null;
  createdAt: string;
  expiresAt: string;
  maxRedemptions: number | null;
  redeemed: number;
  activeInstallations: number;
  lastRedeemedAt: string | null;
  rejected: number;
  lastRejectedAt: string | null;
  revokedAt: string | null;
  rotatedFrom: string | null;
  status: EnrollmentKeyStatus;
};

export type IssuedEnrollmentKey = { key: EnrollmentKey; token: string };

export type EnrollmentKeyChange = {
  keyId: string; label: string; groupId?: string; groupName?: string; expiresAt?: string; maxRedemptions?: number; redeemed?: number;
  rotatedFrom?: string; previousKeyExpiresAt?: string;
};

export const maxKeyDays = 30;
export const maxKeyRedemptions = 100_000;
export const enrollmentKeyPattern = /^zke_[a-f0-9]{64}$/;

export const keyStatusLabels: Record<EnrollmentKeyStatus, string> = {
  active: 'Active', exhausted: 'Limit reached', expired: 'Expired', revoked: 'Revoked',
};

// A key that can still enroll and is close to its limit, unlimited, or rejecting attempts deserves a second look.
export function keyAttention(key: EnrollmentKey): string | undefined {
  if (key.status !== 'active') return;
  if (key.maxRedemptions === null) return 'No redemption limit';
  if (key.redeemed >= key.maxRedemptions * 0.8) return `${key.maxRedemptions - key.redeemed} enrollments left`;
  if (key.rejected > 0) return `${key.rejected} rejected ${key.rejected === 1 ? 'attempt' : 'attempts'}`;
}

export type SnippetInput = { extensionId: string; updateUrl: string; controlOrigin: string; key: string };
export type SnippetError = 'extensionId' | 'updateUrl' | 'controlOrigin' | 'key';

export function snippetErrors(input: SnippetInput): SnippetError[] {
  const errors: SnippetError[] = [];
  if (!/^[a-p]{32}$/.test(input.extensionId)) errors.push('extensionId');
  if (!httpsUrl(input.updateUrl)) errors.push('updateUrl');
  if (!controlOrigin(input.controlOrigin)) errors.push('controlOrigin');
  if (!enrollmentKeyPattern.test(input.key)) errors.push('key');
  return errors;
}

function httpsUrl(value: string) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password;
  } catch { return false; }
}

// The hosted build uses an HTTPS origin. The local demo build talks to loopback over HTTP.
function controlOrigin(value: string) {
  try {
    const url = new URL(value);
    return url.origin === value && (url.protocol === 'https:' || (url.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(url.hostname)));
  } catch { return false; }
}

const xml = (value: string) => value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const powershell = (value: string) => `'${value.replace(/'/g, "''")}'`;

export type PolicySnippet = { id: string; title: string; target: string; steps: string; content: string };

export function policySnippets(input: SnippetInput): PolicySnippet[] {
  const { extensionId, updateUrl, controlOrigin: origin, key } = input;
  const install = { installation_mode: 'force_installed', update_url: updateUrl, override_update_url: true };
  const managed = { ControlOrigin: origin, EnrollmentKey: key };
  const extensionSettings = { [extensionId]: install };
  const chrome = JSON.stringify({ ExtensionSettings: extensionSettings, '3rdparty': { extensions: { [extensionId]: managed } } }, null, 2);
  const googleAdmin = JSON.stringify({ ControlOrigin: { Value: origin }, EnrollmentKey: { Value: key } }, null, 2);
  const omaUri = JSON.stringify([{
    name: 'Zekvar Browser force install', dataType: 'String',
    omaUri: './Device/Vendor/MSFT/Policy/Config/Chrome~Policy~googlechrome~Extensions/ExtensionSettings',
    value: `<enabled/><data id="ExtensionSettings" value="${xml(JSON.stringify(extensionSettings))}"/>`,
  }], null, 2);
  const registry = `HKLM:\\SOFTWARE\\Policies\\Google\\Chrome\\3rdparty\\extensions\\${extensionId}\\policy`;
  const intuneScript = [
    `$path = ${powershell(registry)}`,
    'New-Item -Path $path -Force | Out-Null',
    `New-ItemProperty -Path $path -Name 'ControlOrigin' -PropertyType String -Value ${powershell(origin)} -Force | Out-Null`,
    `New-ItemProperty -Path $path -Name 'EnrollmentKey' -PropertyType String -Value ${powershell(key)} -Force | Out-Null`,
  ].join('\n');
  const plist = (body: string) => `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
${body}
</dict>
</plist>`;
  const jamfChrome = plist(`  <key>ExtensionSettings</key>
  <dict>
    <key>${xml(extensionId)}</key>
    <dict>
      <key>installation_mode</key><string>force_installed</string>
      <key>update_url</key><string>${xml(updateUrl)}</string>
      <key>override_update_url</key><true/>
    </dict>
  </dict>`);
  const jamfExtension = plist(`  <key>ControlOrigin</key><string>${xml(origin)}</string>
  <key>EnrollmentKey</key><string>${xml(key)}</string>`);
  return [
    { id: 'google-admin', title: 'Google Admin console', target: 'Chrome browser › Apps & extensions › Policy for extensions',
      steps: `Add ${extensionId} by ID with the custom update URL ${updateUrl}, set it to Force install for the organizational unit, then paste this JSON.`,
      content: googleAdmin },
    { id: 'intune-windows', title: 'Microsoft Intune · Windows', target: 'Custom profile (ADMX-backed Chrome policy) and a platform script',
      steps: 'Add the OMA-URI row to a custom configuration profile that has the Chrome ADMX ingested, then run the script as a device platform script for the managed storage values.',
      content: `${omaUri}\n\n# Managed storage for the extension (run as system)\n${intuneScript}` },
    { id: 'jamf', title: 'Jamf Pro · macOS', target: 'Application & Custom Settings › two preference domains',
      steps: `Upload the first plist for com.google.Chrome and the second for com.google.Chrome.extensions.${extensionId}. Scope both to the same devices.`,
      content: `<!-- Preference domain: com.google.Chrome -->\n${jamfChrome}\n\n<!-- Preference domain: com.google.Chrome.extensions.${extensionId} -->\n${jamfExtension}` },
    { id: 'chrome-json', title: 'Chrome policy JSON · Linux and Group Policy', target: 'Managed policy directory or chrome-policy.json merge',
      steps: 'Merge this into the device group policy. Keep any existing ExtensionSettings entries.',
      content: chrome },
  ];
}
