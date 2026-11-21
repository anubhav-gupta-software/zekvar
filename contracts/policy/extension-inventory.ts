export const extensionInventoryLimit = 100;

export const observedPermissions = [
  'clipboardRead', 'cookies', 'debugger', 'declarativeNetRequest', 'declarativeNetRequestWithHostAccess',
  'downloads', 'history', 'management', 'nativeMessaging', 'proxy', 'scripting', 'tabs',
  'webRequest', 'webRequestBlocking',
] as const;

export type ObservedPermission = typeof observedPermissions[number];
export type InventoryExtension = {
  id: string;
  name: string;
  version: string;
  enabled: boolean;
  installType: 'admin' | 'development' | 'normal' | 'sideload' | 'other';
  siteAccess: 'none' | 'selected' | 'all';
  permissions: ObservedPermission[];
};

export type InventoryStatus = 'reported' | 'permission_required' | 'unavailable';
export type InventorySnapshot = { status: InventoryStatus; entries: InventoryExtension[]; omitted: number };
