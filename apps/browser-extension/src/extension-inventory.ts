import { extensionInventoryLimit, observedPermissions, type InventoryExtension, type InventorySnapshot } from
  '../../../contracts/policy/extension-inventory';

export const inventoryPermission: chrome.permissions.Permissions = { permissions: ['management'] };

function summarizeExtension(info: chrome.management.ExtensionInfo): InventoryExtension {
  const name = info.name.replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ').trim().slice(0, 100)
    .replace(/[\uD800-\uDBFF]$/, '').trim();
  const hosts = info.hostPermissions;
  const broad = hosts.some((pattern) => pattern === '<all_urls>' || /^(?:\*|https?):\/\/\*\//.test(pattern));
  return {
    id: info.id,
    name: name || 'Unnamed extension',
    version: info.version,
    enabled: info.enabled,
    installType: info.installType,
    siteAccess: broad ? 'all' : hosts.length ? 'selected' : 'none',
    permissions: observedPermissions.filter((permission) => info.permissions.includes(permission)),
  };
}

export async function collectExtensionInventory(): Promise<InventorySnapshot> {
  try {
    if (!await chrome.permissions.contains(inventoryPermission)) {
      return { status: 'permission_required', entries: [], omitted: 0 };
    }
    const installed = (await chrome.management.getAll())
      .filter((info) => info.type === 'extension' && info.id !== chrome.runtime.id)
      .sort((left, right) => left.id.localeCompare(right.id));
    if (!await chrome.permissions.contains(inventoryPermission)) {
      return { status: 'permission_required', entries: [], omitted: 0 };
    }
    return {
      status: 'reported',
      entries: installed.slice(0, extensionInventoryLimit).map(summarizeExtension),
      omitted: Math.max(0, installed.length - extensionInventoryLimit),
    };
  } catch {
    return { status: 'unavailable', entries: [], omitted: 0 };
  }
}
