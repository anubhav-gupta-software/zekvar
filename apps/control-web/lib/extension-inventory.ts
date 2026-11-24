import type { InventoryExtension, InventoryStatus, ObservedPermission } from '../../../contracts/policy/extension-inventory';

export type InventoryInstallation = {
  installationId: string;
  groupName: string | null;
  status: InventoryStatus | 'off' | 'awaiting';
  reportedAt: string | null;
  extensionCount: number;
  omitted: number;
  entries: InventoryExtension[] | null;
  changeHistory?: InventoryChangeBatch[];
};

export type InventoryExtensionState = Omit<InventoryExtension, 'id' | 'name'>;
export type InventoryExtensionChange = { extensionId: string; before: InventoryExtensionState | null; after: InventoryExtensionState | null };
export type InventoryChangeBatch = { id: string; policyVersion: number; reportedAt: string; changes: InventoryExtensionChange[] };

export const inventoryStatusLabels: Record<InventoryInstallation['status'], string> = {
  off: 'Off',
  awaiting: 'Awaiting report',
  permission_required: 'Permission needed',
  unavailable: 'Unavailable',
  reported: 'Reported',
};

export const installTypeLabels: Record<InventoryExtension['installType'], string> = {
  admin: 'Managed policy',
  development: 'Unpacked',
  normal: 'Standard install',
  sideload: 'Sideloaded',
  other: 'Other',
};

export const siteAccessLabels: Record<InventoryExtension['siteAccess'], string> = {
  all: 'Broad site access',
  selected: 'Selected sites',
  none: 'None reported',
};

const privileged = new Set<ObservedPermission>(['cookies', 'debugger', 'management', 'nativeMessaging', 'proxy']);

export function needsReview(extension: Pick<InventoryExtension, 'siteAccess' | 'installType' | 'permissions'>) {
  return extension.siteAccess === 'all' || extension.installType === 'development' || extension.installType === 'sideload' ||
    extension.permissions.some((permission) => privileged.has(permission));
}

const siteAccessRank = { none: 0, selected: 1, all: 2 };

export function hasExpandedAccess({ before, after }: InventoryExtensionChange) {
  if (!after?.enabled) return false;
  if (!before?.enabled) return needsReview(after);
  return siteAccessRank[before.siteAccess] < siteAccessRank[after.siteAccess] ||
    (before.installType !== after.installType && (after.installType === 'development' || after.installType === 'sideload')) ||
    after.permissions.some((permission) => privileged.has(permission) && !before.permissions.includes(permission));
}
