export type OrganizationDeletionStatus = {
  id: string;
  status: 'pending' | 'deleting' | 'completed' | 'cancelled';
  requestedAt: string;
  purgeAfter: string;
  cancelledAt: string | null;
  startedAt: string | null;
  completedAt: string | null;
  deletedRows: number;
  batches: number;
  lastError?: string;
};
export type OrganizationDeletionView = { deletion: OrganizationDeletionStatus | null; graceDays: number; available: boolean };
export type RequestedOrganizationDeletion = { deletion: OrganizationDeletionStatus; receiptToken: string };
export type InstallationDeletion = { installationId: string; deletedRows: Record<string, number> };
export type PolicyPurgeKept = { current: number; openReview: number; activeRollout: number; retainedEvent: number; installation: number; evidence: number };
export type PolicyPurge = { scope: 'baseline' | 'group'; groupId: string | null; publishedBefore: string; dryRun: boolean; versions: number[]; kept: PolicyPurgeKept };
export type DataDeletionAudit = {
  installationId?: string;
  deletedRows?: Record<string, number>;
  scope?: 'baseline' | 'group';
  groupId?: string | null;
  publishedBefore?: string;
  versions?: number[];
  kept?: PolicyPurgeKept;
  deletionId?: string;
  purgeAfter?: string;
  graceDays?: number;
  format?: string;
};

export const deletionStatuses: Record<OrganizationDeletionStatus['status'], string> = {
  pending: 'Scheduled',
  deleting: 'Deleting',
  completed: 'Deleted',
  cancelled: 'Cancelled',
};

export const keptLabels: Record<keyof PolicyPurgeKept, string> = {
  current: 'current',
  openReview: 'open review',
  activeRollout: 'active rollout',
  retainedEvent: 'retained events',
  installation: 'applied by a browser',
  evidence: 'inventory, template, or exception evidence',
};

export function keptSummary(kept: PolicyPurgeKept) {
  const parts = (Object.keys(keptLabels) as (keyof PolicyPurgeKept)[]).filter((key) => kept[key] > 0)
    .map((key) => `${kept[key]} ${keptLabels[key]}`);
  return parts.length ? `Kept ${parts.join(', ')}.` : 'No versions kept.';
}

export function versionList(versions: number[]) {
  return versions.length ? versions.map((version) => `v${version}`).join(', ') : 'none';
}

export function deletedRowTotal(rows: Record<string, number> | undefined) {
  return Object.values(rows ?? {}).reduce((sum, count) => sum + count, 0);
}

export function dataDeletionDetails(action: string, change: DataDeletionAudit) {
  switch (action) {
    case 'installation_deleted':
      return `Browser ${change.installationId?.slice(0, 13)} · ${deletedRowTotal(change.deletedRows)} records deleted`;
    case 'policy_history_purged':
      return `${change.scope === 'group' ? 'Rollout group' : 'Organization baseline'} · Purged ${versionList(change.versions ?? [])}`;
    case 'organization_deletion_requested':
      return `Deletion scheduled after a ${change.graceDays}-day grace period`;
    case 'organization_deletion_cancelled':
      return 'Scheduled deletion cancelled';
    case 'organization_exported':
      return 'Full organization export downloaded';
    default:
      return '';
  }
}
