export type FleetBrowser = {
  installationId: string; enrolledAt: string; lastSeenAt: string; groupId: string | null; groupName: string | null;
  assignmentVersion: number; assignmentAware: boolean; expectedPolicyVersion: number; extensionVersion: string | null;
};
export type FleetPage = { entries: FleetBrowser[]; next: { enrolledAt: string; installationId: string } | null };
export type FleetSelection = Pick<FleetBrowser, 'installationId' | 'assignmentVersion'>;
export type FleetRequest = {
  requestId: string; operation: 'assign' | 'revoke'; groupId: string | null; expectedPolicyVersion: number | null; selections: FleetSelection[];
};
export type FleetChange = {
  batchId: string; operation: FleetRequest['operation']; groupId: string | null; groupName: string | null; policyVersion: number | null;
  selectedCount: number; changedInstallations: string[];
};
