import type { AccessIdentity } from './access';
import type { Policy } from './control';

export const reviewOperations = { publish: 'Publish policy', restore: 'Restore policy', promote: 'Promote group policy' };
export const reviewStatuses = {
  pending: 'Pending', approved: 'Approved', rejected: 'Rejected', withdrawn: 'Withdrawn',
  stale: 'Stale', cancelled: 'Cancelled', expired: 'Expired',
};

export type QueuedReview = { reviewId: string };
export type PolicyChange = Policy | QueuedReview;
export type PolicyReview = {
  id: string;
  status: keyof typeof reviewStatuses;
  operation: keyof typeof reviewOperations;
  groupId: string | null;
  groupName: string | null;
  sourceGroupId: string | null;
  sourceGroupName: string | null;
  sourceVersion: number | null;
  requestedAt: string;
  expiresAt: string;
  decidedAt: string | null;
  publishedVersion: number | null;
  requester: AccessIdentity;
  reviewer: AccessIdentity | null;
  snapshots: { before: Policy; candidate: Policy };
};

export type PolicyReviewQueue = { required: boolean; entries: PolicyReview[] };
export type PolicyReviewAudit = {
  reviewId: string | null; operation: PolicyReview['operation'] | null; status: PolicyReview['status'] | null;
  groupId: string | null; baseVersion: number | null; sourceVersion: number | null; publishedVersion: number | null;
  required: boolean | null; cancelled: number | null;
};
