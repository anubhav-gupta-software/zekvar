export type IssuedEnrollmentBatch = { id: string; expiresAt: string; grants: string[] };

export type EnrollmentBatch = {
  id: string;
  groupId: string | null;
  groupName: string | null;
  size: number;
  redeemed: number;
  available: number;
  createdAt: string;
  expiresAt: string;
  status: 'open' | 'used' | 'expired' | 'cancelled';
};

export type EnrollmentBatchChange = { batchId: string; groupId: string | null; groupName: string | null; count: number };
