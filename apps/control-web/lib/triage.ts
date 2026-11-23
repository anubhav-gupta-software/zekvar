import type { AccessIdentity } from './access';
import { isId, type SecurityEvent } from './control';

export const triageStatuses = {
  needs_review: 'Needs review',
  investigating: 'Investigating',
  resolved: 'Resolved',
} as const;
export const triageDispositions = {
  confirmed_violation: 'Confirmed violation',
  false_positive: 'False positive',
  expected_activity: 'Expected activity',
  insufficient_evidence: 'Insufficient evidence',
} as const;

export type TriageStatus = keyof typeof triageStatuses;
export type TriageDisposition = keyof typeof triageDispositions;
export type TriageAssignee = { id: string; name: string; active: boolean };
export type EventTriage = {
  revision: number; status: TriageStatus; disposition: TriageDisposition | null;
  assignee: TriageAssignee | null; updatedAt: string | null;
};
export type TriageState = { status: TriageStatus; disposition: TriageDisposition | null; assigneeId: string | null };
export type EventTriageChange = { installationId: string; eventId: string; revision: number; before: TriageState; after: TriageState };
export type EventDetails = {
  event: SecurityEvent;
  activity: { id: string; occurredAt: string; actorAccess: AccessIdentity | null; change: EventTriageChange }[];
};
export type TriageUpdate = TriageState & { expectedRevision: number };

export const initialTriage: EventTriage = {
  revision: 0, status: 'needs_review', disposition: null, assignee: null, updatedAt: null,
};
export const eventPath = (installationId: string, eventId: string) => `/events/${installationId}/${eventId}`;

export function isTriageStatus(value: unknown): value is TriageStatus {
  return typeof value === 'string' && Object.hasOwn(triageStatuses, value);
}

export function isTriageDisposition(value: unknown): value is TriageDisposition {
  return typeof value === 'string' && Object.hasOwn(triageDispositions, value);
}

export function isTriageId(value: unknown): value is string {
  return isId(value) && value !== '00000000-0000-0000-0000-000000000000';
}

export function triageStatusFilter(value: unknown) {
  if (value === undefined || value === '') return '';
  if (isTriageStatus(value)) return value;
  return undefined;
}

export function triageAssigneeFilter(value: unknown) {
  if (value === undefined || value === '') return '';
  if (value === 'unassigned') return value;
  if (isTriageId(value)) return value.toLowerCase();
  return undefined;
}
