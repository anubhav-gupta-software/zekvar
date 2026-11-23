import type { AccessIdentity } from './access';
import type { SecurityEvent } from './control';
import { isTriageId, triageStatusFilter, type EventTriage, type TriageState, type TriageStatus } from './triage';

export const caseCategories = {
  suspected_data_exposure: 'Suspected data exposure',
  repeated_policy_blocks: 'Repeated policy blocks',
  unexpected_ai_use: 'Unexpected AI use',
  other: 'Other investigation',
} as const;

export const caseOperations = {
  created: 'Case opened',
  triage_updated: 'Case triage updated',
  event_added: 'Event linked',
  event_removed: 'Event unlinked',
} as const;

export type CaseCategory = keyof typeof caseCategories;
export type CaseReference = { id: string; category: CaseCategory; revision: number; status: TriageStatus };
export type IncidentCase = { id: string; category: CaseCategory; createdAt: string; triage: EventTriage; eventCount: number };
export type CaseCursor = { createdAt: string; id: string };
export type CasePage = { entries: IncidentCase[]; next: CaseCursor | null };
export type EventReference = { installationId: string; eventId: string };
export type CaseChange = {
  caseId: string; category: CaseCategory; revision: number; operation: keyof typeof caseOperations;
  before: TriageState | null; after: TriageState | null; installationId: string | null; eventId: string | null;
};
export type CaseDetails = {
  case: IncidentCase; events: SecurityEvent[];
  activity: { id: string; occurredAt: string; actorAccess: AccessIdentity | null; change: CaseChange }[];
};
export const casePath = (id: string) => `/cases/${id}`;
export const caseNumber = (id: string) => `Case ${id.slice(0, 8).toUpperCase()}`;

export function isCaseCategory(value: unknown): value is CaseCategory {
  return typeof value === 'string' && Object.hasOwn(caseCategories, value);
}

export function caseListFilters(search: Record<string, string | string[] | undefined>) {
  const { beforeAt, beforeId, installation, event, open } = search;
  const status = triageStatusFilter(search.status);
  const source = isTriageId(installation) && isTriageId(event) ? { installationId: installation, eventId: event } : undefined;
  if (status === undefined || (open !== undefined && open !== '1') || ((installation !== undefined || event !== undefined) && !source)) return;
  const page = new URLSearchParams();
  const query = new URLSearchParams();
  if (status) {
    page.set('status', status);
    query.set('status', status);
  }
  if (open) {
    page.set('open', open);
    query.set('openOnly', 'true');
  }
  if (source) {
    page.set('installation', source.installationId);
    page.set('event', source.eventId);
  }
  if (beforeAt !== undefined || beforeId !== undefined) {
    if (typeof beforeAt !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|[+-]\d\d:\d\d)$/.test(beforeAt) ||
        !Number.isFinite(Date.parse(beforeAt)) || !isTriageId(beforeId)) return;
    query.set('beforeAt', beforeAt);
    query.set('beforeId', beforeId);
  }
  return { status, open, source, page, query, paged: beforeAt !== undefined };
}
