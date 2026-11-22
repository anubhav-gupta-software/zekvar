import type { DiscoveredAppId, AppClassification, PolicyGroupChange } from './control';
import type { RetentionCleanup, RetentionPolicy } from './retention';
import type { AccessIdentity } from './access';
import type { PolicyReviewAudit } from './reviews';

export const auditActions = {
  policy_published: 'Policy published',
  policy_restored: 'Policy restored',
  grant_issued: 'Enrollment grant issued',
  browser_enrolled: 'Browser enrolled',
  browser_revoked: 'Browser revoked',
  app_classified: 'AI app classified',
  retention_changed: 'Retention settings changed',
  retention_cleanup: 'Expired records deleted',
  policy_group_created: 'Rollout group created',
  policy_group_assigned: 'Browser assignment changed',
  access_issued: 'Control access granted',
  access_revoked: 'Control access revoked',
  control_sso_signed_in: 'Single sign-on completed',
  policy_review_setting_changed: 'Policy review requirement changed',
  policy_review_requested: 'Policy review requested',
  policy_review_decided: 'Policy review decided',
} as const;

export type AuditAction = keyof typeof auditActions;
export type AuditCursor = { occurredAt: string; id: string };
export type AuditEntry = AuditCursor & {
  action: AuditAction;
  actor: 'organization_admin' | 'named_administrator' | 'sso_identity' | 'browser_enrollment' | 'system';
  actorAccess?: AccessIdentity;
  subjectAccess?: AccessIdentity;
  reviewChange?: PolicyReviewAudit;
  policyVersion: number | null;
  restoredFrom: number | null;
  installationId: string | null;
  appId: DiscoveredAppId | null;
  classification: AppClassification | null;
  retention: RetentionPolicy | null;
  cleanup: RetentionCleanup | null;
  groupChange: PolicyGroupChange | null;
};
export type AuditPage = { entries: AuditEntry[]; next: AuditCursor | null };
type Search = Record<string, string | string[] | undefined>;

function utcDay(value: string) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value) || value.startsWith('0000')) return;
  const day = new Date(`${value}T00:00:00Z`);
  if (Number.isFinite(day.getTime()) && day.toISOString().startsWith(`${value}T`)) return day;
}

export function auditSearchValues(params: URLSearchParams): Search {
  const result: Search = {};
  for (const key of ['action', 'from', 'through', 'beforeAt', 'beforeId']) {
    const values = params.getAll(key);
    if (values.length) result[key] = values.length === 1 ? values[0] : values;
  }
  return result;
}

export function auditFilters(search: Search) {
  const { action = '', from = '', through = '', beforeAt = '', beforeId = '' } = search;
  if (typeof action !== 'string' || typeof from !== 'string' || typeof through !== 'string' ||
      typeof beforeAt !== 'string' || typeof beforeId !== 'string') return;
  const since = from ? utcDay(from) : undefined;
  const lastDay = through ? utcDay(through) : undefined;
  if ((action && !Object.hasOwn(auditActions, action)) || (from && !since) || (through && !lastDay) ||
      (since && lastDay && since > lastDay) || through === '9999-12-31') return;
  if (Boolean(beforeAt) !== Boolean(beforeId) || (beforeAt &&
      (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z$/.test(beforeAt) || !Number.isFinite(Date.parse(beforeAt)) ||
       !/^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/i.test(beforeId) || beforeId === '00000000-0000-0000-0000-000000000000'))) return;

  const query = new URLSearchParams();
  const page = new URLSearchParams();
  if (action) {
    query.set('action', action);
    page.set('action', action);
  }
  if (since) {
    query.set('since', since.toISOString());
    page.set('from', from);
  }
  if (lastDay) {
    query.set('until', new Date(lastDay.getTime() + 86_400_000).toISOString());
    page.set('through', through);
  }
  if (beforeAt && beforeId) {
    query.set('beforeAt', beforeAt);
    query.set('beforeId', beforeId);
  }
  return { query, page, action, from, through, beforeAt };
}
