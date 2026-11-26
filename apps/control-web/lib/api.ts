import type { AdapterControls } from '../../../contracts/policy/adapter-controls';
import type {
  AppClassification, BrowserHealthView, BrowserReleaseCount, ComposerReadinessReport, DiscoveredApp, DiscoveredAppId, Grant, Installation, Policy, PolicyGroup,
} from './control';
import type { AuditPage } from './audit';
import type { EventPage } from './events';
import type { RetentionCleanup, RetentionPolicy } from './retention';
import type { PreviewPolicy } from './preview';
import type { ControlAccess, ControlSession, DelegatedRole, EventFeedKey, IssuedControlAccess, IssuedEventFeedKey } from './access';
import type { PolicyChange, PolicyReviewQueue } from './reviews';
import type { InventoryInstallation } from './extension-inventory';
import type { EnrollmentBatch, IssuedEnrollmentBatch } from './enrollment';
import type { AiEnforcementReport } from './reports';
import type { ExtensionDeployment } from './extension-deployment';
import type { BrowserHardening } from './browser-hardening';
import type { FleetChange, FleetPage, FleetRequest } from './fleet';
import type { PolicyTemplate, PolicyTemplateDetails, PolicyTemplatePreview } from './templates';
import type { PolicyImpactReport } from './policy-impact';
import type { RolloutPlan, RolloutStageRequest } from './rollouts';
import type { PromptExceptionRequest, PromptRequestDecision } from './prompt-requests';
import type { AiPromptApp } from '../../../contracts/policy/apps';
import { eventPath, type EventDetails, type EventTriage, type TriageAssignee, type TriageUpdate } from './triage';
import { casePath, type CaseCategory, type CaseDetails, type CasePage, type EventReference } from './cases';
import { alertPath, extensionAlertPath, extensionAlertsPath, type AlertDetails, type AlertPage, type AlertSettings,
  type ExtensionAccessDetails, type ExtensionAccessPage, type ExtensionAccessSettings } from './alerts';

const port = Number(process.env.ZEKVAR_CONTROL_PORT ?? 5187);
if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('Invalid Control loopback port.');
const api = `http://127.0.0.1:${port}/v1`;

export class ApiError extends Error {
  constructor(readonly status: number, readonly code?: string) {
    super(`Control API returned HTTP ${status}`);
  }
}

async function apiResponse(path: string, token: string, options: RequestInit = {}, namespace = 'admin'): Promise<Response> {
  let response: Response;
  try {
    response = await fetch(`${api}/${namespace}${path}`, {
      ...options,
      cache: 'no-store',
      redirect: 'error',
      signal: options.signal ?? AbortSignal.timeout(5000),
      headers: { ...options.headers, Authorization: `Bearer ${token}` },
    });
  } catch {
    throw new ApiError(503);
  }
  if (!response.ok) {
    const detail = [400, 403, 409].includes(response.status) ? await response.json().catch(() => null) : null;
    throw new ApiError(response.status, typeof detail?.code === 'string' ? detail.code : undefined);
  }
  return response;
}

async function request<T>(path: string, token: string, method = 'GET', body?: unknown, expectReview = false): Promise<T> {
  const response = await apiResponse(path, token, {
    method,
    headers: {
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      ...(expectReview ? { 'X-Zekvar-Expect-Review': '1' } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return response.status === 204 ? undefined as T : await response.json() as T;
}

const policiesPath = (groupId?: string) => groupId ? `/policy-groups/${groupId}/policies` : '/policies';

async function eventResponse(path: string, token: string, filters: URLSearchParams, signal?: AbortSignal) {
  const response = await apiResponse(`${path}?${filters}`, token, { signal });
  if (filters.get('rolloutGroup') && response.headers.get('X-Zekvar-Event-Rollout') !== '1') {
    await response.body?.cancel();
    throw new ApiError(409, 'event_rollout_unavailable');
  }
  if ((filters.get('triageStatus') || filters.get('triageAssignee')) && response.headers.get('X-Zekvar-Event-Triage') !== '1') {
    await response.body?.cancel();
    throw new ApiError(409, 'event_triage_unavailable');
  }
  return response;
}

export const controlApi = {
  session: (token: string) => request<ControlSession>('/session', token),
  access: (token: string) => request<ControlAccess[]>('/access', token),
  ssoSettings: (token: string) => request<{ issuer: string } | undefined>('/access/sso', token),
  addSsoIdentity: (token: string, name: string, role: DelegatedRole, subject: string) =>
    request<ControlAccess>('/access/sso', token, 'POST', { name, role, subject }),
  issueAccess: (token: string, name: string, role: DelegatedRole, hours: number) =>
    request<IssuedControlAccess>('/access', token, 'POST', { name, role, hours }),
  revokeAccess: (token: string, id: string) => request<void>(`/access/${id}/revoke`, token, 'POST'),
  eventFeedKeys: (token: string) => request<EventFeedKey[]>('/access/event-feed', token).catch((error: unknown) => {
    if (error instanceof ApiError && error.status === 404) return undefined;
    throw error;
  }),
  issueEventFeedKey: (token: string, requestId: string, name: string, days: number) =>
    request<IssuedEventFeedKey>('/access/event-feed', token, 'POST', { requestId, name, days }),
  revokeEventFeedKey: (token: string, id: string) => request<void>(`/access/event-feed/${id}/revoke`, token, 'POST'),
  policies: (token: string, groupId?: string) => request<Policy[]>(policiesPath(groupId), token),
  templates: (token: string) => request<PolicyTemplate[]>('/policy-templates', token),
  template: (token: string, id: string) => request<PolicyTemplateDetails>(`/policy-templates/${id}`, token),
  templatePreview: (token: string, id: string, revision: number, groupId?: string) => {
    const filter = new URLSearchParams({ revision: String(revision) });
    if (groupId) filter.set('groupId', groupId);
    return request<PolicyTemplatePreview>(`/policy-templates/${id}/preview?${filter}`, token);
  },
  createTemplate: (token: string, name: string, sourceVersion: number) =>
    request<PolicyTemplate>('/policy-templates', token, 'POST', { name, sourceVersion }),
  reviseTemplate: (token: string, id: string, expectedRevision: number, sourceVersion: number) =>
    request<PolicyTemplate>(`/policy-templates/${id}/revisions`, token, 'POST', { expectedRevision, sourceVersion }),
  archiveTemplate: (token: string, id: string, expectedRevision: number) =>
    request<void>(`/policy-templates/${id}/archive`, token, 'POST', { expectedRevision }),
  applyTemplate: (token: string, id: string, revision: number, expectedVersion: number, groupId: string | null, review: boolean) =>
    request<PolicyChange>(`/policy-templates/${id}/apply`, token, 'POST', { revision, expectedVersion, groupId }, review),
  groups: (token: string) => request<PolicyGroup[]>('/policy-groups', token),
  createGroup: (token: string, name: string) => request<PolicyGroup>('/policy-groups', token, 'POST', { name }),
  assignGroup: (token: string, installationId: string, groupId: string | null) =>
    request<void>(`/installations/${installationId}/policy-group`, token, 'POST', { groupId }),
  promoteGroup: (token: string, groupId: string, expectedVersion: number, review: boolean, expectedBaselineVersion?: number) =>
    request<PolicyChange>(`/policy-groups/${groupId}/promote`, token, 'POST', { expectedVersion, expectedBaselineVersion }, review),
  policyReviews: (token: string) => request<PolicyReviewQueue>('/policy-reviews', token),
  rolloutPlans: (token: string) => request<RolloutPlan[]>('/rollout-plans', token),
  createRolloutPlan: (token: string, requestId: string, name: string, sourceVersion: number, stages: RolloutStageRequest[]) =>
    request<RolloutPlan>('/rollout-plans', token, 'POST', { requestId, name, sourceVersion, stages }),
  decideRolloutPlan: (token: string, id: string, approve: boolean) =>
    request<RolloutPlan>(`/rollout-plans/${id}/decision`, token, 'POST', { approve }),
  changeRolloutPlan: (token: string, id: string, operation: 'pause' | 'resume' | 'rollback' | 'cancel') =>
    request<RolloutPlan>(`/rollout-plans/${id}/${operation}`, token, 'POST'),
  promptExceptionRequests: (token: string, status: 'pending' | 'decided') =>
    request<PromptExceptionRequest[]>(`/prompt-exception-requests?status=${status}`, token),
  decidePromptExceptionRequest: (token: string, id: string, status: PromptRequestDecision) =>
    request<{ id: string; status: PromptRequestDecision }>(`/prompt-exception-requests/${id}/decision`, token, 'POST', { status }),
  setPolicyReview: (token: string, required: boolean) => request<void>('/policy-reviews/setting', token, 'POST', { required }),
  decidePolicyReview: (token: string, id: string, approve: boolean) =>
    request<Policy | undefined>(`/policy-reviews/${id}/decision`, token, 'POST', { approve }),
  installations: (token: string) => request<Installation[]>('/installations', token),
  fleet: (token: string, filters: URLSearchParams) => request<FleetPage>(`/installations/fleet?${filters}`, token),
  applyFleetChange: (token: string, change: FleetRequest) => request<FleetChange>('/installations/fleet', token, 'POST', change),
  browserHealth: (token: string, filters: URLSearchParams) => request<BrowserHealthView>(`/browser-health?${filters}`, token),
  composerReadiness: (token: string, filters: URLSearchParams) =>
    request<ComposerReadinessReport>(`/reports/composer-readiness?${filters}`, token),
  browserReleases: (token: string) => request<BrowserReleaseCount[]>('/browser-releases', token).catch((error: unknown) => {
    if (error instanceof ApiError && error.status === 404) return undefined;
    throw error;
  }),
  extensionInventory: (token: string) => request<InventoryInstallation[]>('/extension-inventory', token),
  publishExtensionDeployment: (token: string, extensionDeployment: ExtensionDeployment, expectedVersion: number, review: boolean, groupId?: string) =>
    request<PolicyChange>(policiesPath(groupId), token, 'POST', { extensionDeployment, expectedVersion }, review),
  publishAdapterControls: (token: string, adapterControls: AdapterControls, expectedVersion: number, review: boolean, groupId?: string) =>
    request<PolicyChange>(policiesPath(groupId), token, 'POST', { adapterControls, expectedVersion }, review),
  publishBrowserHardening: (token: string, browserHardening: BrowserHardening, expectedVersion: number, review: boolean, groupId?: string) =>
    request<PolicyChange>(policiesPath(groupId), token, 'POST', { browserHardening, expectedVersion }, review),
  browserExtensionInventory: (token: string, id: string) => request<InventoryInstallation>(`/extension-inventory/${id}`, token),
  events: async (token: string, filters: URLSearchParams): Promise<EventPage> => {
    const response = await eventResponse('/events/history', token, filters);
    return { ...await response.json(), rolloutAvailable: response.headers.get('X-Zekvar-Event-Rollout') === '1',
      triageAvailable: response.headers.get('X-Zekvar-Event-Triage') === '1' };
  },
  event: (token: string, installationId: string, eventId: string) =>
    request<EventDetails>(eventPath(installationId, eventId), token),
  triageAssignees: (token: string) => request<TriageAssignee[]>('/events/triage-assignees', token),
  saveEventTriage: (token: string, installationId: string, eventId: string, change: TriageUpdate) =>
    request<EventTriage>(`${eventPath(installationId, eventId)}/triage`, token, 'POST', change),
  cases: (token: string, filters: URLSearchParams) => request<CasePage>(`/cases?${filters}`, token),
  case: (token: string, id: string) => request<CaseDetails>(casePath(id), token),
  createCase: (token: string, requestId: string, category: CaseCategory, event: EventReference) =>
    request<{ caseId: string }>('/cases', token, 'POST', { requestId, category, ...event }),
  saveCaseTriage: (token: string, id: string, change: TriageUpdate) =>
    request<{ caseId: string }>(`${casePath(id)}/triage`, token, 'POST', change),
  changeCaseMembership: (token: string, id: string, event: EventReference, expectedRevision: number, linked: boolean) =>
    request<{ caseId: string }>(`${casePath(id)}/membership`, token, 'POST', { ...event, expectedRevision, linked }),
  exportCase: (token: string, id: string) => apiResponse(`${casePath(id)}/export`, token),
  alerts: (token: string, query: URLSearchParams) => request<AlertPage>(`/alerts?${query}`, token),
  alert: (token: string, id: string, query: URLSearchParams) => request<AlertDetails>(`${alertPath(id)}?${query}`, token),
  alertSettings: (token: string) => request<AlertSettings>('/alerts/settings', token),
  saveAlertSettings: (token: string, enabled: boolean, threshold: number, expectedRevision: number) =>
    request<AlertSettings>('/alerts/settings', token, 'POST', { enabled, threshold, expectedRevision }),
  acknowledgeAlert: (token: string, id: string) => request<void>(`${alertPath(id)}/acknowledge`, token, 'POST'),
  extensionAlerts: (token: string, query: URLSearchParams) => request<ExtensionAccessPage>(`${extensionAlertsPath}?${query}`, token),
  extensionAlert: (token: string, id: string) => request<ExtensionAccessDetails>(extensionAlertPath(id), token),
  extensionAlertSettings: (token: string) => request<ExtensionAccessSettings>(`${extensionAlertsPath}/settings`, token),
  saveExtensionAlertSettings: (token: string, enabled: boolean, expectedRevision: number) =>
    request<ExtensionAccessSettings>(`${extensionAlertsPath}/settings`, token, 'POST', { enabled, expectedRevision }),
  acknowledgeExtensionAlert: (token: string, id: string) => request<void>(`${extensionAlertPath(id)}/acknowledge`, token, 'POST'),
  exportEvents: (token: string, filters: URLSearchParams, signal: AbortSignal) =>
    eventResponse('/events/export', token, filters, signal),
  aiEnforcement: (token: string, filters: URLSearchParams) => request<AiEnforcementReport>(`/reports/ai-enforcement?${filters}`, token),
  policyImpact: (token: string, query: URLSearchParams) => request<PolicyImpactReport>(`/reports/policy-impact?${query}`, token),
  audit: (token: string, filters: URLSearchParams) => request<AuditPage>(`/audit?${filters}`, token),
  retention: (token: string) => request<RetentionPolicy>('/retention', token),
  saveRetention: (token: string, policy: RetentionPolicy) => request<void>('/retention', token, 'POST', policy),
  cleanupRetention: (token: string) => request<RetentionCleanup>('/retention/cleanup', token, 'POST'),
  aiApps: (token: string) => request<DiscoveredApp[]>('/ai-apps', token),
  classifyApp: (token: string, appId: DiscoveredAppId, status: AppClassification) =>
    request<void>(`/ai-apps/${appId}/classification`, token, 'POST', { status }),
  publish: (token: string, policy: Omit<PreviewPolicy, 'domainRules' | 'pathRules' | 'customApps' | 'promptExceptions'> & { expectedVersion?: number }, review: boolean, groupId?: string) =>
    request<PolicyChange>(policiesPath(groupId), token, 'POST', policy, review),
  publishNavigation: (token: string, rules: Pick<PreviewPolicy, 'domainRules' | 'pathRules'>, expectedVersion: number, review: boolean, groupId?: string) =>
    request<PolicyChange>(policiesPath(groupId), token, 'POST', { ...rules, expectedVersion }, review),
  publishPreview: (token: string, policy: PreviewPolicy & { requireComposerReady?: AiPromptApp[] }, expectedVersion: number, review: boolean, groupId?: string) =>
    request<PolicyChange>(policiesPath(groupId), token, 'POST', { ...policy, expectedVersion }, review),
  restore: (token: string, version: number, review: boolean, groupId?: string) =>
    request<PolicyChange>(`${policiesPath(groupId)}/${version}/restore`, token, 'POST', undefined, review),
  issueGrant: (token: string) => request<Grant>('/enrollment-grants', token, 'POST'),
  enrollmentBatches: (token: string) => request<EnrollmentBatch[]>('/enrollment-batches', token),
  issueEnrollmentBatch: (token: string, requestId: string, groupId: string | null, count: number) =>
    request<IssuedEnrollmentBatch>('/enrollment-batches', token, 'POST', { requestId, groupId, count }),
  cancelEnrollmentBatch: (token: string, id: string) => request<void>(`/enrollment-batches/${id}/cancel`, token, 'POST'),
  revoke: (token: string, installationId: string) => request<void>(`/installations/${installationId}/revoke`, token, 'POST'),
};

export const ssoApi = {
  async exchange(key: string, issuer: string, subject: string, expiresAt: string, organizationSlug?: string) {
    const response = await apiResponse('/sso/session', key, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ issuer, subject, expiresAt, organizationSlug }),
    }, 'internal');
    return response.json() as Promise<{ token: string; expiresAt: string }>;
  },
  end: (token: string) => apiResponse('/sso/session', token, { method: 'DELETE', signal: AbortSignal.timeout(1500) }, 'internal'),
};
