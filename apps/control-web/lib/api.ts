import type { AiAppId, AppClassification, DetectorMode, DiscoveredApp, DomainRules, Grant, Installation, Mode, Policy, PolicyGroup } from './control';
import type { AuditPage } from './audit';
import type { EventPage } from './events';
import type { RetentionCleanup, RetentionPolicy } from './retention';
import type { PreviewPolicy } from './preview';

const port = Number(process.env.ZEKVAR_CONTROL_PORT ?? 5187);
if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('Invalid Control loopback port.');
const api = `http://127.0.0.1:${port}/v1/admin`;

export class ApiError extends Error {
  constructor(readonly status: number) {
    super(`Control API returned HTTP ${status}`);
  }
}

async function apiResponse(path: string, token: string, options: RequestInit = {}): Promise<Response> {
  let response: Response;
  try {
    response = await fetch(`${api}${path}`, {
      ...options,
      cache: 'no-store',
      redirect: 'error',
      signal: options.signal ?? AbortSignal.timeout(5000),
      headers: { ...options.headers, Authorization: `Bearer ${token}` },
    });
  } catch {
    throw new ApiError(503);
  }
  if (!response.ok) throw new ApiError(response.status);
  return response;
}

async function request<T>(path: string, token: string, method = 'GET', body?: unknown): Promise<T> {
  const response = await apiResponse(path, token, {
    method,
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return response.status === 204 ? undefined as T : await response.json() as T;
}

const policiesPath = (groupId?: string) => groupId ? `/policy-groups/${groupId}/policies` : '/policies';

export const controlApi = {
  session: (token: string) => request<{ organization: string }>('/session', token),
  policies: (token: string, groupId?: string) => request<Policy[]>(policiesPath(groupId), token),
  groups: (token: string) => request<PolicyGroup[]>('/policy-groups', token),
  createGroup: (token: string, name: string) => request<PolicyGroup>('/policy-groups', token, 'POST', { name }),
  assignGroup: (token: string, installationId: string, groupId: string | null) =>
    request<void>(`/installations/${installationId}/policy-group`, token, 'POST', { groupId }),
  promoteGroup: (token: string, groupId: string, expectedVersion: number) =>
    request<Policy>(`/policy-groups/${groupId}/promote`, token, 'POST', { expectedVersion }),
  installations: (token: string) => request<Installation[]>('/installations', token),
  events: (token: string, filters: URLSearchParams) => request<EventPage>(`/events/history?${filters}`, token),
  exportEvents: (token: string, filters: URLSearchParams, signal: AbortSignal) =>
    apiResponse(`/events/export?${filters}`, token, { signal }),
  audit: (token: string, filters: URLSearchParams) => request<AuditPage>(`/audit?${filters}`, token),
  retention: (token: string) => request<RetentionPolicy>('/retention', token),
  saveRetention: (token: string, policy: RetentionPolicy) => request<void>('/retention', token, 'POST', policy),
  cleanupRetention: (token: string) => request<RetentionCleanup>('/retention/cleanup', token, 'POST'),
  aiApps: (token: string) => request<DiscoveredApp[]>('/ai-apps', token),
  classifyApp: (token: string, appId: AiAppId, status: AppClassification) =>
    request<void>(`/ai-apps/${appId}/classification`, token, 'POST', { status }),
  publish: (token: string, mode: Mode, githubPatMode: DetectorMode, discoveryEnabled: boolean, groupId?: string) =>
    request<Policy>(policiesPath(groupId), token, 'POST', { mode, githubPatMode, discoveryEnabled }),
  publishDomains: (token: string, domainRules: DomainRules, groupId?: string) =>
    request<Policy>(policiesPath(groupId), token, 'POST', { domainRules }),
  publishPreview: (token: string, policy: PreviewPolicy, expectedVersion: number, groupId?: string) =>
    request<Policy>(policiesPath(groupId), token, 'POST', { ...policy, expectedVersion }),
  restore: (token: string, version: number, groupId?: string) => request<Policy>(`${policiesPath(groupId)}/${version}/restore`, token, 'POST'),
  issueGrant: (token: string) => request<Grant>('/enrollment-grants', token, 'POST'),
  revoke: (token: string, installationId: string) => request<void>(`/installations/${installationId}/revoke`, token, 'POST'),
};
