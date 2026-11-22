import type { AppClassification, BrowserReleaseCount, DiscoveredApp, DiscoveredAppId, Grant, Installation, Policy, PolicyGroup } from './control';
import type { AuditPage } from './audit';
import type { EventPage } from './events';
import type { RetentionCleanup, RetentionPolicy } from './retention';
import type { PreviewPolicy } from './preview';
import type { ControlAccess, ControlSession, DelegatedRole, IssuedControlAccess } from './access';
import type { PolicyChange, PolicyReviewQueue } from './reviews';
import type { InventoryInstallation } from './extension-inventory';

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
    const detail = response.status === 409 || response.status === 403 ? await response.json().catch(() => null) : null;
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

export const controlApi = {
  session: (token: string) => request<ControlSession>('/session', token),
  access: (token: string) => request<ControlAccess[]>('/access', token),
  ssoSettings: (token: string) => request<{ issuer: string } | undefined>('/access/sso', token),
  addSsoIdentity: (token: string, name: string, role: DelegatedRole, subject: string) =>
    request<ControlAccess>('/access/sso', token, 'POST', { name, role, subject }),
  issueAccess: (token: string, name: string, role: DelegatedRole, hours: number) =>
    request<IssuedControlAccess>('/access', token, 'POST', { name, role, hours }),
  revokeAccess: (token: string, id: string) => request<void>(`/access/${id}/revoke`, token, 'POST'),
  policies: (token: string, groupId?: string) => request<Policy[]>(policiesPath(groupId), token),
  groups: (token: string) => request<PolicyGroup[]>('/policy-groups', token),
  createGroup: (token: string, name: string) => request<PolicyGroup>('/policy-groups', token, 'POST', { name }),
  assignGroup: (token: string, installationId: string, groupId: string | null) =>
    request<void>(`/installations/${installationId}/policy-group`, token, 'POST', { groupId }),
  promoteGroup: (token: string, groupId: string, expectedVersion: number, review: boolean) =>
    request<PolicyChange>(`/policy-groups/${groupId}/promote`, token, 'POST', { expectedVersion }, review),
  policyReviews: (token: string) => request<PolicyReviewQueue>('/policy-reviews', token),
  setPolicyReview: (token: string, required: boolean) => request<void>('/policy-reviews/setting', token, 'POST', { required }),
  decidePolicyReview: (token: string, id: string, approve: boolean) =>
    request<Policy | undefined>(`/policy-reviews/${id}/decision`, token, 'POST', { approve }),
  installations: (token: string) => request<Installation[]>('/installations', token),
  browserReleases: (token: string) => request<BrowserReleaseCount[]>('/browser-releases', token).catch((error: unknown) => {
    if (error instanceof ApiError && error.status === 404) return undefined;
    throw error;
  }),
  extensionInventory: (token: string) => request<InventoryInstallation[]>('/extension-inventory', token),
  browserExtensionInventory: (token: string, id: string) => request<InventoryInstallation>(`/extension-inventory/${id}`, token),
  events: (token: string, filters: URLSearchParams) => request<EventPage>(`/events/history?${filters}`, token),
  exportEvents: (token: string, filters: URLSearchParams, signal: AbortSignal) =>
    apiResponse(`/events/export?${filters}`, token, { signal }),
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
  publishPreview: (token: string, policy: PreviewPolicy, expectedVersion: number, review: boolean, groupId?: string) =>
    request<PolicyChange>(policiesPath(groupId), token, 'POST', { ...policy, expectedVersion }, review),
  restore: (token: string, version: number, review: boolean, groupId?: string) =>
    request<PolicyChange>(`${policiesPath(groupId)}/${version}/restore`, token, 'POST', undefined, review),
  issueGrant: (token: string) => request<Grant>('/enrollment-grants', token, 'POST'),
  revoke: (token: string, installationId: string) => request<void>(`/installations/${installationId}/revoke`, token, 'POST'),
};

export const ssoApi = {
  async exchange(key: string, issuer: string, subject: string, expiresAt: string) {
    const response = await apiResponse('/sso/session', key, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ issuer, subject, expiresAt }),
    }, 'internal');
    return response.json() as Promise<{ token: string; expiresAt: string }>;
  },
  end: (token: string) => apiResponse('/sso/session', token, { method: 'DELETE', signal: AbortSignal.timeout(1500) }, 'internal'),
};
