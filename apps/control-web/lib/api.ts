import type { AiAppId, AppClassification, DetectorMode, DiscoveredApp, DomainRules, Grant, Installation, Mode, Policy, SecurityEvent } from './control';
import type { AuditPage } from './audit';
import type { RetentionCleanup, RetentionPolicy } from './retention';

const port = Number(process.env.ZEKVAR_CONTROL_PORT ?? 5187);
if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('Invalid Control loopback port.');
const api = `http://127.0.0.1:${port}/v1/admin`;

export class ApiError extends Error {
  constructor(readonly status: number) {
    super(`Control API returned HTTP ${status}`);
  }
}

async function request<T>(path: string, token: string, method = 'GET', body?: unknown): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${api}${path}`, {
      method,
      cache: 'no-store',
      redirect: 'error',
      signal: AbortSignal.timeout(5000),
      headers: {
        Authorization: `Bearer ${token}`,
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(503);
  }
  if (!response.ok) throw new ApiError(response.status);
  return response.status === 204 ? undefined as T : await response.json() as T;
}

export const controlApi = {
  session: (token: string) => request<{ organization: string }>('/session', token),
  policies: (token: string) => request<Policy[]>('/policies', token),
  installations: (token: string) => request<Installation[]>('/installations', token),
  events: (token: string, filters: URLSearchParams) => request<SecurityEvent[]>(`/events?${filters}`, token),
  audit: (token: string, filters: URLSearchParams) => request<AuditPage>(`/audit?${filters}`, token),
  retention: (token: string) => request<RetentionPolicy>('/retention', token),
  saveRetention: (token: string, policy: RetentionPolicy) => request<void>('/retention', token, 'POST', policy),
  cleanupRetention: (token: string) => request<RetentionCleanup>('/retention/cleanup', token, 'POST'),
  aiApps: (token: string) => request<DiscoveredApp[]>('/ai-apps', token),
  classifyApp: (token: string, appId: AiAppId, status: AppClassification) =>
    request<void>(`/ai-apps/${appId}/classification`, token, 'POST', { status }),
  publish: (token: string, mode: Mode, githubPatMode: DetectorMode, discoveryEnabled: boolean) =>
    request<Policy>('/policies', token, 'POST', { mode, githubPatMode, discoveryEnabled }),
  publishDomains: (token: string, domainRules: DomainRules) => request<Policy>('/policies', token, 'POST', { domainRules }),
  restore: (token: string, version: number) => request<Policy>(`/policies/${version}/restore`, token, 'POST'),
  issueGrant: (token: string) => request<Grant>('/enrollment-grants', token, 'POST'),
  revoke: (token: string, installationId: string) => request<void>(`/installations/${installationId}/revoke`, token, 'POST'),
};
