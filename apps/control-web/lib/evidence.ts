export type CredentialKind = 'owner_token' | 'control_token' | 'sso_identity' | 'event_feed_key';
export type AccessReviewCredential = {
  kind: CredentialKind; id: string | null; name: string; role: 'owner' | 'administrator' | 'auditor' | 'event_feed';
  issuer: string | null; subject: string | null; issuedAt: string | null; expiresAt: string | null; lastUsedAt: string | null;
  status: 'active' | 'expired' | 'revoked'; createdBy: 'deployment_configuration' | 'organization_owner' | 'operator_recovery'; stale: boolean;
};
export type Attestation = {
  id: string; kind: 'access_review' | 'backup_drill' | 'restore_drill'; recordedAt: string; recordedBy?: string;
  reviewer?: string; notes?: string; staleDays?: number; fingerprint?: string; activeCredentials?: number; staleCredentials?: number;
  staleCredentialIds?: string[]; performedAt?: string; outcome?: 'succeeded' | 'failed'; operator?: string;
  archiveSha256?: string | null; recoveryMinutes?: number | null;
};
export type AccessReviewReport = {
  generatedAt: string; staleDays: number; fingerprint: string; credentials: AccessReviewCredential[];
  summary: { active: number; stale: number; ssoIdentities: number; eventFeedKeys: number }; attestations: Attestation[];
};
export type ReadAccess = {
  resource: keyof typeof accessResources; scope: Record<string, unknown>; records: number; requests: number; completed: boolean;
  lastAt: string; keyId?: string; keyName?: string;
};

export const credentialKinds: Record<CredentialKind, string> = {
  owner_token: 'Owner token', control_token: 'Named token', sso_identity: 'SSO identity', event_feed_key: 'Event feed key',
};
export const credentialCreators: Record<AccessReviewCredential['createdBy'], string> = {
  deployment_configuration: 'Deployment configuration', organization_owner: 'Organization owner', operator_recovery: 'Operator recovery',
};
export const accessResources = {
  security_events: 'Security events', incident_case: 'Incident case', audit_log: 'Audit log', event_feed: 'SIEM event feed',
  composer_readiness: 'Composer readiness', ai_enforcement: 'AI enforcement report', extension_inventory: 'Browser extensions',
  access_review: 'Access review', evidence_pack: 'Evidence pack', saas_inventory: 'SaaS inventory', organization_export: 'Organization export', billing: 'Billing',
} as const;
export const drillKinds = { backup_drill: 'Backup drill', restore_drill: 'Restore drill' } as const;

export function staleDaysValue(value: string | string[] | undefined) {
  if (value === undefined || value === '') return 90;
  return typeof value === 'string' && /^\d{1,3}$/.test(value) && Number(value) >= 1 && Number(value) <= 365 ? Number(value) : undefined;
}

export function readAccessSummary(access: ReadAccess) {
  const records = `${access.records.toLocaleString('en-US')} ${access.records === 1 ? 'record' : 'records'}`;
  const requests = access.requests > 1 ? ` · ${access.requests.toLocaleString('en-US')} requests this hour` : '';
  return `${accessResources[access.resource] ?? access.resource}${access.keyName ? ` · ${access.keyName}` : ''} · ${records}${requests}` +
    (access.completed ? '' : ' · Incomplete');
}
