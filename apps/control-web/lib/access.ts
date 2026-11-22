export type DelegatedRole = 'administrator' | 'auditor';
export type ControlRole = 'owner' | DelegatedRole;

export const roleLabels: Record<ControlRole, string> = {
  owner: 'Owner',
  administrator: 'Administrator',
  auditor: 'Auditor',
};

export type AccessIdentity = { id: string; name: string; role: DelegatedRole };
export type ControlSession = { organization: string; role: ControlRole; access: AccessIdentity | null; reviewRequired: boolean };
export type ControlAccess = AccessIdentity & {
  issuedAt: string; expiresAt: string | null; status: 'active' | 'expired' | 'revoked'; issuer?: string; subject?: string;
};
export type IssuedControlAccess = { access: ControlAccess & { expiresAt: string }; token: string };
export const canWrite = (session?: ControlSession) => session?.role === 'owner' || session?.role === 'administrator';
export const canChangePolicy = (session?: ControlSession) => canWrite(session) && (!session?.reviewRequired || session.role === 'administrator');
