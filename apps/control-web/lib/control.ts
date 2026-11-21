export const modes = ['monitor', 'warn', 'block'] as const;
export const decisions = [...modes, 'warn_override'] as const;
export type Mode = typeof modes[number];
export type Decision = typeof decisions[number];

export const decisionLabels: Record<Decision, string> = {
  monitor: 'Monitor', warn: 'Warn', block: 'Block', warn_override: 'Warning overridden',
};

export const fixtureApp = 'local-prompt-fixture';

export type Policy = {
  version: number;
  mode: Mode;
  publishedAt: string;
  restoredFrom: number | null;
};

export type Installation = {
  installationId: string;
  enrolledAt: string;
  lastSeenAt: string;
  appliedPolicyVersion: number | null;
  revokedAt: string | null;
};

export type SecurityEvent = {
  eventId: string;
  installationId: string;
  appId: string;
  timestamp: string;
  detectorCategory: string;
  policyVersion: number;
  decision: Decision;
};

export type Grant = { grant: string; expiresAt: string };
export type Feedback = { error?: string; message?: string; grant?: Grant };

export const utc = new Intl.DateTimeFormat('en-US', {
  dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC',
});
