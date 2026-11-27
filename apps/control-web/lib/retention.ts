export const retentionFields = {
  securityEventDays: 'Security events',
  aiObservationDays: 'AI observations',
  auditDays: 'Audit log',
} as const;

export type RetentionField = keyof typeof retentionFields;
export type RetentionPolicy = Record<RetentionField, number | null>;
export type RetentionCleanup = { securityEvents: number; aiObservations: number; auditEntries: number; incidentCases?: number; alertWindows?: number;
  saasObservations?: number; accessLogEntries?: number;
  source: 'manual' | 'scheduled' };

export function cleanupCounts(result: RetentionCleanup) {
  const count = (value: number, singular: string, plural: string) => `${value} ${value === 1 ? singular : plural}`;
  const removed = [count(result.securityEvents, 'security event', 'security events'),
    count(result.aiObservations, 'AI observation', 'AI observations'), count(result.auditEntries, 'audit entry', 'audit entries')];
  if (result.incidentCases) removed.push(count(result.incidentCases, 'resolved case', 'resolved cases'));
  if (result.alertWindows) removed.push(count(result.alertWindows, 'alert window', 'alert windows'));
  if (result.saasObservations) removed.push(count(result.saasObservations, 'SaaS app record', 'SaaS app records'));
  if (result.accessLogEntries) removed.push(count(result.accessLogEntries, 'access log entry', 'access log entries'));
  return removed.join(', ');
}
