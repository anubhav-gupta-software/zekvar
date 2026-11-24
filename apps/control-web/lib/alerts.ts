import { aiPromptApps, isId, type SecurityEvent } from './control';
import { isEventTimestamp, type EventCursor } from './events';
import type { InventoryExtensionChange } from './extension-inventory';

export type AlertSettings = { enabled: boolean; threshold: number; revision: number };
export type Alert = {
  id: string;
  appId: typeof aiPromptApps[number];
  rollout: NonNullable<SecurityEvent['rollout']>;
  windowStart: string;
  windowEnd: string;
  threshold: number;
  blockCount: number;
  triggeredAt: string;
  acknowledgedAt: string | null;
};
export type AlertCursor = { triggeredAt: string; id: string };
export type AlertPage = { entries: Alert[]; next: AlertCursor | null };
export type AlertWebhook = {
  status: 'queued' | 'sending' | 'retrying' | 'sent' | 'failed' | 'paused';
  attempts: number;
  lastAttemptAt: string | null;
  nextAttemptAt: string | null;
  sentAt: string | null;
  failureCode: string | null;
  lastHttpStatus: number | null;
};
export type AlertDetails = { alert: Alert; evidence: { entries: SecurityEvent[]; next: EventCursor | null }; webhook?: AlertWebhook };
export type ExtensionAccessSettings = { enabled: boolean; revision: number };
export type ExtensionAccessAlert = {
  id: string;
  installationId: string;
  groupName: string | null;
  policyVersion: number;
  changeCount: number;
  triggeredAt: string;
  acknowledgedAt: string | null;
};
export type ExtensionAccessPage = { entries: ExtensionAccessAlert[]; next: AlertCursor | null };
export type ExtensionAccessDetails = { alert: ExtensionAccessAlert; changes: InventoryExtensionChange[] };
export type AlertChange = {
  alertId: string | null;
  before: AlertSettings | null;
  after: AlertSettings | null;
  extensionAccess?: boolean;
  extensionBefore?: ExtensionAccessSettings;
  extensionAfter?: ExtensionAccessSettings;
};

export const alertPath = (id: string) => `/alerts/${id}`;
export const extensionAlertsPath = '/alerts/extensions';
export const extensionAlertPath = (id: string) => `${extensionAlertsPath}/${id}`;
export const alertNumber = (id: string) => id.slice(0, 8).toUpperCase();
export const alertStatus = (alert: Pick<Alert, 'acknowledgedAt'>) => alert.acknowledgedAt ? 'Acknowledged' : 'Open';
export const alertRollout = ({ rollout }: Alert) => rollout.kind === 'group' ? rollout.groupName ?? 'Unavailable rollout group'
  : rollout.kind === 'baseline' ? 'Organization baseline' : 'Unattributed';

export function alertFilters(search: Record<string, string | string[] | undefined>) {
  const { app = '', status = 'open', beforeAt, beforeId } = search;
  if (typeof app !== 'string' || (app && !aiPromptApps.some((item) => item === app)) ||
      (status !== 'all' && status !== 'open' && status !== 'acknowledged')) return;
  const page = new URLSearchParams();
  if (app) page.set('app', app);
  page.set('status', status);
  const query = new URLSearchParams();
  if (app) query.set('appId', app);
  if (status !== 'all') query.set('status', status);
  const paged = beforeAt !== undefined || beforeId !== undefined;
  if (paged) {
    if (!isEventTimestamp(beforeAt) || !isId(beforeId) || beforeId === '00000000-0000-0000-0000-000000000000') return;
    query.set('beforeAt', beforeAt);
    query.set('beforeId', beforeId);
  }
  return { app, status, page, query, paged };
}
