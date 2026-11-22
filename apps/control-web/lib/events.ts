import { decisions, isId, isPromptApp, rolloutFilter, type SecurityEvent } from './control';

export type EventCursor = { receivedAt: string; eventId: string; installationId: string };
export type EventPage = { entries: SecurityEvent[]; next: EventCursor | null; rolloutAvailable?: boolean };
type Search = Record<string, string | string[] | undefined>;
const emptyId = '00000000-0000-0000-0000-000000000000';

function nonEmptyId(value: unknown) {
  return isId(value) && value !== emptyId ? value : undefined;
}

function timestamp(value: unknown): value is string {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})$/.test(value)
    && Number.isFinite(Date.parse(value));
}

export function setEventCursor(query: URLSearchParams, cursor: EventCursor) {
  query.set('beforeAt', cursor.receivedAt);
  query.set('beforeEventId', cursor.eventId);
  query.set('beforeInstallationId', cursor.installationId);
}

export function eventFilters(search: Search) {
  const query = new URLSearchParams();
  const page = new URLSearchParams();
  const app = isPromptApp(search.app) ? search.app : '';
  const decision = decisions.find((value) => value === search.decision) ?? '';
  const period = search.period === 'day' || search.period === 'week' ? search.period : '';
  const installation = nonEmptyId(search.installation) ?? '';
  const invalidInstallation = search.installation !== undefined && search.installation !== '' && !installation;
  const rolloutGroup = rolloutFilter(search.eventGroup);
  if (app) {
    page.set('app', app);
    query.set('appId', app);
  }
  if (decision) {
    page.set('decision', decision);
    query.set('decision', decision);
  }
  if (installation) {
    page.set('installation', installation);
    query.set('installationId', installation);
  }
  if (rolloutGroup) {
    page.set('eventGroup', rolloutGroup);
    query.set('rolloutGroup', rolloutGroup);
  }
  if (period) {
    const since = timestamp(search.since) ? search.since
      : new Date(Date.now() - (period === 'day' ? 1 : 7) * 86_400_000).toISOString();
    page.set('period', period);
    page.set('since', since);
    query.set('since', since);
  }
  const { beforeAt, beforeEventId, beforeInstallationId } = search;
  const eventId = nonEmptyId(beforeEventId);
  const browserId = nonEmptyId(beforeInstallationId);
  const cursor = timestamp(beforeAt) && eventId && browserId
    ? { receivedAt: beforeAt, eventId, installationId: browserId } : undefined;
  const invalidCursor = !cursor && [beforeAt, beforeEventId, beforeInstallationId].some((value) => value !== undefined);
  return { app, decision, period, installation, rolloutGroup, invalidInstallation, invalidCursor, cursor, page, query };
}
