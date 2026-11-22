import { aiPromptApps, decisions, rolloutFilter, type Decision } from './control';

export type DecisionCounts = Record<Decision, number>;
export type ReportBreakdown = { id: string; counts: DecisionCounts };
export type AiEnforcementReport = {
  organization: string; startOn: string; asOf: string; days: number; appId: string | null;
  counts: DecisionCounts; daily: { day: string; counts: DecisionCounts }[];
  byApp: ReportBreakdown[]; byRule: ReportBreakdown[];
  bySource?: ReportBreakdown[];
  rolloutGroup?: string | null;
};

export function reportFilters(search: Record<string, string | string[] | undefined>) {
  const { days = '7', appId = '' } = search;
  const rolloutGroup = rolloutFilter(search.rolloutGroup);
  const app = aiPromptApps.find((id) => id === appId);
  if (Object.keys(search).some((key) => !['days', 'appId', 'rolloutGroup'].includes(key)) ||
      (days !== '7' && days !== '30') || (appId !== '' && !app) || rolloutGroup === undefined) return null;
  const query = new URLSearchParams({ days });
  if (app) query.set('appId', app);
  if (rolloutGroup) query.set('rolloutGroup', rolloutGroup);
  return { days, app, rolloutGroup, query };
}

export function eventTotal(counts: DecisionCounts) {
  return decisions.reduce((sum, decision) => sum + counts[decision], 0);
}
