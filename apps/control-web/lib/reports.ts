import { aiPromptApps, decisions, type Decision } from './control';

export type DecisionCounts = Record<Decision, number>;
export type ReportBreakdown = { id: string; counts: DecisionCounts };
export type AiEnforcementReport = {
  organization: string; startOn: string; asOf: string; days: number; appId: string | null;
  counts: DecisionCounts; daily: { day: string; counts: DecisionCounts }[];
  byApp: ReportBreakdown[]; byRule: ReportBreakdown[];
  bySource?: ReportBreakdown[];
};

export function reportFilters(search: Record<string, string | string[] | undefined>) {
  const { days = '7', appId = '' } = search;
  const app = aiPromptApps.find((id) => id === appId);
  if (Object.keys(search).some((key) => key !== 'days' && key !== 'appId') ||
      (days !== '7' && days !== '30') || (appId !== '' && !app)) return null;
  const query = new URLSearchParams({ days });
  if (app) query.set('appId', app);
  return { days, app, query };
}

export function eventTotal(counts: DecisionCounts) {
  return decisions.reduce((sum, decision) => sum + counts[decision], 0);
}
