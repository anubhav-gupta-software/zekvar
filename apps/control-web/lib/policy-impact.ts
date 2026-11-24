import type { BrowserComposerReadiness } from './control';

export type ImpactCounts = { active: number; reporting: number; acknowledged: number; reportingAndAcknowledged: number };
export type PolicyImpactReport = {
  schemaVersion: 1;
  asOf: string;
  scope: { groupId: string | null; groupName: string | null; policyVersion: number; followsBaseline: boolean };
  freshness: { heartbeatSeconds: number; observationSeconds: number };
  totals: ImpactCounts;
  outsideScope: number;
  cohorts: { groupId: string | null; groupName: string | null; counts: ImpactCounts }[];
  composers: BrowserComposerReadiness['apps'];
};

export function policyImpactQuery(groupId?: string | null, version?: number) {
  const query = new URLSearchParams({ scope: groupId ?? 'baseline' });
  if (version !== undefined) query.set('expectedVersion', String(version));
  return query;
}
