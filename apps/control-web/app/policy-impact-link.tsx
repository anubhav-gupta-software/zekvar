import { policyImpactQuery } from '../lib/policy-impact';

export function PolicyImpactLink({ groupId, version, label = 'Review rollout impact' }: {
  groupId?: string | null; version?: number; label?: string;
}) {
  return <a className="button small" target="_blank" rel="noopener"
    href={`/reports/policy-impact?${policyImpactQuery(groupId, version)}`}>{label}</a>;
}
