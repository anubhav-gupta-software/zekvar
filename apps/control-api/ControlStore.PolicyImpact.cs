using System.Data;
using Npgsql;

namespace Control;

internal sealed record PolicyImpactScope(Guid? GroupId, string? GroupName, int PolicyVersion, bool FollowsBaseline);
internal sealed record PolicyImpactCounts(long Active, long Reporting, long Acknowledged, long ReportingAndAcknowledged);
internal sealed record PolicyImpactCohort(Guid? GroupId, string? GroupName, PolicyImpactCounts Counts);
internal sealed record PolicyImpactReport(DateTimeOffset AsOf, PolicyImpactScope Scope, ComposerReadinessFreshness Freshness,
    PolicyImpactCounts Totals, long OutsideScope, IReadOnlyList<PolicyImpactCohort> Cohorts, IReadOnlyList<ComposerCounts> Composers)
{
    public int SchemaVersion => 1;
}

internal sealed partial class ControlStore
{
    public async Task<(PolicyImpactReport? Report, bool Stale)> PolicyImpact(Guid org, Guid? groupId, int? expectedVersion, CancellationToken ct)
    {
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var snapshot = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        var scope = await ReadPolicyScope(snapshot, org, groupId, ct);
        if (scope is null) return (null, false);
        if (expectedVersion.HasValue && scope.Version != expectedVersion.Value) return (null, true);

        await using var countsQuery = BrowserRead(snapshot, """
            SELECT now(), count(*) FROM installations WHERE organization_id = $1 AND revoked_at IS NULL
            """, org);
        DateTimeOffset asOf;
        long active;
        await using (var counts = await countsQuery.ExecuteReaderAsync(ct))
        {
            await counts.ReadAsync(ct);
            asOf = counts.GetFieldValue<DateTimeOffset>(0);
            active = counts.GetInt64(1);
        }

        await using var command = BrowserRead(snapshot, """
            WITH cohorts AS (
                SELECT NULL::uuid AS id, NULL::text AS name WHERE $2::uuid IS NULL
                UNION ALL SELECT id, name FROM policy_groups
                WHERE organization_id = $1 AND (id = $2 OR ($2 IS NULL AND policy_version IS NULL))
            ), browser_counts AS (
                SELECT i.policy_group_id, count(*) AS active,
                    count(*) FILTER (WHERE i.last_seen_at > now() - make_interval(secs => $4)) AS reporting,
                    count(*) FILTER (WHERE i.applied_policy_version = $3) AS acknowledged,
                    count(*) FILTER (WHERE i.applied_policy_version = $3 AND i.last_seen_at > now() - make_interval(secs => $4)) AS current
                FROM installations i LEFT JOIN policy_groups g ON g.organization_id = i.organization_id AND g.id = i.policy_group_id
                WHERE i.organization_id = $1 AND i.revoked_at IS NULL
                    AND (i.policy_group_id = $2 OR ($2 IS NULL AND g.policy_version IS NULL))
                GROUP BY i.policy_group_id
            )
            SELECT c.id, c.name, COALESCE(b.active, 0), COALESCE(b.reporting, 0), COALESCE(b.acknowledged, 0), COALESCE(b.current, 0)
            FROM cohorts c LEFT JOIN browser_counts b ON b.policy_group_id IS NOT DISTINCT FROM c.id
            ORDER BY c.id IS NOT NULL, lower(c.name), c.id
            """, org, (object?)groupId ?? DBNull.Value, scope.Version, ReadinessHeartbeatSeconds);
        var cohorts = new List<PolicyImpactCohort>();
        await using (var rows = await command.ExecuteReaderAsync(ct))
        {
            while (await rows.ReadAsync(ct))
                cohorts.Add(new(rows.IsDBNull(0) ? null : rows.GetGuid(0), rows.IsDBNull(1) ? null : rows.GetString(1),
                    new(rows.GetInt64(2), rows.GetInt64(3), rows.GetInt64(4), rows.GetInt64(5))));
        }
        var (readiness, _) = await BrowserComposerReadiness(org, new(groupId.HasValue, groupId, null), [], snapshot, ct,
            baselineImpact: groupId is null);
        await snapshot.CommitAsync(ct);
        var totals = new PolicyImpactCounts(cohorts.Sum(row => row.Counts.Active), cohorts.Sum(row => row.Counts.Reporting),
            cohorts.Sum(row => row.Counts.Acknowledged), cohorts.Sum(row => row.Counts.ReportingAndAcknowledged));
        return (new(asOf, new(groupId, scope.Name, scope.Version, groupId.HasValue && !scope.Published),
            new(ReadinessHeartbeatSeconds, ReadinessObservationSeconds), totals, active - totals.Active, cohorts, readiness.Apps), false);
    }
}
