using System.Data;
using System.Text.Json;
using Npgsql;

namespace Control;

internal sealed record ComposerCheck(string State, DateTimeOffset? CheckedAt);
internal sealed record ComposerCounts(string AppId, Dictionary<string, long> Counts);
internal sealed record BrowserComposerReadiness(long ActiveInstallations, IReadOnlyList<ComposerCounts> Apps);
internal sealed record ComposerReadinessScope(string RolloutGroup, string? RolloutGroupName, string? BrowserVersion, int? TargetPolicyVersion);
internal sealed record ComposerReadinessFreshness(int HeartbeatSeconds, int ObservationSeconds);
internal sealed record ComposerReadinessReport(DateTimeOffset AsOf, ComposerReadinessScope Scope, ComposerReadinessFreshness Freshness,
    long ActiveInstallations, IReadOnlyList<ComposerCounts> Apps)
{
    public int SchemaVersion => 1;
}

internal sealed partial class ControlStore
{
    private const int ReadinessHeartbeatSeconds = 90;
    private const int ReadinessObservationSeconds = 24 * 60 * 60;

    public async Task<ComposerReadinessReport?> ReadComposerReadinessReport(Guid organizationId, BrowserHealthFilter filter, CancellationToken ct)
    {
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var snapshot = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        await using var scopeQuery = BrowserRead(snapshot, """
            SELECT now(), g.name, CASE WHEN $2 THEN COALESCE(g.policy_version, org.policy_version) END
            FROM organizations org
            LEFT JOIN policy_groups g ON g.organization_id = org.id AND g.id = $3::uuid
            WHERE org.id = $1 AND ($3::uuid IS NULL OR g.id IS NOT NULL)
            """, organizationId, filter.Scoped, (object?)filter.GroupId ?? DBNull.Value);
        DateTimeOffset asOf;
        ComposerReadinessScope scope;
        await using (var scopeRow = await scopeQuery.ExecuteReaderAsync(ct))
        {
            if (!await scopeRow.ReadAsync(ct)) return null;
            asOf = scopeRow.GetFieldValue<DateTimeOffset>(0);
            scope = new(filter.GroupId?.ToString() ?? (filter.Scoped ? "baseline" : "all"),
                scopeRow.IsDBNull(1) ? null : scopeRow.GetString(1), filter.Version,
                scopeRow.IsDBNull(2) ? null : scopeRow.GetInt32(2));
        }
        var (readiness, _) = await BrowserComposerReadiness(organizationId, filter, [], snapshot, ct);
        await snapshot.CommitAsync(ct);
        return new(asOf, scope, new(ReadinessHeartbeatSeconds, ReadinessObservationSeconds), readiness.ActiveInstallations, readiness.Apps);
    }

    private async Task<(BrowserComposerReadiness Summary, Dictionary<Guid, Dictionary<string, ComposerCheck>> Checks)> BrowserComposerReadiness(
        Guid organizationId, BrowserHealthFilter filter, IReadOnlyList<Installation> detail, NpgsqlTransaction snapshot, CancellationToken ct)
    {
        var visible = detail.Where(row => row.RevokedAt is null).Select(row => row.InstallationId).ToArray();
        await using var command = BrowserRead(snapshot, """
            WITH states AS (
                SELECT i.id, app.app_id,
                    CASE WHEN NOT app.enabled THEN 'off'
                        WHEN i.applied_policy_version IS DISTINCT FROM p.version THEN 'policy_pending'
                        WHEN o.checked_at IS NULL THEN 'unobserved'
                        WHEN i.last_seen_at <= now() - make_interval(secs => $6)
                            OR o.checked_at <= now() - make_interval(secs => $7) THEN 'stale'
                        WHEN o.coverage = 'ready' THEN 'detected' ELSE 'unsupported' END AS state,
                    CASE WHEN app.enabled AND i.applied_policy_version = p.version THEN o.checked_at END AS checked_at
                FROM installations i JOIN organizations org ON org.id = i.organization_id
                LEFT JOIN policy_groups g ON g.organization_id = org.id AND g.id = i.policy_group_id
                JOIN policy_versions p ON p.organization_id = org.id AND p.version = COALESCE(g.policy_version, org.policy_version)
                CROSS JOIN LATERAL (VALUES ('chatgpt', true), ('claude', p.claude_prompt_enabled), ('gemini', true)) app(app_id, enabled)
                LEFT JOIN composer_observations o ON o.installation_id = i.id AND o.app_id = app.app_id
                    AND o.assignment_version = i.assignment_version AND o.policy_version = p.version
                WHERE i.organization_id = $1 AND i.revoked_at IS NULL AND (NOT $2 OR i.policy_group_id IS NOT DISTINCT FROM $3::uuid)
                    AND ($4::text IS NULL OR i.extension_version = $4 OR ($4 = 'unreported' AND i.extension_version IS NULL))
            )
            SELECT app_id, state, count(*), jsonb_object_agg(id, checked_at) FILTER (WHERE id = ANY($5))
            FROM states GROUP BY app_id, state
            """, organizationId, filter.Scoped, (object?)filter.GroupId ?? DBNull.Value, (object?)filter.Version ?? DBNull.Value, visible,
            ReadinessHeartbeatSeconds, ReadinessObservationSeconds);
        var counts = DiscoveryCatalog.AppIds.ToDictionary(app => app, _ => new Dictionary<string, long>(StringComparer.Ordinal)
        {
            ["detected"] = 0, ["unsupported"] = 0, ["stale"] = 0, ["unobserved"] = 0, ["policy_pending"] = 0, ["off"] = 0,
        });
        var checks = visible.ToDictionary(id => id, _ => new Dictionary<string, ComposerCheck>(StringComparer.Ordinal));
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct))
        {
            var app = rows.GetString(0);
            var state = rows.GetString(1);
            counts[app][state] = rows.GetInt64(2);
            if (rows.IsDBNull(3)) continue;
            var details = JsonSerializer.Deserialize<Dictionary<Guid, DateTimeOffset?>>(rows.GetString(3))!;
            foreach (var (id, checkedAt) in details) checks[id].Add(app, new(state, checkedAt));
        }
        var apps = DiscoveryCatalog.AppIds.Select(app => new ComposerCounts(app, counts[app])).ToArray();
        return (new(apps[0].Counts.Values.Sum(), apps), checks);
    }
}
