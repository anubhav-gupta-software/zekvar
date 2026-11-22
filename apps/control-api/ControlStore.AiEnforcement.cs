using System.Globalization;

namespace Control;

internal sealed record AiReportQuery(int Days, string? AppId, DateTimeOffset AsOf, string? RolloutGroup, EventRolloutFilter Rollout)
{
    public static AiReportQuery? Parse(IQueryCollection query, DateTimeOffset now)
    {
        if (query.Any(entry => entry.Key is not ("days" or "appId" or "asOf" or "rolloutGroup") || entry.Value.Count != 1)) return null;
        var days = query["days"].ToString();
        var appId = query["appId"].ToString();
        var rolloutGroup = query["rolloutGroup"].ToString();
        if ((query.ContainsKey("days") && days is not ("7" or "30")) ||
            (query.ContainsKey("appId") && !FixtureContract.IsAiPromptApp(appId)) ||
            EventRolloutFilter.Parse(rolloutGroup) is not { } rollout) return null;

        // Match the precision in report links so the initial view and download use the same upper bound.
        var end = now.ToUnixTimeMilliseconds();
        if (query.ContainsKey("asOf") && (!long.TryParse(query["asOf"].ToString(), NumberStyles.None, CultureInfo.InvariantCulture, out end)
            || end < now.AddDays(-1).ToUnixTimeMilliseconds() || end > now.ToUnixTimeMilliseconds())) return null;
        return new(days == "30" ? 30 : 7, appId.Length == 0 ? null : appId, DateTimeOffset.FromUnixTimeMilliseconds(end),
            rolloutGroup.Length == 0 ? null : rolloutGroup, rollout);
    }
}

internal sealed record AiEnforcementReport(string Organization, DateOnly StartOn, DateTimeOffset AsOf, int Days, string? AppId, string? RolloutGroup,
    Dictionary<string, long> Counts, AiReportDay[] Daily, AiReportBreakdown[] ByApp, AiReportBreakdown[] ByRule, AiReportBreakdown[] BySource);
internal sealed record AiReportDay(DateOnly Day, Dictionary<string, long> Counts);
internal sealed record AiReportBreakdown(string Id, Dictionary<string, long> Counts);

internal sealed partial class ControlStore
{
    public async Task<AiEnforcementReport> ReadAiEnforcement(RequestIdentity identity, AiReportQuery query, CancellationToken ct)
    {
        var start = DateOnly.FromDateTime(query.AsOf.UtcDateTime).AddDays(1 - query.Days);
        var totals = EmptyDecisionCounts();
        var days = Enumerable.Range(0, query.Days).Select(offset => new AiReportDay(start.AddDays(offset), EmptyDecisionCounts())).ToArray();
        var apps = new SortedDictionary<string, Dictionary<string, long>>(StringComparer.Ordinal);
        var rules = new SortedDictionary<string, Dictionary<string, long>>(StringComparer.Ordinal);
        var sources = new SortedDictionary<string, Dictionary<string, long>>(StringComparer.Ordinal);

        await using var command = Command("""
            SELECT (occurred_at AT TIME ZONE 'UTC')::date AS day, app_id, rule_id,
                CASE WHEN upload_method IS NULL THEN 'prompt' WHEN rule_id = 'ai-file-upload' THEN 'file_policy' ELSE 'file_content' END AS source,
                decision, count(*)
            FROM security_events e LEFT JOIN retention_cutoffs r ON r.organization_id = e.organization_id
            WHERE e.organization_id = $1 AND occurred_at >= $2 AND occurred_at <= $3 AND received_at <= $3
                AND (r.event_cutoff IS NULL OR LEAST(occurred_at, received_at) >= r.event_cutoff)
                AND app_id <> 'local-prompt-fixture' AND ($4::text IS NULL OR app_id = $4)
                AND ($5::boolean IS NULL OR e.rollout_attributed = $5
                    AND (e.rollout_group_id = $6::uuid OR ($6 IS NULL AND e.rollout_group_id IS NULL)))
            GROUP BY GROUPING SETS ((decision), (day, decision), (app_id, decision), (rule_id, decision), (source, decision))
            """, identity.OrganizationId, start.ToDateTime(TimeOnly.MinValue, DateTimeKind.Utc), query.AsOf.UtcDateTime,
            (object?)query.AppId ?? DBNull.Value, (object?)query.Rollout.Attributed ?? DBNull.Value, (object?)query.Rollout.GroupId ?? DBNull.Value);
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct))
        {
            var counts = !rows.IsDBNull(0) ? days[rows.GetFieldValue<DateOnly>(0).DayNumber - start.DayNumber].Counts
                : !rows.IsDBNull(1) ? Bucket(apps, rows.GetString(1))
                : !rows.IsDBNull(2) ? Bucket(rules, rows.GetString(2))
                : !rows.IsDBNull(3) ? Bucket(sources, rows.GetString(3)) : totals;
            counts[rows.GetString(4)] = rows.GetInt64(5);
        }
        return new(identity.OrganizationSlug!, start, query.AsOf, query.Days, query.AppId, query.RolloutGroup, totals, days,
            apps.Select(entry => new AiReportBreakdown(entry.Key, entry.Value)).ToArray(),
            rules.Select(entry => new AiReportBreakdown(entry.Key, entry.Value)).ToArray(),
            sources.Select(entry => new AiReportBreakdown(entry.Key, entry.Value)).ToArray());
    }

    private static Dictionary<string, long> Bucket(SortedDictionary<string, Dictionary<string, long>> buckets, string id)
    {
        if (!buckets.TryGetValue(id, out var counts)) buckets[id] = counts = EmptyDecisionCounts();
        return counts;
    }

    private static Dictionary<string, long> EmptyDecisionCounts() => new(StringComparer.Ordinal)
    {
        ["monitor"] = 0, ["warn"] = 0, ["block"] = 0, ["warn_override"] = 0, [FixtureContract.ExceptionApplied] = 0
    };
}
