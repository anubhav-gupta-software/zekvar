using Npgsql;

namespace Control;

internal sealed record RequestPromptException(Guid EventId, string AppId);
internal sealed record DecidePromptException(string Status);
internal sealed record PromptExceptionReceipt(Guid Id, string Status);
internal sealed record PromptExceptionRequest(Guid Id, Guid InstallationId, Guid EventId, string AppId, string RuleId, int PolicyVersion,
    string Decision, Guid? GroupId, string? GroupName, DateTimeOffset RequestedAt, string Status, DateTimeOffset? DecidedAt,
    string? DecidedBy, int? PublishedVersion);
internal sealed record PromptRequestResult(PromptExceptionReceipt? Receipt = null, string? Error = null);

internal sealed partial class ControlStore
{
    private const string RequestEventJoin = """
        JOIN prompt_exception_requests q ON q.organization_id = e.organization_id AND q.installation_id = e.installation_id AND q.event_id = e.event_id
        """;
    private const string RequestColumns = """
        q.id, e.installation_id, e.event_id, e.app_id, e.rule_id, e.policy_version, e.decision,
        e.rollout_group_id, g.name, q.requested_at, q.status, q.decided_at,
        CASE WHEN q.decided_at IS NOT NULL THEN COALESCE(a.display_name, 'Organization owner') END, q.published_version
        """;

    public async Task<PromptExceptionReceipt?> RequestException(RequestIdentity identity, RequestPromptException input, CancellationToken ct)
    {
        var org = identity.OrganizationId;
        var browser = identity.InstallationId!.Value;
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using var lockBrowser = BrowserRead(transaction, """
            SELECT id FROM installations WHERE organization_id = $1 AND id = $2 AND revoked_at IS NULL FOR UPDATE
            """, org, browser);
        if (await lockBrowser.ExecuteScalarAsync(ct) is null) return null;
        await using var command = BrowserRead(transaction, $"""
            WITH evidence AS (
                SELECT e.* FROM {EventSources}
                JOIN installations i ON e.organization_id = i.organization_id AND e.installation_id = i.id
                JOIN organizations o ON o.id = i.organization_id
                LEFT JOIN policy_groups current_group ON current_group.organization_id = i.organization_id AND current_group.id = i.policy_group_id
                WHERE e.organization_id = $1 AND e.installation_id = $2 AND e.event_id = $3 AND e.app_id = $4
                    AND e.decision IN ('warn', 'block') AND e.upload_method IS NULL AND NOT e.clipboard_paste
                    AND e.rule_id IN ('fixture-secret', 'github-classic-pat', 'github-app-or-fine-grained-token', 'payment-card-number',
                        'pem-private-key', 'organization-identifier', 'us-social-security-number')
                    AND e.rollout_attributed AND e.rollout_group_id IS NOT DISTINCT FROM i.policy_group_id
                    AND e.policy_version = COALESCE(current_group.policy_version, o.policy_version)
                    AND e.occurred_at BETWEEN now() - interval '1 hour' AND now() + interval '2 minutes' AND {EventRetained}
                FOR SHARE OF e
            ), existing AS (
                SELECT q.id, q.status FROM {EventSources} {RequestEventJoin}
                JOIN evidence target ON e.installation_id = target.installation_id
                    AND e.organization_id = target.organization_id AND e.app_id = target.app_id AND e.rule_id = target.rule_id
                    AND e.policy_version = target.policy_version AND e.rollout_group_id IS NOT DISTINCT FROM target.rollout_group_id
                WHERE q.requested_at >= now() - interval '24 hours' AND {EventRetained}
                ORDER BY q.requested_at DESC, q.id LIMIT 1
            ), inserted AS (
                INSERT INTO prompt_exception_requests (organization_id, id, installation_id, event_id)
                SELECT organization_id, $5, installation_id, event_id FROM evidence WHERE NOT EXISTS (SELECT FROM existing)
                ON CONFLICT (installation_id, event_id) DO NOTHING
                RETURNING id, status
            )
            SELECT id, status FROM inserted UNION ALL SELECT id, status FROM existing
            """, org, browser, input.EventId, input.AppId, Guid.NewGuid());
        PromptExceptionReceipt? result;
        await using (var rows = await command.ExecuteReaderAsync(ct))
            result = await rows.ReadAsync(ct) ? new(rows.GetGuid(0), rows.GetString(1)) : null;
        await transaction.CommitAsync(ct);
        return result;
    }

    public async Task<IReadOnlyList<PromptExceptionRequest>> PromptExceptionRequests(Guid org, bool pending, CancellationToken ct)
    {
        await using var command = Command($"""
            SELECT {RequestColumns} FROM {EventSources} {RequestEventJoin}
            LEFT JOIN control_access a ON q.organization_id = a.organization_id AND q.decided_by = a.id
            WHERE q.organization_id = $1 AND (q.status = 'pending') = $2 AND {EventRetained}
            ORDER BY CASE WHEN $2 THEN q.requested_at END ASC, q.requested_at DESC, q.id LIMIT 100
            """, org, pending);
        var requests = new List<PromptExceptionRequest>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct)) requests.Add(ReadPromptRequest(rows));
        return requests;
    }

    public async Task<PromptRequestResult> DecideException(RequestIdentity identity, Guid id, string status, CancellationToken ct)
    {
        var org = identity.OrganizationId;
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await LockPolicySettings(transaction, org, ct);
        await using var lookup = BrowserRead(transaction, $"""
            SELECT {RequestColumns} FROM {EventSources} {RequestEventJoin}
            LEFT JOIN control_access a ON q.organization_id = a.organization_id AND q.decided_by = a.id
            WHERE q.organization_id = $1 AND q.id = $2 AND {EventRetained}
            FOR UPDATE OF q FOR SHARE OF e
            """, org, id);
        PromptExceptionRequest request;
        await using (var rows = await lookup.ExecuteReaderAsync(ct))
        {
            if (!await rows.ReadAsync(ct)) return new();
            request = ReadPromptRequest(rows);
        }
        if (request.Status == status) return new(new(id, status));
        if (request.Status != "pending") return new(Error: "prompt_request_decided");

        int? published = null;
        if (status == "exception_available")
        {
            await using var stillAssigned = BrowserRead(transaction, """
                SELECT id FROM installations WHERE organization_id = $1 AND id = $2
                    AND revoked_at IS NULL AND policy_group_id IS NOT DISTINCT FROM $3::uuid FOR SHARE
                """, org, request.InstallationId, (object?)request.GroupId ?? DBNull.Value);
            if (await stillAssigned.ExecuteScalarAsync(ct) is null) return new(Error: "prompt_request_assignment_changed");
            var scope = await ReadPolicyScope(transaction, org, request.GroupId, ct);
            var policy = scope is not null && (request.GroupId is null || scope.Published)
                ? await ReadPolicySnapshot(transaction, org, scope.Version, ct) : null;
            if (policy is null || !HasLiveException(policy, request)) return new(Error: "prompt_request_exception_required");
            published = policy.Version;
        }
        await using var update = BrowserRead(transaction, """
            UPDATE prompt_exception_requests SET status = $3, decided_at = clock_timestamp(), decided_by = $4, published_version = $5
            WHERE organization_id = $1 AND id = $2
            """, org, id, status, (object?)identity.Access?.Id ?? DBNull.Value, (object?)published ?? DBNull.Value);
        await update.ExecuteNonQueryAsync(ct);
        await transaction.CommitAsync(ct);
        return new(new(id, status));
    }

    private static bool HasLiveException(Policy policy, PromptExceptionRequest request)
    {
        var mode = policy.PromptModeForApp(request.AppId, request.RuleId);
        return mode is "warn" or "block" && (request.AppId != FixtureContract.Claude || policy.ClaudePromptEnabled) &&
            policy.PromptExceptions?.Any(entry => entry.AppId == request.AppId && entry.RuleId == request.RuleId &&
                entry.ExpiresAt > DateTimeOffset.UtcNow) == true;
    }

    private static PromptExceptionRequest ReadPromptRequest(NpgsqlDataReader row) =>
        new(row.GetGuid(0), row.GetGuid(1), row.GetGuid(2), row.GetString(3), row.GetString(4), row.GetInt32(5), row.GetString(6),
            row.IsDBNull(7) ? null : row.GetGuid(7), row.IsDBNull(8) ? null : row.GetString(8), row.GetFieldValue<DateTimeOffset>(9),
            row.GetString(10), row.IsDBNull(11) ? null : row.GetFieldValue<DateTimeOffset>(11),
            row.IsDBNull(12) ? null : row.GetString(12), row.IsDBNull(13) ? null : row.GetInt32(13));
}
