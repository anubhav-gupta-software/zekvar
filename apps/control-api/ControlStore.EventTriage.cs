using System.Data;
using System.Text.Json;
using Npgsql;

namespace Control;

internal sealed partial class ControlStore
{
    private const string EventFields = """
        e.event_id, e.installation_id, e.occurred_at, e.received_at, e.policy_version, e.decision, e.app_id, e.rule_id, e.upload_method,
        e.rollout_attributed, e.rollout_group_id, g.name, t.revision, t.status, t.disposition, t.updated_at,
        a.id, a.display_name, a.revoked_at IS NULL AND (a.expires_at IS NULL OR a.expires_at > now()), e.clipboard_paste
        """;
    private const string EventSources = """
        security_events e LEFT JOIN retention_cutoffs r ON e.organization_id = r.organization_id
        LEFT JOIN policy_groups g ON e.organization_id = g.organization_id AND e.rollout_group_id = g.id
        """;
    private const string EventTriageJoin = """
        JOIN event_triage t ON t.organization_id = e.organization_id AND t.installation_id = e.installation_id AND t.event_id = e.event_id
        LEFT JOIN control_access a ON a.organization_id = t.organization_id AND a.id = t.assignee_id
        """;
    private const string EventRetained = "(r.event_cutoff IS NULL OR LEAST(e.occurred_at, e.received_at) >= r.event_cutoff)";
    private const string EventDetailSql = $"""
        SELECT {EventFields}
        FROM {EventSources} LEFT {EventTriageJoin}
        WHERE e.organization_id = $1 AND e.installation_id = $2 AND e.event_id = $3 AND {EventRetained}
        """;

    private static StoredEvent ReadEvent(NpgsqlDataReader rows) => new(
        rows.GetGuid(0), rows.GetGuid(1), rows.GetDateTime(2), rows.GetDateTime(3), rows.GetInt32(4), rows.GetString(5),
        rows.GetString(6), rows.GetString(7), rows.IsDBNull(8) ? null : rows.GetString(8),
        rows.GetBoolean(9) ? rows.IsDBNull(10) ? new("baseline") : new("group", rows.GetGuid(10), rows.GetString(11)) : new("unattributed"),
        rows.IsDBNull(12) ? null : new(rows.GetInt32(12), rows.GetString(13), rows.IsDBNull(14) ? null : rows.GetString(14),
            rows.IsDBNull(16) ? null : new(rows.GetGuid(16), rows.GetString(17), rows.GetBoolean(18)), rows.GetDateTime(15)), rows.GetBoolean(19));

    public async Task<TriageAssignee[]> EventTriageAssignees(Guid organizationId, CancellationToken ct)
    {
        await using var command = Command("""
            SELECT id, display_name FROM control_access
            WHERE organization_id = $1 AND role = 'administrator' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())
            ORDER BY lower(display_name), id
            """, organizationId);
        await using var rows = await command.ExecuteReaderAsync(ct);
        var assignees = new List<TriageAssignee>();
        while (await rows.ReadAsync(ct)) assignees.Add(new(rows.GetGuid(0), rows.GetString(1), true));
        return assignees.ToArray();
    }

    public async Task<EventDetails?> EventDetail(Guid org, Guid installationId, Guid eventId, CancellationToken ct)
    {
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        var entry = await ReadEventDetail(transaction, org, installationId, eventId, ct);
        if (entry is null) return null;
        await using var command = new NpgsqlCommand("""
            SELECT a.id, a.occurred_at, a.event_triage_change, actor.id, actor.display_name, actor.role
            FROM control_audit a LEFT JOIN retention_cutoffs r ON r.organization_id = a.organization_id
            LEFT JOIN control_access actor ON actor.organization_id = a.organization_id AND actor.id = a.actor_access_id
            WHERE a.organization_id = $1 AND a.action = 'event_triage_changed'
                AND a.event_triage_change->>'installationId' = $2::uuid::text AND a.event_triage_change->>'eventId' = $3::uuid::text
                AND (r.audit_cutoff IS NULL OR a.occurred_at >= r.audit_cutoff)
            ORDER BY a.occurred_at DESC, a.id DESC LIMIT 50
            """, connection, transaction);
        AddParameters(command, org, installationId, eventId);
        var activity = new List<EventTriageActivity>();
        await using (var rows = await command.ExecuteReaderAsync(ct))
            while (await rows.ReadAsync(ct))
                activity.Add(new(rows.GetGuid(0), rows.GetDateTime(1),
                    rows.IsDBNull(3) ? null : new(rows.GetGuid(3), rows.GetString(4), rows.GetString(5)),
                    JsonSerializer.Deserialize<EventTriageChange>(rows.GetString(2), JsonSerializerOptions.Web)!));
        var incident = await FindCaseForEvent(transaction, org, installationId, eventId, ct);
        await transaction.CommitAsync(ct);
        return new(entry, activity.ToArray(), incident);
    }

    private static async Task<StoredEvent?> ReadEventDetail(NpgsqlTransaction transaction, Guid org, Guid installationId, Guid eventId, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(EventDetailSql, transaction.Connection, transaction);
        AddParameters(command, org, installationId, eventId);
        await using var rows = await command.ExecuteReaderAsync(ct);
        return await rows.ReadAsync(ct) ? ReadEvent(rows) : null;
    }

    public async Task<TriageResult> ChangeEventTriage(RequestIdentity identity, Guid installationId, Guid eventId,
        SetEventTriage request, CancellationToken ct)
    {
        var org = identity.OrganizationId;
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        if (!await LockEvent(transaction, org, installationId, eventId, ct)) return new();
        var entry = await ReadEventDetail(transaction, org, installationId, eventId, ct);
        if (entry is null) return new();

        var current = entry.Triage ?? EventTriage.Initial;
        var desired = new EventTriageState(request.Status!, request.Disposition, request.AssigneeId);
        if (current.State() == desired && RetryRevision(current.Revision, request.ExpectedRevision))
            return new(current);
        if (current.Revision != request.ExpectedRevision) return new(Error: "event_triage_stale");
        var assignee = current.Assignee;
        if (request.AssigneeId is { } assigneeId && assigneeId != assignee?.Id)
        {
            assignee = await FindActiveTriageAssignee(transaction, org, assigneeId, ct);
            if (assignee is null) return new(Error: "event_assignee_unavailable");
        }
        if (request.AssigneeId is null) assignee = null;

        var revision = current.Revision + 1;
        var change = new EventTriageChange(installationId, eventId, revision, current.State(), desired);
        await using var write = new NpgsqlCommand("""
            WITH saved AS (
                INSERT INTO event_triage (organization_id, installation_id, event_id, revision, status, disposition, assignee_id, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, statement_timestamp())
                ON CONFLICT (installation_id, event_id) DO UPDATE SET
                    revision = EXCLUDED.revision, status = EXCLUDED.status, disposition = EXCLUDED.disposition,
                    assignee_id = EXCLUDED.assignee_id, updated_at = EXCLUDED.updated_at
                RETURNING updated_at
            ), audit AS (
                INSERT INTO control_audit (organization_id, occurred_at, action, actor_access_id, event_triage_change)
                SELECT $1, updated_at, 'event_triage_changed', $8, $9::jsonb FROM saved
            )
            SELECT updated_at FROM saved
            """, connection, transaction);
        AddParameters(write, org, installationId, eventId, revision, desired.Status, (object?)desired.Disposition ?? DBNull.Value,
            (object?)request.AssigneeId ?? DBNull.Value, (object?)identity.Access?.Id ?? DBNull.Value,
            JsonSerializer.Serialize(change, JsonSerializerOptions.Web));
        var updatedAt = (DateTime)(await write.ExecuteScalarAsync(ct))!;
        await transaction.CommitAsync(ct);
        return new(new(revision, desired.Status, desired.Disposition, assignee, updatedAt));
    }

    private static bool RetryRevision(int current, int? expected) => expected == current || expected == current - 1;

    private static async Task<bool> LockEvent(NpgsqlTransaction transaction, Guid org, Guid installationId, Guid eventId, CancellationToken ct)
    {
        await using var gate = new NpgsqlCommand("""
            SELECT 1 FROM security_events WHERE organization_id = $1 AND installation_id = $2 AND event_id = $3 FOR UPDATE
            """, transaction.Connection, transaction);
        AddParameters(gate, org, installationId, eventId);
        return await gate.ExecuteScalarAsync(ct) is not null;
    }

    private static async Task<TriageAssignee?> FindActiveTriageAssignee(NpgsqlTransaction transaction, Guid org, Guid id, CancellationToken ct)
    {
        await using var verify = new NpgsqlCommand("""
            SELECT display_name FROM control_access WHERE organization_id = $1 AND id = $2 AND role = 'administrator'
                AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now()) FOR SHARE
            """, transaction.Connection, transaction);
        AddParameters(verify, org, id);
        return await verify.ExecuteScalarAsync(ct) is string name ? new(id, name, true) : null;
    }
}
