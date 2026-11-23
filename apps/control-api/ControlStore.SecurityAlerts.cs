using System.Data;
using System.Text.Json;
using Npgsql;

namespace Control;

internal sealed partial class ControlStore
{
    private const int AlertPageSize = 100;
    private const string AlertFields = """
        a.id, a.app_id, a.rollout_attributed, a.rollout_group_id, g.name, a.window_start,
        a.window_start + interval '15 minutes', a.threshold, a.block_count, a.triggered_at, a.acknowledged_at
        """;
    private const string AlertSources = """
        security_alert_windows a
        LEFT JOIN retention_cutoffs r ON r.organization_id = a.organization_id
        LEFT JOIN policy_groups g ON g.organization_id = a.organization_id AND g.id = a.rollout_group_id
        """;
    private const string AlertVisible = """
        a.triggered_at IS NOT NULL
        AND a.first_received_at >= GREATEST(now() - interval '30 days', r.event_cutoff)
        """;
    private const string AlertExpired = """
        a.first_received_at < GREATEST(now() - interval '30 days', r.event_cutoff)
        OR (a.triggered_at IS NULL AND a.window_start < now() - interval '1 hour')
        """;

    public async Task<SecurityAlertSettings> GetSecurityAlertSettings(Guid organizationId, CancellationToken ct)
    {
        await using var command = Command("""
            SELECT enabled, threshold, revision FROM security_alert_settings WHERE organization_id = $1
            """, organizationId);
        await using var rows = await command.ExecuteReaderAsync(ct);
        return await rows.ReadAsync(ct) ? ReadAlertSettings(rows) : SecurityAlertSettings.Default;
    }

    public async Task<SecurityAlertSettings?> UpdateSecurityAlertSettings(RequestIdentity identity, SetSecurityAlertSettings request, CancellationToken ct)
    {
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using var ensure = BrowserRead(transaction, """
            INSERT INTO security_alert_settings (organization_id) VALUES ($1) ON CONFLICT DO NOTHING
            """, identity.OrganizationId);
        await ensure.ExecuteNonQueryAsync(ct);
        await using var read = BrowserRead(transaction, """
            SELECT enabled, threshold, revision FROM security_alert_settings WHERE organization_id = $1 FOR UPDATE
            """, identity.OrganizationId);
        SecurityAlertSettings previous;
        await using (var rows = await read.ExecuteReaderAsync(ct))
        {
            await rows.ReadAsync(ct);
            previous = ReadAlertSettings(rows);
        }
        var sameSettings = previous.Enabled == request.Enabled && previous.Threshold == request.Threshold;
        if (sameSettings && (request.ExpectedRevision == previous.Revision || request.ExpectedRevision == previous.Revision - 1))
            return previous;
        if (request.ExpectedRevision != previous.Revision) return null;

        var current = new SecurityAlertSettings(request.Enabled!.Value, request.Threshold, previous.Revision + 1);
        await using var write = BrowserRead(transaction, """
            WITH changed AS (
                UPDATE security_alert_settings SET enabled = $2, threshold = $3, revision = $4
                WHERE organization_id = $1 RETURNING organization_id
            )
            INSERT INTO control_audit (organization_id, action, security_alert_change, actor_access_id)
            SELECT organization_id, 'security_alert_settings_changed', $5::jsonb, $6 FROM changed
            """, identity.OrganizationId, current.Enabled, current.Threshold, current.Revision,
            JsonSerializer.Serialize(new SecurityAlertChange(Before: previous, After: current), JsonSerializerOptions.Web),
            (object?)identity.Access?.Id ?? DBNull.Value);
        await write.ExecuteNonQueryAsync(ct);
        await transaction.CommitAsync(ct);
        return current;
    }

    public async Task<SecurityAlertPage> SecurityAlerts(Guid organizationId, string? app, string? status, SecurityAlertCursor? cursor, CancellationToken ct)
    {
        await using var command = Command($"""
            SELECT {AlertFields} FROM {AlertSources}
            WHERE a.organization_id = $1 AND {AlertVisible}
                AND ($2::text IS NULL OR a.app_id = $2)
                AND ($3::text IS NULL OR (a.acknowledged_at IS NULL) = ($3 = 'open'))
                AND ($4::timestamptz IS NULL OR (a.triggered_at, a.id) < ($4, $5::uuid))
            ORDER BY a.triggered_at DESC, a.id DESC LIMIT $6
            """, organizationId, (object?)app ?? DBNull.Value, (object?)status ?? DBNull.Value,
            (object?)cursor?.TriggeredAt.UtcDateTime ?? DBNull.Value, (object?)cursor?.Id ?? DBNull.Value, AlertPageSize + 1);
        var entries = new List<SecurityAlert>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct)) entries.Add(ReadAlert(rows));
        if (entries.Count <= AlertPageSize) return new(entries, null);
        entries.RemoveAt(AlertPageSize);
        var oldest = entries[^1];
        return new(entries, new(oldest.TriggeredAt, oldest.Id));
    }

    public async Task<SecurityAlertDetails?> SecurityAlertDetail(Guid organizationId, Guid alertId, EventCursor? cursor, CancellationToken ct)
    {
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var snapshot = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        await using var summary = BrowserRead(snapshot, $"""
            SELECT {AlertFields} FROM {AlertSources}
            WHERE a.organization_id = $1 AND a.id = $2 AND {AlertVisible}
            """, organizationId, alertId);
        SecurityAlert alert;
        await using (var rows = await summary.ExecuteReaderAsync(ct))
        {
            if (!await rows.ReadAsync(ct)) return null;
            alert = ReadAlert(rows);
        }
        await using var evidence = BrowserRead(snapshot, $"""
            SELECT {EventFields}
            FROM {EventSources} LEFT {EventTriageJoin}
            JOIN security_alert_events m ON m.organization_id = e.organization_id
                AND m.installation_id = e.installation_id AND m.event_id = e.event_id
            WHERE m.organization_id = $1 AND m.alert_id = $2 AND {EventRetained}
                AND ($3::timestamptz IS NULL OR (e.received_at, e.event_id, e.installation_id) < ($3, $4::uuid, $5::uuid))
            ORDER BY e.received_at DESC, e.event_id DESC, e.installation_id DESC LIMIT $6
            """, organizationId, alertId, (object?)cursor?.ReceivedAt.UtcDateTime ?? DBNull.Value,
            (object?)cursor?.EventId ?? DBNull.Value, (object?)cursor?.InstallationId ?? DBNull.Value, AlertPageSize + 1);
        var entries = new List<StoredEvent>();
        await using (var rows = await evidence.ExecuteReaderAsync(ct))
            while (await rows.ReadAsync(ct)) entries.Add(ReadEvent(rows));
        await snapshot.CommitAsync(ct);
        if (entries.Count <= AlertPageSize) return new(alert, new(entries, null));
        entries.RemoveAt(AlertPageSize);
        var last = entries[^1];
        return new(alert, new(entries, new(last.ReceivedAt, last.EventId, last.InstallationId)));
    }

    public async Task<bool> AcknowledgeSecurityAlert(RequestIdentity identity, Guid alertId, CancellationToken ct)
    {
        await using var command = Command($"""
            WITH target AS (
                SELECT a.id, a.acknowledged_at FROM {AlertSources}
                WHERE a.organization_id = $1 AND a.id = $2 AND {AlertVisible} FOR UPDATE OF a
            ), acknowledged AS (
                UPDATE security_alert_windows a SET acknowledged_at = statement_timestamp()
                FROM target t WHERE a.organization_id = $1 AND a.id = t.id AND t.acknowledged_at IS NULL
                RETURNING a.organization_id, a.id
            ), audit AS (
                INSERT INTO control_audit (organization_id, action, security_alert_change, actor_access_id)
                SELECT organization_id, 'security_alert_acknowledged', jsonb_build_object('alertId', id), $3
                FROM acknowledged
            )
            SELECT EXISTS (SELECT 1 FROM target)
            """, identity.OrganizationId, alertId, (object?)identity.Access?.Id ?? DBNull.Value);
        return (bool)(await command.ExecuteScalarAsync(ct))!;
    }

    private static SecurityAlertSettings ReadAlertSettings(NpgsqlDataReader rows) => new(rows.GetBoolean(0), rows.GetInt32(1), rows.GetInt32(2));

    private static SecurityAlert ReadAlert(NpgsqlDataReader rows) => new(rows.GetGuid(0), rows.GetString(1),
        !rows.GetBoolean(2) ? new("unattributed") : rows.IsDBNull(3) ? new("baseline")
            : new("group", rows.GetGuid(3), rows.IsDBNull(4) ? null : rows.GetString(4)),
        rows.GetDateTime(5), rows.GetDateTime(6), rows.GetInt32(7), rows.GetInt64(8), rows.GetDateTime(9),
        rows.IsDBNull(10) ? null : rows.GetDateTime(10));
}
