using System.Text.Json;
using Npgsql;

namespace Control;

internal sealed partial class ControlStore
{
    private const string RiskyExtensionChanges = "jsonb_path_query_array(b.changes, '$[*] ? (@.reviewAccess == true)')";
    private const string ExtensionAlertFields = $"""
        b.alert_id, i.id, g.name, b.policy_version, jsonb_array_length({RiskyExtensionChanges}), b.received_at, b.alert_acknowledged_at
        """;
    private const string ExtensionAlertSources = $"""
        {InventoryScope}
        JOIN extension_inventory_change_batches b ON b.organization_id = i.organization_id AND b.installation_id = i.id
        """;
    private const string ExtensionAlertVisible = $"""
        b.alert_id IS NOT NULL AND i.revoked_at IS NULL AND p.extension_inventory_enabled AND {InventoryHistoryVisible}
        """;

    public async Task<ExtensionAccessSettings> GetExtensionAccessSettings(Guid organizationId, CancellationToken ct)
    {
        await using var command = Command("""
            SELECT enabled, revision FROM extension_access_alert_settings WHERE organization_id = $1
            """, organizationId);
        await using var rows = await command.ExecuteReaderAsync(ct);
        return await rows.ReadAsync(ct) ? new(rows.GetBoolean(0), rows.GetInt32(1)) : new(false, 0);
    }

    public async Task<ExtensionAccessSettings?> UpdateExtensionAccessSettings(RequestIdentity identity, SetExtensionAccessSettings request,
        CancellationToken ct)
    {
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using var ensure = BrowserRead(transaction, """
            INSERT INTO extension_access_alert_settings (organization_id) VALUES ($1) ON CONFLICT DO NOTHING
            """, identity.OrganizationId);
        await ensure.ExecuteNonQueryAsync(ct);

        await using var read = BrowserRead(transaction, """
            SELECT enabled, revision FROM extension_access_alert_settings WHERE organization_id = $1 FOR UPDATE
            """, identity.OrganizationId);
        ExtensionAccessSettings previous;
        await using (var rows = await read.ExecuteReaderAsync(ct))
        {
            await rows.ReadAsync(ct);
            previous = new(rows.GetBoolean(0), rows.GetInt32(1));
        }
        var enabled = request.Enabled!.Value;
        if (enabled == previous.Enabled && (request.ExpectedRevision == previous.Revision || request.ExpectedRevision == previous.Revision - 1))
            return previous;
        if (request.ExpectedRevision != previous.Revision) return null;
        var settings = new ExtensionAccessSettings(enabled, previous.Revision + 1);
        var change = new SecurityAlertChange(ExtensionAccess: true, ExtensionBefore: previous, ExtensionAfter: settings);
        await using var write = BrowserRead(transaction, """
            WITH saved AS (
                UPDATE extension_access_alert_settings SET enabled = $2, revision = $3
                WHERE organization_id = $1 RETURNING organization_id
            )
            INSERT INTO control_audit (organization_id, action, security_alert_change, actor_access_id)
            SELECT organization_id, 'security_alert_settings_changed', $4::jsonb, $5 FROM saved
            """, identity.OrganizationId, settings.Enabled, settings.Revision,
            JsonSerializer.Serialize(change, JsonSerializerOptions.Web), (object?)identity.Access?.Id ?? DBNull.Value);
        await write.ExecuteNonQueryAsync(ct);
        await transaction.CommitAsync(ct);
        return settings;
    }

    public async Task<ExtensionAccessAlertPage> ExtensionAccessAlerts(Guid organizationId, string? status,
        SecurityAlertCursor? cursor, CancellationToken ct)
    {
        await using var command = Command($"""
            SELECT {ExtensionAlertFields}
            {ExtensionAlertSources}
            WHERE b.organization_id = $1 AND {ExtensionAlertVisible}
                AND ($2::text IS NULL OR (b.alert_acknowledged_at IS NULL) = ($2 = 'open'))
                AND ($3::timestamptz IS NULL OR (b.received_at, b.alert_id) < ($3, $4::uuid))
            ORDER BY b.received_at DESC, b.alert_id DESC LIMIT $5
            """, organizationId, (object?)status ?? DBNull.Value,
            (object?)cursor?.TriggeredAt.UtcDateTime ?? DBNull.Value, (object?)cursor?.Id ?? DBNull.Value, AlertPageSize + 1);
        var alerts = new List<ExtensionAccessAlert>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct)) alerts.Add(ReadExtensionAccessAlert(rows));
        if (alerts.Count <= AlertPageSize) return new(alerts, null);
        alerts.RemoveAt(AlertPageSize);
        var oldest = alerts[^1];
        return new(alerts, new(oldest.TriggeredAt, oldest.Id));
    }

    public async Task<ExtensionAccessAlertDetail?> ExtensionAccessAlertDetails(Guid organizationId, Guid id, CancellationToken ct)
    {
        await using var command = Command($"""
            SELECT {ExtensionAlertFields}, {RiskyExtensionChanges}
            {ExtensionAlertSources}
            WHERE b.organization_id = $1 AND b.alert_id = $2 AND {ExtensionAlertVisible}
            """, organizationId, id);
        await using var rows = await command.ExecuteReaderAsync(ct);
        return await rows.ReadAsync(ct) ? new(ReadExtensionAccessAlert(rows),
            JsonSerializer.Deserialize<InventoryExtensionChange[]>(rows.GetString(7), JsonSerializerOptions.Web)!) : null;
    }

    public async Task<bool> AcknowledgeExtensionAccessAlert(RequestIdentity identity, Guid id, CancellationToken ct)
    {
        await using var command = Command($"""
            WITH target AS (
                SELECT b.id
                {ExtensionAlertSources}
                WHERE b.organization_id = $1 AND b.alert_id = $2 AND {ExtensionAlertVisible} FOR UPDATE OF b
            ), acknowledged AS (
                UPDATE extension_inventory_change_batches b SET alert_acknowledged_at = statement_timestamp()
                FROM target WHERE b.id = target.id AND b.alert_acknowledged_at IS NULL RETURNING b.organization_id, b.alert_id
            ), audit AS (
                INSERT INTO control_audit (organization_id, action, security_alert_change, actor_access_id)
                SELECT organization_id, 'security_alert_acknowledged', jsonb_build_object('alertId', alert_id, 'extensionAccess', true), $3
                FROM acknowledged
            )
            SELECT EXISTS (SELECT 1 FROM target)
            """, identity.OrganizationId, id, (object?)identity.Access?.Id ?? DBNull.Value);
        return (bool)(await command.ExecuteScalarAsync(ct))!;
    }

    private static ExtensionAccessAlert ReadExtensionAccessAlert(NpgsqlDataReader rows) =>
        new(rows.GetGuid(0), rows.GetGuid(1), rows.IsDBNull(2) ? null : rows.GetString(2), rows.GetInt32(3), rows.GetInt32(4),
            rows.GetDateTime(5), rows.IsDBNull(6) ? null : rows.GetDateTime(6));
}
