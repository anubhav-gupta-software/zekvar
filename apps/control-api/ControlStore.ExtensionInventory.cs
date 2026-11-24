using System.Text.Json;

namespace Control;

internal sealed partial class ControlStore
{
    private const int InventoryHistoryLimit = 20;
    private const int ExtensionInventoryCleanupBatchSize = 1000;
    private const string InventoryScope = """
        FROM installations i JOIN organizations o ON o.id = i.organization_id
        LEFT JOIN policy_groups g ON g.organization_id = i.organization_id AND g.id = i.policy_group_id
        JOIN policy_versions p ON p.organization_id = i.organization_id AND p.version = COALESCE(g.policy_version, o.policy_version)
        """;

    // A group inherits baseline publications until its first independent policy.
    private const string InventoryGap = """
        SELECT COALESCE(max(stopped.version), 0)
        FROM policy_versions stopped
        WHERE stopped.organization_id = i.organization_id AND stopped.version < p.version AND NOT stopped.extension_inventory_enabled
            AND (stopped.policy_group_id = g.id OR stopped.policy_group_id IS NULL AND NOT EXISTS (
                SELECT 1 FROM policy_versions scoped
                WHERE scoped.organization_id = i.organization_id AND scoped.policy_group_id = g.id AND scoped.version < stopped.version
            ))
        """;
    private const string InventoryHistoryVisible = $"""
        b.assignment_version = i.assignment_version AND b.policy_version > ({InventoryGap})
        AND b.received_at >= now() - interval '30 days'
        """;

    public async Task<bool> ReportInventory(Guid installationId, ReportExtensionInventory report, CancellationToken ct)
    {
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        // Lock before reading the snapshot so concurrent reports compare with the last accepted state.
        await using var locked = BrowserRead(transaction, """
            SELECT organization_id FROM installations WHERE id = $1 AND revoked_at IS NULL FOR UPDATE
            """, installationId);
        if (await locked.ExecuteScalarAsync(ct) is not Guid organizationId) return false;

        var capturedAt = report.CapturedAt.UtcDateTime;
        // PostgreSQL timestamps have microsecond precision. Compare at the same precision used for storage.
        capturedAt = capturedAt.AddTicks(-(capturedAt.Ticks % TimeSpan.TicksPerMicrosecond));
        var changes = Array.Empty<InventoryExtensionChange>();
        await using (var previous = BrowserRead(transaction, $"""
            SELECT s.assignment_version, s.policy_version, s.captured_at,
                s.status = 'reported' AND s.assignment_version = i.assignment_version
                    AND s.received_at >= now() - interval '30 days' AND s.policy_version > ({InventoryGap}),
                s.entries, s.omitted
            {InventoryScope}
            LEFT JOIN extension_inventory_snapshots s ON s.installation_id = i.id
            WHERE i.id = $1 AND p.version = $2 AND i.assignment_version = $3 AND p.extension_inventory_enabled
            """, installationId, report.PolicyVersion, report.AssignmentVersion))
        await using (var row = await previous.ExecuteReaderAsync(ct))
        {
            if (!await row.ReadAsync(ct)) return false;
            if (!row.IsDBNull(0))
            {
                var prior = (row.GetInt32(0), row.GetInt32(1), row.GetDateTime(2));
                if (prior.CompareTo((report.AssignmentVersion, report.PolicyVersion, capturedAt)) >= 0) return true;
                if (report.Status == "reported" && row.GetBoolean(3))
                    changes = InventoryExtensionChange.Compare(
                        JsonSerializer.Deserialize<InventoryExtension[]>(row.GetString(4), JsonSerializerOptions.Web)!, report,
                        row.GetInt32(5) == 0 && report.Omitted == 0);
            }
        }

        await using var record = BrowserRead(transaction, """
            INSERT INTO extension_inventory_snapshots (installation_id, organization_id, policy_version,
                assignment_version, captured_at, status, entries, omitted)
            VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8)
            ON CONFLICT (installation_id) DO UPDATE SET policy_version = EXCLUDED.policy_version,
                assignment_version = EXCLUDED.assignment_version, captured_at = EXCLUDED.captured_at,
                received_at = now(), status = EXCLUDED.status, entries = EXCLUDED.entries, omitted = EXCLUDED.omitted
            """, installationId, organizationId, report.PolicyVersion, report.AssignmentVersion, capturedAt,
            report.Status, JsonSerializer.Serialize(report.Entries, JsonSerializerOptions.Web), report.Omitted);
        await record.ExecuteNonQueryAsync(ct);
        if (changes.Length > 0)
        {
            await using var history = BrowserRead(transaction, """
                WITH added AS (
                    INSERT INTO extension_inventory_change_batches (installation_id, organization_id, policy_version, assignment_version, changes, alert_id)
                    VALUES ($1, $2, $3, $4, $5::jsonb, CASE WHEN $7 AND EXISTS (
                        SELECT 1 FROM extension_access_alert_settings WHERE organization_id = $2 AND enabled
                    ) THEN gen_random_uuid() END)
                )
                DELETE FROM extension_inventory_change_batches WHERE id IN (
                    SELECT id FROM extension_inventory_change_batches WHERE installation_id = $1 ORDER BY id DESC OFFSET $6
                )
                """, installationId, organizationId, report.PolicyVersion, report.AssignmentVersion,
                JsonSerializer.Serialize(changes, JsonSerializerOptions.Web), InventoryHistoryLimit - 1,
                changes.Any(change => change.ReviewAccess));
            await history.ExecuteNonQueryAsync(ct);
        }
        await transaction.CommitAsync(ct);
        return true;
    }

    public async Task<IReadOnlyList<InventoryInstallation>> ExtensionInventory(Guid organizationId, Guid? installationId, CancellationToken ct)
    {
        await using var command = Command($"""
            SELECT i.id, g.name,
                CASE WHEN NOT p.extension_inventory_enabled THEN 'off' ELSE COALESCE(s.status, 'awaiting') END,
                s.received_at, COALESCE(jsonb_array_length(s.entries), 0), COALESCE(s.omitted, 0),
                CASE WHEN $2::uuid IS NOT NULL THEN s.entries END,
                CASE WHEN $2::uuid IS NOT NULL AND p.extension_inventory_enabled THEN (
                    SELECT COALESCE(jsonb_agg(jsonb_build_object('id', b.id::text, 'policyVersion', b.policy_version,
                        'reportedAt', b.received_at, 'changes', b.changes) ORDER BY b.id DESC), '[]'::jsonb)
                    FROM extension_inventory_change_batches b
                    WHERE b.organization_id = i.organization_id AND b.installation_id = i.id
                        AND {InventoryHistoryVisible}
                ) END
            {InventoryScope}
            LEFT JOIN extension_inventory_snapshots s ON p.extension_inventory_enabled AND s.installation_id = i.id
                AND s.policy_version = p.version AND s.assignment_version = i.assignment_version AND s.received_at >= now() - interval '30 days'
            WHERE i.organization_id = $1 AND i.revoked_at IS NULL AND ($2 IS NULL OR i.id = $2)
            ORDER BY i.enrolled_at DESC, i.id LIMIT 100
            """, organizationId, (object?)installationId ?? DBNull.Value);
        var result = new List<InventoryInstallation>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct))
            result.Add(new(rows.GetGuid(0), rows.IsDBNull(1) ? null : rows.GetString(1), rows.GetString(2),
                rows.IsDBNull(3) ? null : rows.GetDateTime(3), rows.GetInt32(4), rows.GetInt32(5),
                rows.IsDBNull(6) ? null : JsonSerializer.Deserialize<InventoryExtension[]>(rows.GetString(6), JsonSerializerOptions.Web),
                rows.IsDBNull(7) ? null : JsonSerializer.Deserialize<InventoryChangeBatch[]>(rows.GetString(7), JsonSerializerOptions.Web)));
        return result;
    }

    public async Task ExpireExtensionInventory(CancellationToken ct)
    {
        await using var command = Command($"""
            DELETE FROM extension_inventory_snapshots WHERE installation_id IN (
                SELECT s.installation_id
                {InventoryScope}
                JOIN extension_inventory_snapshots s ON s.installation_id = i.id
                WHERE s.received_at < now() - interval '30 days' OR i.revoked_at IS NOT NULL OR NOT p.extension_inventory_enabled
                ORDER BY s.installation_id LIMIT $1 FOR UPDATE OF s SKIP LOCKED
            )
            """, ExtensionInventoryCleanupBatchSize);
        while (await command.ExecuteNonQueryAsync(ct) == ExtensionInventoryCleanupBatchSize)
            ct.ThrowIfCancellationRequested();

        await using var changes = Command($"""
            DELETE FROM extension_inventory_change_batches WHERE id IN (
                SELECT b.id
                {InventoryScope}
                JOIN extension_inventory_change_batches b ON b.installation_id = i.id
                WHERE b.received_at < now() - interval '30 days' OR i.revoked_at IS NOT NULL
                    OR b.assignment_version <> i.assignment_version OR NOT p.extension_inventory_enabled
                ORDER BY b.received_at, b.id LIMIT $1 FOR UPDATE OF b SKIP LOCKED
            )
            """, ExtensionInventoryCleanupBatchSize);
        while (await changes.ExecuteNonQueryAsync(ct) == ExtensionInventoryCleanupBatchSize)
            ct.ThrowIfCancellationRequested();
    }
}
