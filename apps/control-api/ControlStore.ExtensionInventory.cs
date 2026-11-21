using System.Text.Json;

namespace Control;

internal sealed partial class ControlStore
{
    public async Task<bool> ReportInventory(Guid installationId, ReportExtensionInventory report, CancellationToken ct)
    {
        await using var command = Command("""
            WITH eligible AS (
                SELECT i.id, i.organization_id
                FROM installations i JOIN organizations o ON o.id = i.organization_id
                LEFT JOIN policy_groups g ON g.organization_id = i.organization_id AND g.id = i.policy_group_id
                JOIN policy_versions p ON p.organization_id = i.organization_id
                    AND p.version = COALESCE(g.policy_version, o.policy_version)
                WHERE i.id = $1 AND i.revoked_at IS NULL AND i.assignment_version = $3
                    AND p.version = $2 AND p.extension_inventory_enabled
                FOR SHARE OF i
            ), recorded AS (
                INSERT INTO extension_inventory_snapshots (installation_id, organization_id, policy_version,
                    assignment_version, captured_at, status, entries, omitted)
                SELECT id, organization_id, $2, $3, $4, $5, $6::jsonb, $7 FROM eligible
                ON CONFLICT (installation_id) DO UPDATE SET policy_version = EXCLUDED.policy_version,
                    assignment_version = EXCLUDED.assignment_version, captured_at = EXCLUDED.captured_at,
                    received_at = now(), status = EXCLUDED.status, entries = EXCLUDED.entries, omitted = EXCLUDED.omitted
                WHERE (extension_inventory_snapshots.assignment_version, extension_inventory_snapshots.policy_version,
                    extension_inventory_snapshots.captured_at) < (EXCLUDED.assignment_version, EXCLUDED.policy_version, EXCLUDED.captured_at)
            )
            SELECT EXISTS (SELECT 1 FROM eligible)
            """, installationId, report.PolicyVersion, report.AssignmentVersion, report.CapturedAt.UtcDateTime,
            report.Status, JsonSerializer.Serialize(report.Entries, JsonSerializerOptions.Web), report.Omitted);
        return (bool)(await command.ExecuteScalarAsync(ct))!;
    }

    public async Task<IReadOnlyList<InventoryInstallation>> ExtensionInventory(Guid organizationId, Guid? installationId, CancellationToken ct)
    {
        await using var command = Command("""
            SELECT i.id, g.name,
                CASE WHEN NOT p.extension_inventory_enabled THEN 'off' ELSE COALESCE(s.status, 'awaiting') END,
                s.received_at, COALESCE(jsonb_array_length(s.entries), 0), COALESCE(s.omitted, 0),
                CASE WHEN $2::uuid IS NOT NULL THEN s.entries END
            FROM installations i JOIN organizations o ON o.id = i.organization_id
            LEFT JOIN policy_groups g ON g.organization_id = i.organization_id AND g.id = i.policy_group_id
            JOIN policy_versions p ON p.organization_id = i.organization_id AND p.version = COALESCE(g.policy_version, o.policy_version)
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
                rows.IsDBNull(6) ? null : JsonSerializer.Deserialize<InventoryExtension[]>(rows.GetString(6), JsonSerializerOptions.Web)));
        return result;
    }

    public async Task ExpireExtensionInventory(CancellationToken ct)
    {
        await using var command = Command("""
            DELETE FROM extension_inventory_snapshots WHERE installation_id IN (
                SELECT s.installation_id
                FROM extension_inventory_snapshots s JOIN installations i ON s.installation_id = i.id
                JOIN organizations o ON o.id = i.organization_id
                LEFT JOIN policy_groups g ON g.organization_id = i.organization_id AND g.id = i.policy_group_id
                JOIN policy_versions p ON p.organization_id = i.organization_id AND p.version = COALESCE(g.policy_version, o.policy_version)
                WHERE s.received_at < now() - interval '30 days' OR i.revoked_at IS NOT NULL OR NOT p.extension_inventory_enabled
                ORDER BY s.installation_id LIMIT $1 FOR UPDATE OF s SKIP LOCKED
            )
            """, ExtensionInventoryCleanupBatchSize);
        while (await command.ExecuteNonQueryAsync(ct) == ExtensionInventoryCleanupBatchSize)
            ct.ThrowIfCancellationRequested();
    }

    private const int ExtensionInventoryCleanupBatchSize = 1000;
}
