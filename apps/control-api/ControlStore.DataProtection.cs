using Npgsql;

namespace Control;

internal sealed record DataProtectionStatus(bool Enabled, string? ActiveKeyId, long SealedValues, long ActiveKeyValues, long PlaintextValues);

internal sealed partial class ControlStore
{
    private const string ClassificationField = "policy_versions.classification_protection.terms";
    private const string IdentifierField = "policy_versions.identifier_protection.formats";
    private const string HealthField = "policy_versions.health_protection.recordFormats";
    private const string ReviewSnapshotField = "policy_reviews.snapshots";

    private const string SealedCounts = """
        WITH fields AS (
            SELECT organization_id, classification_protection->>'sealed' AS sealed,
                jsonb_array_length(classification_protection->'terms') > 0 AS plaintext FROM policy_versions
            UNION ALL SELECT organization_id, identifier_protection->>'sealed',
                jsonb_array_length(identifier_protection->'formats') > 0 FROM policy_versions
            UNION ALL SELECT organization_id, health_protection->>'sealed',
                jsonb_array_length(health_protection->'recordFormats') > 0 FROM policy_versions
            UNION ALL SELECT organization_id, snapshots->>'sealed', NOT (snapshots ? 'sealed') FROM policy_reviews
        )
        SELECT count(*) FILTER (WHERE sealed IS NOT NULL), count(*) FILTER (WHERE sealed LIKE $2),
            count(*) FILTER (WHERE sealed IS NULL AND plaintext)
        FROM fields WHERE $1::uuid IS NULL OR organization_id = $1
        """;

    public async Task<DataProtectionStatus> DataProtectionStatus(Guid? organizationId, CancellationToken ct)
    {
        await using var command = Command(SealedCounts, (object?)organizationId ?? DBNull.Value,
            protection.ActiveKeyId is { } id ? $"zk1:{id}:%" : "zk1::%");
        await using var rows = await command.ExecuteReaderAsync(ct);
        await rows.ReadAsync(ct);
        return new(protection.Enabled, protection.ActiveKeyId, rows.GetInt64(0), rows.GetInt64(1), rows.GetInt64(2));
    }

    // Seals plaintext rows and re-seals rows under retired keys in place. Runs at startup under the migration lock.
    private static async Task<int> SealStoredValues(NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken ct)
    {
        await using (var check = new NpgsqlCommand("""
            SELECT DISTINCT split_part(value, ':', 2) FROM (
                SELECT classification_protection->>'sealed' AS value FROM policy_versions
                UNION SELECT identifier_protection->>'sealed' FROM policy_versions
                UNION SELECT health_protection->>'sealed' FROM policy_versions
                UNION SELECT snapshots->>'sealed' FROM policy_reviews) sealed WHERE value IS NOT NULL
            """, connection, transaction))
        await using (var keys = await check.ExecuteReaderAsync(ct))
        {
            while (await keys.ReadAsync(ct))
                if (!protection.KeyIds.Contains(keys.GetString(0)))
                    throw new InvalidOperationException(protection.Enabled
                        ? "Stored Control values are sealed with a data key missing from Control__DataKeys. Add the retired key until re-sealing completes."
                        : "Stored Control values are sealed. Configure Control__DataKeys with the keys that sealed them.");
        }
        if (!protection.Enabled) return 0;

        var active = $"zk1:{protection.ActiveKeyId}:%";
        var changed = 0;
        var policies = new List<(Guid Org, int Version, string Classification, string Identifier, string Health)>();
        await using (var select = new NpgsqlCommand("""
            SELECT organization_id, version, classification_protection::text, identifier_protection::text, health_protection::text FROM policy_versions
            WHERE (classification_protection ? 'sealed' AND classification_protection->>'sealed' NOT LIKE $1)
                OR (NOT classification_protection ? 'sealed' AND jsonb_array_length(classification_protection->'terms') > 0)
                OR (identifier_protection ? 'sealed' AND identifier_protection->>'sealed' NOT LIKE $1)
                OR (NOT identifier_protection ? 'sealed' AND jsonb_array_length(identifier_protection->'formats') > 0)
                OR (health_protection ? 'sealed' AND health_protection->>'sealed' NOT LIKE $1)
                OR (NOT health_protection ? 'sealed' AND jsonb_array_length(health_protection->'recordFormats') > 0)
            FOR UPDATE
            """, connection, transaction))
        {
            select.Parameters.AddWithValue(active);
            await using var rows = await select.ExecuteReaderAsync(ct);
            while (await rows.ReadAsync(ct)) policies.Add((rows.GetGuid(0), rows.GetInt32(1), rows.GetString(2), rows.GetString(3), rows.GetString(4)));
        }
        foreach (var (org, version, classification, identifier, health) in policies)
        {
            await using var update = new NpgsqlCommand("""
                UPDATE policy_versions SET classification_protection = $3::jsonb, identifier_protection = $4::jsonb, health_protection = $5::jsonb
                WHERE organization_id = $1 AND version = $2
                """, connection, transaction);
            AddParameters(update, org, version,
                protection.SealMember(protection.OpenMember(classification, "terms", org, ClassificationField), "terms", org, ClassificationField),
                protection.SealMember(protection.OpenMember(identifier, "formats", org, IdentifierField), "formats", org, IdentifierField),
                protection.SealMember(protection.OpenMember(health, "recordFormats", org, HealthField), "recordFormats", org, HealthField));
            changed += await update.ExecuteNonQueryAsync(ct);
        }

        var reviews = new List<(Guid Org, Guid Id, string Snapshots)>();
        await using (var select = new NpgsqlCommand("""
            SELECT organization_id, id, snapshots::text FROM policy_reviews
            WHERE NOT snapshots ? 'sealed' OR snapshots->>'sealed' NOT LIKE $1 FOR UPDATE
            """, connection, transaction))
        {
            select.Parameters.AddWithValue(active);
            await using var rows = await select.ExecuteReaderAsync(ct);
            while (await rows.ReadAsync(ct)) reviews.Add((rows.GetGuid(0), rows.GetGuid(1), rows.GetString(2)));
        }
        foreach (var (org, id, snapshots) in reviews)
        {
            await using var update = new NpgsqlCommand(
                "UPDATE policy_reviews SET snapshots = $3::jsonb WHERE organization_id = $1 AND id = $2", connection, transaction);
            AddParameters(update, org, id,
                protection.SealObject(protection.OpenObject(snapshots, org, ReviewSnapshotField), org, ReviewSnapshotField, "template"));
            changed += await update.ExecuteNonQueryAsync(ct);
        }
        return changed;
    }
}
