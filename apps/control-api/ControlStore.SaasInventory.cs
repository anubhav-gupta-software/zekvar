namespace Control;

internal sealed partial class ControlStore
{
    public const int SaasInventoryWindowDays = 30;

    // Accepts one catalog app and UTC day for a browser whose delivered policy enabled SaaS inventory.
    // The upsert keeps one row per browser and app, so retries and repeated visits never add rows.
    public async Task<bool> ObserveSaasApp(Guid installationId, SaasObservation observation, CancellationToken ct)
    {
        await using var command = Command("""
            WITH active AS (
                SELECT organization_id, enrolled_at, policy_group_id FROM installations
                WHERE id = $1 AND revoked_at IS NULL AND assignment_version = $5 FOR SHARE
            ), eligible AS (
                SELECT p.organization_id FROM active
                JOIN policy_versions p ON p.organization_id = active.organization_id AND p.version = $4
                LEFT JOIN retention_cutoffs r ON r.organization_id = active.organization_id
                WHERE p.saas_discovery_enabled
                  AND $3::date BETWEEN GREATEST((active.enrolled_at AT TIME ZONE 'UTC')::date - 1,
                        (now() AT TIME ZONE 'UTC')::date - $6::integer)
                    AND (now() AT TIME ZONE 'UTC')::date + 1
                  AND (r.observation_cutoff IS NULL OR $3::date >= (r.observation_cutoff AT TIME ZONE 'UTC')::date)
                  AND EXISTS (SELECT 1 FROM policy_deliveries d
                    WHERE d.installation_id = $1 AND d.assignment_version = $5 AND d.policy_version = $4 AND d.saas_discovery)
                  AND NOT EXISTS (SELECT 1 FROM policy_versions later
                    WHERE later.organization_id = p.organization_id AND later.version > p.version AND NOT later.saas_discovery_enabled
                      AND (later.policy_group_id = active.policy_group_id OR (later.policy_group_id IS NULL AND p.policy_group_id IS NULL
                        AND NOT EXISTS (SELECT 1 FROM policy_versions first_group
                          WHERE first_group.organization_id = p.organization_id AND first_group.policy_group_id = active.policy_group_id
                            AND first_group.version <= later.version))))
            ), recorded AS (
                INSERT INTO saas_app_observations (organization_id, installation_id, app_id, first_seen_day, last_seen_day)
                SELECT organization_id, $1, $2, $3, $3 FROM eligible
                ON CONFLICT (organization_id, app_id, installation_id) DO UPDATE SET
                    first_seen_day = LEAST(saas_app_observations.first_seen_day, EXCLUDED.first_seen_day),
                    last_seen_day = GREATEST(saas_app_observations.last_seen_day, EXCLUDED.last_seen_day)
                WHERE EXCLUDED.last_seen_day > saas_app_observations.last_seen_day
                    OR EXCLUDED.first_seen_day < saas_app_observations.first_seen_day
            )
            SELECT EXISTS (SELECT 1 FROM eligible)
            """, installationId, observation.AppId!, observation.ReportedDay!.Value, observation.PolicyVersion, observation.AssignmentVersion,
            SaasInventoryWindowDays);
        return (bool)(await command.ExecuteScalarAsync(ct))!;
    }

    public async Task<SaasInventory> SaasInventory(Guid organizationId, CancellationToken ct)
    {
        await using var command = Command("""
            WITH bounds AS (
                SELECT GREATEST((now() AT TIME ZONE 'UTC')::date - $3::integer, (r.observation_cutoff AT TIME ZONE 'UTC')::date) AS since
                FROM (SELECT 1) AS one LEFT JOIN retention_cutoffs r ON r.organization_id = $1
            )
            SELECT catalog.app_id, COALESCE(c.status, 'unclassified'), count(o.installation_id),
                min(CASE WHEN o.first_seen_day IS NOT NULL THEN GREATEST(o.first_seen_day, b.since) END), max(o.last_seen_day),
                EXISTS (SELECT 1 FROM policy_versions p WHERE p.organization_id = $1 AND p.saas_discovery_enabled AND p.version IN (
                    SELECT policy_version FROM organizations WHERE id = $1
                    UNION SELECT policy_version FROM policy_groups WHERE organization_id = $1 AND policy_version IS NOT NULL))
            FROM unnest($2::text[]) WITH ORDINALITY AS catalog(app_id, position) CROSS JOIN bounds b
            LEFT JOIN saas_app_classifications c ON c.organization_id = $1 AND c.app_id = catalog.app_id
            LEFT JOIN saas_app_observations o ON o.organization_id = $1 AND o.app_id = catalog.app_id AND o.last_seen_day >= b.since
            GROUP BY catalog.app_id, catalog.position, c.status
            ORDER BY catalog.position
            """, organizationId, SaasCatalog.AppIds, SaasInventoryWindowDays);
        var apps = new List<SaasInventoryApp>();
        var enabled = false;
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct))
        {
            enabled = rows.GetBoolean(5);
            apps.Add(new(rows.GetString(0), rows.GetString(1), rows.GetInt64(2),
                rows.IsDBNull(3) ? null : rows.GetFieldValue<DateOnly>(3), rows.IsDBNull(4) ? null : rows.GetFieldValue<DateOnly>(4)));
        }
        return new(SaasCatalog.Version, enabled, SaasInventoryWindowDays, apps);
    }

    // Returns false when the status already matches, so an unchanged save writes no audit entry.
    public async Task<bool> ClassifySaasApp(RequestIdentity identity, string appId, string status, CancellationToken ct)
    {
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        // Serialize classification changes per organization so each change is audited exactly once.
        await using (var gate = new Npgsql.NpgsqlCommand("SELECT pg_advisory_xact_lock(hashtextextended('saas-classification:' || $1::text, 0))",
            connection, transaction))
        {
            AddParameters(gate, identity.OrganizationId);
            await gate.ExecuteScalarAsync(ct);
        }
        await using var command = new Npgsql.NpgsqlCommand("""
            WITH previous AS (
                SELECT COALESCE((SELECT status FROM saas_app_classifications WHERE organization_id = $1 AND app_id = $2), 'unclassified') AS status
            ), changed AS (
                INSERT INTO saas_app_classifications (organization_id, app_id, status)
                SELECT $1, $2, $3 FROM previous WHERE previous.status <> $3
                ON CONFLICT (organization_id, app_id) DO UPDATE SET status = EXCLUDED.status
                RETURNING app_id, status
            ), audit AS (
                INSERT INTO control_audit (organization_id, action, saas_classification, actor_access_id)
                SELECT $1, 'saas_app_classified',
                    jsonb_build_object('appId', changed.app_id, 'status', changed.status, 'previous', previous.status), $4
                FROM changed CROSS JOIN previous
            )
            SELECT EXISTS (SELECT 1 FROM changed)
            """, connection, transaction);
        AddParameters(command, identity.OrganizationId, appId, status, (object?)identity.Access?.Id ?? DBNull.Value);
        var changed = (bool)(await command.ExecuteScalarAsync(ct))!;
        await transaction.CommitAsync(ct);
        return changed;
    }
}
