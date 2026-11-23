using Npgsql;

namespace Control;

internal sealed partial class ControlStore
{
    public async Task<RetentionPolicy> GetRetention(Guid organizationId, CancellationToken ct)
    {
        await using var command = Command("""
            SELECT event_days, observation_days, audit_days FROM organization_retention WHERE organization_id = $1
            """, organizationId);
        await using var rows = await command.ExecuteReaderAsync(ct);
        return await rows.ReadAsync(ct)
            ? new(rows.IsDBNull(0) ? null : rows.GetInt32(0), rows.IsDBNull(1) ? null : rows.GetInt32(1),
                rows.IsDBNull(2) ? null : rows.GetInt32(2))
            : new(null, null, null);
    }

    public async Task SetRetention(RequestIdentity identity, RetentionPolicy policy, CancellationToken ct)
    {
        await using var command = Command("""
            WITH changed AS (
                INSERT INTO organization_retention (organization_id, event_days, observation_days, audit_days,
                    event_floor, observation_floor, audit_floor)
                SELECT $1, $2::integer, $3::integer, $4::integer,
                    now() - $2 * interval '24 hours', now() - $3 * interval '24 hours', now() - $4 * interval '24 hours'
                WHERE num_nonnulls($2::integer, $3::integer, $4::integer) > 0
                    OR EXISTS (SELECT 1 FROM organization_retention WHERE organization_id = $1)
                ON CONFLICT (organization_id) DO UPDATE SET
                    event_days = EXCLUDED.event_days, observation_days = EXCLUDED.observation_days, audit_days = EXCLUDED.audit_days,
                    event_floor = GREATEST(organization_retention.event_floor, EXCLUDED.event_floor,
                        now() - organization_retention.event_days * interval '24 hours'),
                    observation_floor = GREATEST(organization_retention.observation_floor, EXCLUDED.observation_floor,
                        now() - organization_retention.observation_days * interval '24 hours'),
                    audit_floor = GREATEST(organization_retention.audit_floor, EXCLUDED.audit_floor,
                        now() - organization_retention.audit_days * interval '24 hours')
                WHERE (organization_retention.event_days, organization_retention.observation_days, organization_retention.audit_days)
                    IS DISTINCT FROM (EXCLUDED.event_days, EXCLUDED.observation_days, EXCLUDED.audit_days)
                RETURNING organization_id, event_days, observation_days, audit_days
            )
            INSERT INTO control_audit (organization_id, action, retention, actor_access_id)
            SELECT organization_id, 'retention_changed', jsonb_build_object(
                'securityEventDays', event_days, 'aiObservationDays', observation_days, 'auditDays', audit_days), $5 FROM changed
            """, identity.OrganizationId, (object?)policy.SecurityEventDays ?? DBNull.Value,
            (object?)policy.AiObservationDays ?? DBNull.Value, (object?)policy.AuditDays ?? DBNull.Value,
            (object?)identity.Access?.Id ?? DBNull.Value);
        await command.ExecuteNonQueryAsync(ct);
    }

    public async Task<IReadOnlyList<Guid>> OrganizationsWithExpiredData(CancellationToken ct)
    {
        await using var command = Command($"""
            SELECT r.organization_id FROM retention_cutoffs r
            WHERE EXISTS (SELECT 1 FROM security_events e WHERE e.organization_id = r.organization_id
                        AND LEAST(e.occurred_at, e.received_at) < r.event_cutoff)
               OR EXISTS (SELECT 1 FROM ai_app_observations o WHERE o.organization_id = r.organization_id
                        AND o.observed_at < r.observation_cutoff)
               OR EXISTS (SELECT 1 FROM control_audit a WHERE a.organization_id = r.organization_id AND a.occurred_at < r.audit_cutoff)
               OR EXISTS (SELECT 1 FROM incident_cases c WHERE c.organization_id = r.organization_id
                        AND c.status = 'resolved' AND c.updated_at < r.audit_cutoff)
            UNION
            SELECT a.organization_id FROM security_alert_windows a
            LEFT JOIN retention_cutoffs r ON r.organization_id = a.organization_id
            WHERE {AlertExpired}
            ORDER BY organization_id
            """);
        var organizations = new List<Guid>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct)) organizations.Add(rows.GetGuid(0));
        return organizations;
    }

    public async Task<RetentionCleanup> CleanupRetention(Guid organizationId, bool scheduled, CancellationToken ct, Guid? actorId = null)
    {
        const int batchSize = 1000;
        var source = scheduled ? "scheduled" : "manual";
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        // Serialize cleanup with changes to the window and other cleanup runs for the same organization.
        await using var gate = new NpgsqlCommand("SELECT organization_id FROM organization_retention WHERE organization_id = $1 FOR UPDATE", connection, transaction);
        gate.Parameters.AddWithValue(organizationId);
        await gate.ExecuteScalarAsync(ct);

        await using var command = new NpgsqlCommand($$"""
            WITH cutoff AS (SELECT * FROM retention_cutoffs WHERE organization_id = $1),
            removed_events AS (
                DELETE FROM security_events WHERE (installation_id, event_id) IN (
                    SELECT e.installation_id, e.event_id FROM security_events e, cutoff c WHERE e.organization_id = $1
                    AND LEAST(e.occurred_at, e.received_at) < c.event_cutoff
                    ORDER BY LEAST(e.occurred_at, e.received_at) LIMIT $2 FOR UPDATE OF e SKIP LOCKED
                ) RETURNING 1
            ), removed_observations AS (
                DELETE FROM ai_app_observations WHERE (organization_id, app_id, installation_id) IN (
                    SELECT o.organization_id, o.app_id, o.installation_id FROM ai_app_observations o, cutoff c
                    WHERE o.organization_id = $1 AND o.observed_at < c.observation_cutoff
                    ORDER BY o.observed_at LIMIT $2 FOR UPDATE OF o SKIP LOCKED
                ) RETURNING 1
            ), removed_audit AS (
                DELETE FROM control_audit WHERE id IN (
                    SELECT a.id FROM control_audit a, cutoff c WHERE a.organization_id = $1 AND a.occurred_at < c.audit_cutoff
                    ORDER BY a.occurred_at LIMIT $2 FOR UPDATE OF a SKIP LOCKED
                ) RETURNING 1
            ), removed_cases AS (
                DELETE FROM incident_cases WHERE organization_id = $1 AND id IN (
                    SELECT c.id FROM incident_cases c, cutoff r WHERE c.organization_id = $1
                    AND c.status = 'resolved' AND c.updated_at < r.audit_cutoff
                    ORDER BY c.updated_at, c.id LIMIT $2 FOR UPDATE OF c SKIP LOCKED
                ) RETURNING 1
            ), removed_alerts AS (
                DELETE FROM security_alert_windows WHERE organization_id = $1 AND id IN (
                    SELECT a.id FROM security_alert_windows a LEFT JOIN cutoff r ON r.organization_id = a.organization_id
                    WHERE a.organization_id = $1 AND ({{AlertExpired}})
                    ORDER BY a.first_received_at, a.id LIMIT $2 FOR UPDATE OF a SKIP LOCKED
                ) RETURNING 1
            ), counts AS (
                SELECT (SELECT count(*) FROM removed_events)::integer AS events,
                    (SELECT count(*) FROM removed_observations)::integer AS observations,
                    (SELECT count(*) FROM removed_audit)::integer AS audit_entries,
                    (SELECT count(*) FROM removed_cases)::integer AS incidents,
                    (SELECT count(*) FROM removed_alerts)::integer AS alert_windows
            ), audit AS (
                INSERT INTO control_audit (organization_id, action, cleanup, actor_access_id)
                SELECT $1, 'retention_cleanup', jsonb_build_object('securityEvents', events,
                    'aiObservations', observations, 'auditEntries', audit_entries, 'source', $3::text)
                    || CASE WHEN incidents > 0 THEN jsonb_build_object('incidentCases', incidents) ELSE '{}'::jsonb END
                    || CASE WHEN alert_windows > 0 THEN jsonb_build_object('alertWindows', alert_windows) ELSE '{}'::jsonb END, $4
                FROM counts WHERE events + observations + audit_entries + incidents + alert_windows > 0
            )
            SELECT events, observations, audit_entries, incidents, alert_windows FROM counts
            """, connection, transaction);
        AddParameters(command, organizationId, batchSize, source, (object?)actorId ?? DBNull.Value);
        RetentionCleanup result;
        await using (var rows = await command.ExecuteReaderAsync(ct))
        {
            await rows.ReadAsync(ct);
            result = new(rows.GetInt32(0), rows.GetInt32(1), rows.GetInt32(2), source, rows.GetInt32(3), rows.GetInt32(4));
        }
        await transaction.CommitAsync(ct);
        return result;
    }
}
