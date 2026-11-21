using System.Runtime.CompilerServices;
using System.Text.Json;
using Npgsql;

namespace Control;

internal sealed partial class ControlStore
{
    private readonly NpgsqlDataSource dataSource;

    public ControlStore(NpgsqlDataSource dataSource) => this.dataSource = dataSource;

    public async Task Initialize(DemoOrganization[] organizations, CancellationToken ct)
    {
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using var setup = connection.CreateCommand();
        setup.CommandText = """
            SELECT pg_advisory_xact_lock(52824960);
            CREATE TABLE IF NOT EXISTS schema_migrations (version integer PRIMARY KEY);
            """;
        await setup.ExecuteNonQueryAsync(ct);

        await ApplyMigration(connection, 1, "001_initial.sql", ct);
        await ApplyMigration(connection, 2, "002_chatgpt_coverage.sql", ct);
        await ApplyMigration(connection, 3, "003_github_pat.sql", ct);
        await ApplyMigration(connection, 4, "004_ai_discovery.sql", ct);
        await ApplyMigration(connection, 5, "005_domain_rules.sql", ct);
        await ApplyMigration(connection, 6, "006_control_audit.sql", ct);
        await ApplyMigration(connection, 7, "007_retention.sql", ct);
        await ApplyMigration(connection, 8, "008_policy_groups.sql", ct);
        await ApplyMigration(connection, 9, "009_event_history.sql", ct);
        await ApplyMigration(connection, 10, "010_gemini_prompt_protection.sql", ct);
        await ApplyMigration(connection, 11, "011_payment_card_detection.sql", ct);
        await ApplyMigration(connection, 12, "012_upload_controls.sql", ct);
        await ApplyMigration(connection, 13, "013_path_rules.sql", ct);
        await ApplyMigration(connection, 14, "014_named_control_access.sql", ct);
        await ApplyMigration(connection, 15, "015_policy_reviews.sql", ct);
        await ApplyMigration(connection, 16, "016_extension_inventory.sql", ct);

        foreach (var organization in organizations)
        {
            await using var seed = connection.CreateCommand();
            seed.CommandText = """
                WITH org AS (
                    INSERT INTO organizations (id, slug) VALUES ($1, $2)
                    ON CONFLICT (slug) DO UPDATE SET slug = EXCLUDED.slug RETURNING id
                ), initial_policy AS (
                    INSERT INTO policy_versions (organization_id, version, mode)
                    SELECT id, 1, 'monitor' FROM org ON CONFLICT DO NOTHING
                )
                INSERT INTO admin_memberships (organization_id, token_hash)
                SELECT id, $3 FROM org
                ON CONFLICT (organization_id) DO UPDATE SET token_hash = EXCLUDED.token_hash
                """;
            seed.Parameters.AddWithValue(Guid.NewGuid());
            seed.Parameters.AddWithValue(organization.Slug);
            seed.Parameters.AddWithValue(Tokens.Hash(organization.AdminToken));
            await seed.ExecuteNonQueryAsync(ct);
        }
        await transaction.CommitAsync(ct);
    }

    private static async Task ApplyMigration(NpgsqlConnection connection, int version, string resourceName, CancellationToken ct)
    {
        await using var check = connection.CreateCommand();
        check.CommandText = "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)";
        check.Parameters.AddWithValue(version);
        if ((bool)(await check.ExecuteScalarAsync(ct))!) return;

        using var stream = typeof(ControlStore).Assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException($"Schema migration {version} is missing.");
        using var reader = new StreamReader(stream);
        await using var migration = connection.CreateCommand();
        migration.CommandText = await reader.ReadToEndAsync(ct);
        await migration.ExecuteNonQueryAsync(ct);
        migration.CommandText = "INSERT INTO schema_migrations (version) VALUES ($1)";
        migration.Parameters.AddWithValue(version);
        await migration.ExecuteNonQueryAsync(ct);
    }

    public async Task<EnrollmentGrant> CreateGrant(RequestIdentity identity, CancellationToken ct)
    {
        var grant = Tokens.Generate();
        await using var command = Command("""
            WITH issued AS (
                INSERT INTO enrollment_grants (token_hash, organization_id, expires_at)
                VALUES ($1, $2, now() + interval '10 minutes') RETURNING organization_id, expires_at
            ), audit AS (
                INSERT INTO control_audit (organization_id, action, actor_access_id)
                SELECT organization_id, 'grant_issued', $3 FROM issued
            )
            SELECT expires_at FROM issued
            """, Tokens.Hash(grant), identity.OrganizationId, (object?)identity.Access?.Id ?? DBNull.Value);
        return new(grant, (DateTime)(await command.ExecuteScalarAsync(ct))!);
    }

    public async Task<Enrollment?> Enroll(string grant, CancellationToken ct)
    {
        var installationId = Guid.NewGuid();
        var token = Tokens.Generate();
        await using var command = Command("""
            WITH redeemed AS (
                UPDATE enrollment_grants SET redeemed_at = now()
                WHERE token_hash = $1 AND redeemed_at IS NULL AND expires_at > now()
                RETURNING organization_id
            ), enrolled AS (
                INSERT INTO installations (id, organization_id, token_hash)
                SELECT $2, organization_id, $3 FROM redeemed RETURNING organization_id, id, enrolled_at
            )
            INSERT INTO control_audit (organization_id, occurred_at, action, installation_id)
            SELECT organization_id, enrolled_at, 'browser_enrolled', id FROM enrolled
            """, Tokens.Hash(grant), installationId, Tokens.Hash(token));
        return await command.ExecuteNonQueryAsync(ct) == 1 ? new(installationId, token) : null;
    }

    public async Task<IReadOnlyList<Policy>> PolicyHistory(Guid organizationId, CancellationToken ct, Guid? groupId = null)
    {
        await using var command = Command("""
            SELECT p.version, p.mode, p.published_at, a.restored_from, p.github_pat_mode, p.discovery_enabled,
                p.allowed_domains, p.blocked_domains, p.payment_card_mode, p.chatgpt_upload_mode, p.gemini_upload_mode,
                p.allowed_paths, p.blocked_paths, p.extension_inventory_enabled
            FROM policy_versions p LEFT JOIN policy_audit a USING (organization_id, version)
            WHERE p.organization_id = $1 AND p.policy_group_id IS NOT DISTINCT FROM $2::uuid ORDER BY p.version DESC LIMIT 100
            """, organizationId, (object?)groupId ?? DBNull.Value);
        var policies = new List<Policy>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct)) policies.Add(ReadPolicy(rows));
        return policies;
    }

    public async Task<Policy?> CurrentPolicy(Guid installationId, bool assignmentAware, CancellationToken ct)
    {
        await using var command = Command("""
            WITH active AS (
                UPDATE installations SET last_seen_at = GREATEST(last_seen_at, now()), assignment_aware = $2
                WHERE id = $1 AND revoked_at IS NULL AND (assignment_version = 0 OR $2)
                RETURNING organization_id, id, policy_group_id, assignment_version
            ), effective AS (
                SELECT i.organization_id, i.id, i.assignment_version, COALESCE(g.policy_version, o.policy_version) AS version
                FROM active i JOIN organizations o ON o.id = i.organization_id
                LEFT JOIN policy_groups g ON g.organization_id = o.id AND g.id = i.policy_group_id
            ), delivery AS (
                INSERT INTO policy_deliveries (organization_id, installation_id, assignment_version, policy_version)
                SELECT organization_id, id, assignment_version, version FROM effective WHERE assignment_version > 0
                ON CONFLICT DO NOTHING
            )
            SELECT p.version, p.mode, p.published_at, a.restored_from, p.github_pat_mode, p.discovery_enabled,
                p.allowed_domains, p.blocked_domains, p.payment_card_mode, p.chatgpt_upload_mode, p.gemini_upload_mode,
                p.allowed_paths, p.blocked_paths, p.extension_inventory_enabled, e.assignment_version
            FROM effective e JOIN policy_versions p ON p.organization_id = e.organization_id AND p.version = e.version
            LEFT JOIN policy_audit a ON a.organization_id = p.organization_id AND a.version = p.version
            """, installationId, assignmentAware);
        await using var rows = await command.ExecuteReaderAsync(ct);
        return await rows.ReadAsync(ct) ? ReadPolicy(rows) with { AssignmentVersion = rows.GetInt32(14) } : null;
    }

    public async Task<bool> RecordHeartbeat(Guid installationId, Heartbeat request, CancellationToken ct)
    {
        await using var command = Command("""
            UPDATE installations i SET last_seen_at = GREATEST(i.last_seen_at, now()),
                applied_policy_version = CASE WHEN (p.payment_card_mode = 'off' OR $7)
                    AND (p.chatgpt_upload_mode = 'off' AND p.gemini_upload_mode = 'off' OR $8)
                    AND (cardinality(p.allowed_paths) + cardinality(p.blocked_paths) = 0 OR $9)
                    THEN GREATEST(i.applied_policy_version, $2)
                    WHEN i.applied_policy_version = $2 THEN NULL ELSE i.applied_policy_version END,
                chatgpt_coverage = COALESCE($3::text, i.chatgpt_coverage),
                chatgpt_checked_at = CASE WHEN $3::text IS NULL THEN i.chatgpt_checked_at ELSE now() END,
                gemini_coverage = COALESCE($6::text, i.gemini_coverage),
                gemini_checked_at = CASE WHEN $6::text IS NULL THEN i.gemini_checked_at ELSE now() END
            FROM policy_versions p
            WHERE i.id = $1 AND i.revoked_at IS NULL AND i.assignment_version = $5
                AND p.organization_id = i.organization_id AND p.version = $2
                AND ($4 OR cardinality(p.allowed_domains) + cardinality(p.blocked_domains) = 0)
                AND (($5 = 0 AND p.policy_group_id IS NULL) OR EXISTS (SELECT 1 FROM policy_deliveries d
                    WHERE d.installation_id = i.id AND d.assignment_version = $5 AND d.policy_version = $2))
            """, installationId, request.PolicyVersion, (object?)request.ChatGptCoverage ?? DBNull.Value,
            request.DomainRulesApplied, request.AssignmentVersion, (object?)request.GeminiCoverage ?? DBNull.Value,
            request.PaymentCardModeApplied, request.UploadControlsApplied, request.PathRulesApplied);
        return await command.ExecuteNonQueryAsync(ct) == 1;
    }

    public async Task<IReadOnlyList<Installation>> Installations(Guid organizationId, CancellationToken ct)
    {
        await using var command = Command("""
            SELECT i.id, i.enrolled_at, i.last_seen_at, i.applied_policy_version, i.revoked_at, i.chatgpt_coverage, i.chatgpt_checked_at,
                i.policy_group_id, g.name, COALESCE(g.policy_version, o.policy_version), i.assignment_aware,
                i.gemini_coverage, i.gemini_checked_at
            FROM installations i JOIN organizations o ON o.id = i.organization_id
            LEFT JOIN policy_groups g ON g.organization_id = o.id AND g.id = i.policy_group_id
            WHERE i.organization_id = $1 ORDER BY i.enrolled_at DESC, i.id LIMIT 100
            """, organizationId);
        var installations = new List<Installation>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct))
            installations.Add(new(rows.GetGuid(0), rows.GetDateTime(1), rows.GetDateTime(2),
                rows.IsDBNull(3) ? null : rows.GetInt32(3), rows.IsDBNull(4) ? null : rows.GetDateTime(4),
                rows.IsDBNull(5) ? null : rows.GetString(5), rows.IsDBNull(6) ? null : rows.GetDateTime(6),
                rows.IsDBNull(7) ? null : rows.GetGuid(7), rows.IsDBNull(8) ? null : rows.GetString(8), rows.GetInt32(9), rows.GetBoolean(10),
                rows.IsDBNull(11) ? null : rows.GetString(11), rows.IsDBNull(12) ? null : rows.GetDateTime(12)));
        return installations;
    }

    public async Task<bool> Revoke(RequestIdentity identity, Guid installationId, CancellationToken ct)
    {
        await using var command = Command("""
            WITH revoked AS (
                UPDATE installations SET revoked_at = now() WHERE organization_id = $1 AND id = $2 AND revoked_at IS NULL
                RETURNING organization_id, id, revoked_at
            ), cleared AS (
                DELETE FROM extension_inventory_snapshots s USING revoked r WHERE s.installation_id = r.id
            ), audit AS (
                INSERT INTO control_audit (organization_id, occurred_at, action, installation_id, actor_access_id)
                SELECT organization_id, revoked_at, 'browser_revoked', id, $3 FROM revoked
            )
            SELECT EXISTS (SELECT 1 FROM installations WHERE organization_id = $1 AND id = $2)
            """, identity.OrganizationId, installationId, (object?)identity.Access?.Id ?? DBNull.Value);
        return (bool)(await command.ExecuteScalarAsync(ct))!;
    }

    public async Task<bool> Ingest(Guid installationId, PolicyEvent request, CancellationToken ct)
    {
        await using var command = Command("""
            WITH active AS (
                SELECT organization_id FROM installations WHERE id = $1 AND revoked_at IS NULL FOR SHARE
            ), eligible AS (
                SELECT p.organization_id FROM active
                JOIN policy_versions p ON p.organization_id = active.organization_id AND p.version = $4
                LEFT JOIN retention_cutoffs r ON r.organization_id = active.organization_id
                WHERE (CASE $7 WHEN 'github-classic-pat' THEN p.github_pat_mode
                    WHEN 'payment-card-number' THEN p.payment_card_mode
                    WHEN 'ai-file-upload' THEN CASE $6 WHEN 'chatgpt' THEN p.chatgpt_upload_mode WHEN 'gemini' THEN p.gemini_upload_mode END
                    ELSE p.mode END)
                    = CASE WHEN $5 = 'warn_override' THEN 'warn' ELSE $5 END
                  AND (r.event_cutoff IS NULL OR $3 >= r.event_cutoff)
                  AND (($8 = 0 AND p.policy_group_id IS NULL) OR EXISTS (SELECT 1 FROM policy_deliveries d
                    WHERE d.installation_id = $1 AND d.assignment_version = $8 AND d.policy_version = $4))
            ), written AS (
                INSERT INTO security_events (organization_id, installation_id, event_id, occurred_at, policy_version, decision, app_id, rule_id, upload_method)
                SELECT organization_id, $1, $2, $3, $4, $5, $6, $7, $9 FROM eligible
                ON CONFLICT (installation_id, event_id) DO NOTHING
            )
            SELECT EXISTS (SELECT 1 FROM eligible)
            """, installationId, request.EventId, request.Timestamp.UtcDateTime, request.PolicyVersion, request.Decision, request.AppId,
            request.RuleId, request.AssignmentVersion, (object?)request.UploadMethod ?? DBNull.Value);
        return (bool)(await command.ExecuteScalarAsync(ct))!;
    }

    public async Task<EventPage> EventHistory(Guid organizationId, EventFilters filters, EventCursor? cursor, CancellationToken ct)
    {
        const int pageSize = 100;
        var entries = new List<StoredEvent>();
        await foreach (var entry in ReadEvents(organizationId, filters, cursor, pageSize + 1, ct))
            entries.Add(entry);
        if (entries.Count <= pageSize) return new(entries, null);
        entries.RemoveAt(pageSize);
        var last = entries[^1];
        return new(entries, new(last.ReceivedAt, last.EventId, last.InstallationId));
    }

    public async IAsyncEnumerable<StoredEvent> ReadEvents(Guid organizationId, EventFilters filters, EventCursor? cursor,
        int? limit, [EnumeratorCancellation] CancellationToken ct)
    {
        await using var command = Command("""
            SELECT event_id, installation_id, occurred_at, received_at, policy_version, decision, app_id, rule_id, upload_method
            FROM security_events e LEFT JOIN retention_cutoffs r ON e.organization_id = r.organization_id
            WHERE e.organization_id = $1
                AND (r.event_cutoff IS NULL OR LEAST(occurred_at, received_at) >= r.event_cutoff)
                AND ($2::text IS NULL OR decision = $2)
                AND ($3::timestamptz IS NULL OR occurred_at >= $3)
                AND ($4::text IS NULL OR app_id = $4)
                AND ($5::timestamptz IS NULL OR occurred_at < $5)
                AND ($6::uuid IS NULL OR installation_id = $6)
                AND ($7::timestamptz IS NULL OR (received_at, event_id, installation_id) < ($7, $8::uuid, $9::uuid))
            ORDER BY received_at DESC, event_id DESC, installation_id DESC LIMIT $10::integer
            """, organizationId, (object?)filters.Decision ?? DBNull.Value, (object?)filters.Since?.UtcDateTime ?? DBNull.Value,
            (object?)filters.AppId ?? DBNull.Value, (object?)filters.Until?.UtcDateTime ?? DBNull.Value,
            (object?)filters.InstallationId ?? DBNull.Value, (object?)cursor?.ReceivedAt.UtcDateTime ?? DBNull.Value,
            (object?)cursor?.EventId ?? DBNull.Value, (object?)cursor?.InstallationId ?? DBNull.Value, (object?)limit ?? DBNull.Value);
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct))
            yield return new(rows.GetGuid(0), rows.GetGuid(1), rows.GetDateTime(2), rows.GetDateTime(3),
                rows.GetInt32(4), rows.GetString(5), rows.GetString(6), rows.GetString(7), rows.IsDBNull(8) ? null : rows.GetString(8));
    }

    public async Task<bool> ObserveApp(Guid installationId, AppObservation observation, CancellationToken ct)
    {
        await using var command = Command("""
            WITH active AS (
                SELECT organization_id, enrolled_at, policy_group_id FROM installations
                WHERE id = $1 AND revoked_at IS NULL AND assignment_version = $5 FOR SHARE
            ), eligible AS (
                SELECT p.organization_id FROM active
                JOIN policy_versions p ON p.organization_id = active.organization_id AND p.version = $4
                LEFT JOIN retention_cutoffs r ON r.organization_id = active.organization_id
                WHERE p.discovery_enabled AND $3 BETWEEN GREATEST(enrolled_at - interval '5 minutes', now() - interval '30 days')
                    AND now() + interval '5 minutes'
                  AND (r.observation_cutoff IS NULL OR $3 >= r.observation_cutoff)
                  AND (($5 = 0 AND p.policy_group_id IS NULL) OR EXISTS (SELECT 1 FROM policy_deliveries d
                    WHERE d.installation_id = $1 AND d.assignment_version = $5 AND d.policy_version = $4))
                  AND NOT EXISTS (SELECT 1 FROM policy_versions later
                    WHERE later.organization_id = p.organization_id AND later.version > p.version AND NOT later.discovery_enabled
                      AND (later.policy_group_id = active.policy_group_id OR (later.policy_group_id IS NULL AND p.policy_group_id IS NULL
                        AND NOT EXISTS (SELECT 1 FROM policy_versions first_group
                          WHERE first_group.organization_id = p.organization_id AND first_group.policy_group_id = active.policy_group_id
                            AND first_group.version <= later.version))))
            ), recorded AS (
                INSERT INTO ai_app_observations (organization_id, installation_id, app_id, observed_at)
                SELECT organization_id, $1, $2, $3 FROM eligible
                ON CONFLICT (organization_id, app_id, installation_id) DO UPDATE SET observed_at = EXCLUDED.observed_at
                WHERE ai_app_observations.observed_at < EXCLUDED.observed_at
            )
            SELECT EXISTS (SELECT 1 FROM eligible)
            """, installationId, observation.AppId, observation.ObservedAt.UtcDateTime, observation.PolicyVersion, observation.AssignmentVersion);
        return (bool)(await command.ExecuteScalarAsync(ct))!;
    }

    public async Task<IReadOnlyList<DiscoveredApp>> DiscoveredApps(Guid organizationId, CancellationToken ct)
    {
        await using var command = Command("""
            SELECT catalog.app_id, COALESCE(c.status, 'unreviewed'), count(o.installation_id), max(o.observed_at)
            FROM unnest($2::text[]) WITH ORDINALITY AS catalog(app_id, position)
            LEFT JOIN retention_cutoffs r ON r.organization_id = $1
            LEFT JOIN ai_app_classifications c ON c.organization_id = $1 AND c.app_id = catalog.app_id
            LEFT JOIN ai_app_observations o ON o.organization_id = $1 AND o.app_id = catalog.app_id
                AND o.observed_at >= GREATEST(now() - interval '30 days', r.observation_cutoff)
            GROUP BY catalog.app_id, catalog.position, c.status ORDER BY catalog.position
            """, organizationId, DiscoveryCatalog.AppIds);
        var apps = new List<DiscoveredApp>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct))
            apps.Add(new(rows.GetString(0), rows.GetString(1), rows.GetInt64(2), rows.IsDBNull(3) ? null : rows.GetDateTime(3)));
        return apps;
    }

    public async Task ClassifyApp(RequestIdentity identity, string appId, string status, CancellationToken ct)
    {
        await using var command = Command("""
            WITH changed AS (
                INSERT INTO ai_app_classifications (organization_id, app_id, status) VALUES ($1, $2, $3)
                ON CONFLICT (organization_id, app_id) DO UPDATE SET status = EXCLUDED.status
                WHERE ai_app_classifications.status IS DISTINCT FROM EXCLUDED.status
                RETURNING organization_id, app_id, status
            )
            INSERT INTO control_audit (organization_id, action, app_id, classification, actor_access_id)
            SELECT organization_id, 'app_classified', app_id, status, $4 FROM changed
            """, identity.OrganizationId, appId, status, (object?)identity.Access?.Id ?? DBNull.Value);
        await command.ExecuteNonQueryAsync(ct);
    }

    public async Task<AuditPage> AuditHistory(Guid organizationId, AuditFilters filters, CancellationToken ct)
    {
        await using var command = Command("""
            SELECT a.id, occurred_at, action, policy_version, restored_from, installation_id, app_id, classification, retention, cleanup, group_change,
                actor.id, actor.display_name, actor.role, subject.id, subject.display_name, subject.role, a.review_change
            FROM control_audit a LEFT JOIN retention_cutoffs r ON a.organization_id = r.organization_id
            LEFT JOIN control_access actor ON actor.organization_id = a.organization_id AND actor.id = a.actor_access_id
            LEFT JOIN control_access subject ON subject.organization_id = a.organization_id AND subject.id = a.subject_access_id
            WHERE a.organization_id = $1
                AND (r.audit_cutoff IS NULL OR occurred_at >= r.audit_cutoff)
                AND ($2::text IS NULL OR action = $2)
                AND ($3::timestamptz IS NULL OR occurred_at >= $3)
                AND ($4::timestamptz IS NULL OR occurred_at < $4)
                AND ($5::timestamptz IS NULL OR (occurred_at, a.id) < ($5, $6::uuid))
            ORDER BY occurred_at DESC, a.id DESC LIMIT $7
            """, organizationId, (object?)filters.Action ?? DBNull.Value, (object?)filters.Since?.UtcDateTime ?? DBNull.Value,
            (object?)filters.Until?.UtcDateTime ?? DBNull.Value, (object?)filters.BeforeAt?.UtcDateTime ?? DBNull.Value,
            (object?)filters.BeforeId ?? DBNull.Value, filters.Limit + 1);
        var entries = new List<AuditEntry>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct))
            entries.Add(new(rows.GetGuid(0), rows.GetDateTime(1), rows.GetString(2), rows.IsDBNull(3) ? null : rows.GetInt32(3),
                rows.IsDBNull(4) ? null : rows.GetInt32(4), rows.IsDBNull(5) ? null : rows.GetGuid(5),
                rows.IsDBNull(6) ? null : rows.GetString(6), rows.IsDBNull(7) ? null : rows.GetString(7),
                rows.IsDBNull(8) ? null : JsonSerializer.Deserialize<RetentionPolicy>(rows.GetString(8), JsonSerializerOptions.Web),
                rows.IsDBNull(9) ? null : JsonSerializer.Deserialize<RetentionCleanup>(rows.GetString(9), JsonSerializerOptions.Web),
                rows.IsDBNull(10) ? null : JsonSerializer.Deserialize<PolicyGroupChange>(rows.GetString(10), JsonSerializerOptions.Web),
                ReadAccessIdentity(rows, 11), ReadAccessIdentity(rows, 14),
                rows.IsDBNull(17) ? null : JsonSerializer.Deserialize<PolicyReviewAudit>(rows.GetString(17), JsonSerializerOptions.Web)));
        if (entries.Count <= filters.Limit) return new(entries, null);
        entries.RemoveAt(filters.Limit);
        var last = entries[^1];
        return new(entries, new(last.OccurredAt, last.Id));
    }

    private NpgsqlCommand Command(string sql, params object[] values)
    {
        var command = dataSource.CreateCommand(sql);
        AddParameters(command, values);
        return command;
    }

    private static void AddParameters(NpgsqlCommand command, params object[] values)
    {
        foreach (var value in values) command.Parameters.Add(new NpgsqlParameter { Value = value });
    }

    private static Policy ReadPolicy(NpgsqlDataReader rows) => new(rows.GetInt32(0), rows.GetString(1),
        rows.GetDateTime(2), rows.IsDBNull(3) ? null : rows.GetInt32(3), rows.GetString(4), rows.GetBoolean(5),
        new(rows.GetFieldValue<string[]>(6), rows.GetFieldValue<string[]>(7)), rows.GetString(8), new(rows.GetString(9), rows.GetString(10)),
        new(rows.GetFieldValue<string[]>(11), rows.GetFieldValue<string[]>(12)), rows.GetBoolean(13));
}
