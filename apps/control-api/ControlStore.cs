using Npgsql;

namespace Control;

internal sealed class ControlStore(NpgsqlDataSource dataSource)
{
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

    public async Task<RequestIdentity?> Authenticate(string token, bool browser, CancellationToken ct)
    {
        var sql = browser
            ? "SELECT organization_id, id, NULL::text FROM installations WHERE token_hash = $1 AND revoked_at IS NULL"
            : "SELECT o.id, NULL::uuid, o.slug FROM admin_memberships m JOIN organizations o ON o.id = m.organization_id WHERE m.token_hash = $1";
        await using var command = Command(sql, Tokens.Hash(token));
        await using var rows = await command.ExecuteReaderAsync(ct);
        return await rows.ReadAsync(ct)
            ? new(rows.GetGuid(0), rows.IsDBNull(1) ? null : rows.GetGuid(1), rows.IsDBNull(2) ? null : rows.GetString(2))
            : null;
    }

    public async Task<EnrollmentGrant> CreateGrant(Guid organizationId, CancellationToken ct)
    {
        var grant = Tokens.Generate();
        await using var command = Command("""
            WITH issued AS (
                INSERT INTO enrollment_grants (token_hash, organization_id, expires_at)
                VALUES ($1, $2, now() + interval '10 minutes') RETURNING organization_id, expires_at
            ), audit AS (
                INSERT INTO control_audit (organization_id, action) SELECT organization_id, 'grant_issued' FROM issued
            )
            SELECT expires_at FROM issued
            """, Tokens.Hash(grant), organizationId);
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

    public async Task<Policy?> Publish(Guid organizationId, PublishPolicy? request, int? restoredFrom, CancellationToken ct)
    {
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        // Read the source version after locking the organization so concurrent publishes cannot lose a rule.
        await using var gate = new NpgsqlCommand("SELECT id FROM organizations WHERE id = $1 FOR UPDATE", connection, transaction);
        gate.Parameters.AddWithValue(organizationId);
        if (await gate.ExecuteScalarAsync(ct) is null) return null;

        await using var command = new NpgsqlCommand("""
            WITH selection AS (
                SELECT COALESCE($2::text, p.mode) AS mode, COALESCE($4::text, p.github_pat_mode) AS github_pat_mode,
                    COALESCE($5::boolean, p.discovery_enabled) AS discovery_enabled,
                    COALESCE($6::text[], p.allowed_domains) AS allowed_domains,
                    COALESCE($7::text[], p.blocked_domains) AS blocked_domains
                FROM organizations o JOIN policy_versions p ON p.organization_id = o.id
                  AND p.version = COALESCE($3::integer, o.policy_version)
                WHERE o.id = $1
            ), next_version AS (
                UPDATE organizations SET policy_version = policy_version + 1
                WHERE id = $1 AND EXISTS (SELECT 1 FROM selection)
                RETURNING id, policy_version
            ), published AS (
                INSERT INTO policy_versions (organization_id, version, mode, github_pat_mode, discovery_enabled, allowed_domains, blocked_domains)
                SELECT id, policy_version, mode, github_pat_mode, discovery_enabled, allowed_domains, blocked_domains
                FROM next_version CROSS JOIN selection
                RETURNING organization_id, version, mode, published_at, github_pat_mode, discovery_enabled, allowed_domains, blocked_domains
            ), history AS (
                INSERT INTO policy_audit (organization_id, version, restored_from)
                SELECT organization_id, version, $3 FROM published
            ), audit AS (
                INSERT INTO control_audit (organization_id, occurred_at, action, policy_version, restored_from)
                SELECT organization_id, published_at, CASE WHEN $3 IS NULL THEN 'policy_published' ELSE 'policy_restored' END,
                    version, $3 FROM published
            )
            SELECT version, mode, published_at, $3, github_pat_mode, discovery_enabled, allowed_domains, blocked_domains FROM published
            """, connection, transaction);
        AddParameters(command, organizationId, (object?)request?.Mode ?? DBNull.Value, (object?)restoredFrom ?? DBNull.Value,
            (object?)request?.GithubPatMode ?? DBNull.Value, (object?)request?.DiscoveryEnabled ?? DBNull.Value,
            (object?)request?.DomainRules?.Allow ?? DBNull.Value, (object?)request?.DomainRules?.Block ?? DBNull.Value);
        Policy? policy;
        await using (var rows = await command.ExecuteReaderAsync(ct))
            policy = await rows.ReadAsync(ct) ? ReadPolicy(rows) : null;
        await transaction.CommitAsync(ct);
        return policy;
    }

    public async Task<IReadOnlyList<Policy>> PolicyHistory(Guid organizationId, CancellationToken ct)
    {
        await using var command = Command("""
            SELECT p.version, p.mode, p.published_at, a.restored_from, p.github_pat_mode, p.discovery_enabled,
                p.allowed_domains, p.blocked_domains
            FROM policy_versions p LEFT JOIN policy_audit a USING (organization_id, version)
            WHERE p.organization_id = $1 ORDER BY p.version DESC LIMIT 100
            """, organizationId);
        var policies = new List<Policy>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct)) policies.Add(ReadPolicy(rows));
        return policies;
    }

    public async Task<Policy?> CurrentPolicy(Guid installationId, CancellationToken ct)
    {
        await using var command = Command("""
            WITH active AS (
                UPDATE installations SET last_seen_at = GREATEST(last_seen_at, now())
                WHERE id = $1 AND revoked_at IS NULL RETURNING organization_id
            )
            SELECT p.version, p.mode, p.published_at, a.restored_from, p.github_pat_mode, p.discovery_enabled,
                p.allowed_domains, p.blocked_domains
            FROM active JOIN organizations o ON o.id = active.organization_id
            JOIN policy_versions p ON p.organization_id = o.id AND p.version = o.policy_version
            LEFT JOIN policy_audit a ON a.organization_id = p.organization_id AND a.version = p.version
            """, installationId);
        await using var rows = await command.ExecuteReaderAsync(ct);
        return await rows.ReadAsync(ct) ? ReadPolicy(rows) : null;
    }

    public async Task<bool> RecordHeartbeat(Guid installationId, Heartbeat request, CancellationToken ct)
    {
        await using var command = Command("""
            UPDATE installations i SET last_seen_at = GREATEST(i.last_seen_at, now()),
                applied_policy_version = GREATEST(i.applied_policy_version, $2),
                chatgpt_coverage = COALESCE($3::text, i.chatgpt_coverage),
                chatgpt_checked_at = CASE WHEN $3::text IS NULL THEN i.chatgpt_checked_at ELSE now() END
            WHERE i.id = $1 AND i.revoked_at IS NULL AND EXISTS (
                SELECT 1 FROM policy_versions p WHERE p.organization_id = i.organization_id AND p.version = $2
                  AND ($4 OR cardinality(p.allowed_domains) + cardinality(p.blocked_domains) = 0)
            )
            """, installationId, request.PolicyVersion, (object?)request.ChatGptCoverage ?? DBNull.Value, request.DomainRulesApplied);
        return await command.ExecuteNonQueryAsync(ct) == 1;
    }

    public async Task<IReadOnlyList<Installation>> Installations(Guid organizationId, CancellationToken ct)
    {
        await using var command = Command("""
            SELECT id, enrolled_at, last_seen_at, applied_policy_version, revoked_at, chatgpt_coverage, chatgpt_checked_at
            FROM installations WHERE organization_id = $1 ORDER BY enrolled_at DESC, id LIMIT 100
            """, organizationId);
        var installations = new List<Installation>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct))
            installations.Add(new(rows.GetGuid(0), rows.GetDateTime(1), rows.GetDateTime(2),
                rows.IsDBNull(3) ? null : rows.GetInt32(3), rows.IsDBNull(4) ? null : rows.GetDateTime(4),
                rows.IsDBNull(5) ? null : rows.GetString(5), rows.IsDBNull(6) ? null : rows.GetDateTime(6)));
        return installations;
    }

    public async Task<bool> Revoke(Guid organizationId, Guid installationId, CancellationToken ct)
    {
        await using var command = Command("""
            WITH revoked AS (
                UPDATE installations SET revoked_at = now() WHERE organization_id = $1 AND id = $2 AND revoked_at IS NULL
                RETURNING organization_id, id, revoked_at
            ), audit AS (
                INSERT INTO control_audit (organization_id, occurred_at, action, installation_id)
                SELECT organization_id, revoked_at, 'browser_revoked', id FROM revoked
            )
            SELECT EXISTS (SELECT 1 FROM installations WHERE organization_id = $1 AND id = $2)
            """, organizationId, installationId);
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
                WHERE (CASE WHEN $7 = 'github-classic-pat' THEN p.github_pat_mode ELSE p.mode END)
                    = CASE WHEN $5 = 'warn_override' THEN 'warn' ELSE $5 END
            ), written AS (
                INSERT INTO security_events (organization_id, installation_id, event_id, occurred_at, policy_version, decision, app_id, rule_id)
                SELECT organization_id, $1, $2, $3, $4, $5, $6, $7 FROM eligible
                ON CONFLICT (installation_id, event_id) DO NOTHING
            )
            SELECT EXISTS (SELECT 1 FROM eligible)
            """, installationId, request.EventId, request.Timestamp.UtcDateTime, request.PolicyVersion, request.Decision, request.AppId, request.RuleId);
        return (bool)(await command.ExecuteScalarAsync(ct))!;
    }

    public async Task<IReadOnlyList<StoredEvent>> Events(Guid organizationId, string? appId, string? decision,
        DateTimeOffset? since, CancellationToken ct)
    {
        await using var command = Command("""
            SELECT event_id, installation_id, occurred_at, received_at, policy_version, decision, app_id, rule_id
            FROM security_events WHERE organization_id = $1
                AND ($2::text IS NULL OR decision = $2)
                AND ($3::timestamptz IS NULL OR occurred_at >= $3)
                AND ($4::text IS NULL OR app_id = $4)
            ORDER BY received_at DESC, event_id LIMIT 100
            """, organizationId, (object?)decision ?? DBNull.Value, (object?)since?.UtcDateTime ?? DBNull.Value,
            (object?)appId ?? DBNull.Value);
        var events = new List<StoredEvent>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct))
            events.Add(new(rows.GetGuid(0), rows.GetGuid(1), rows.GetDateTime(2), rows.GetDateTime(3),
                rows.GetInt32(4), rows.GetString(5), rows.GetString(6), rows.GetString(7)));
        return events;
    }

    public async Task<bool> ObserveApp(Guid installationId, AppObservation observation, CancellationToken ct)
    {
        await using var command = Command("""
            WITH active AS (
                SELECT organization_id, enrolled_at FROM installations WHERE id = $1 AND revoked_at IS NULL FOR SHARE
            ), eligible AS (
                SELECT p.organization_id FROM active
                JOIN policy_versions p ON p.organization_id = active.organization_id AND p.version = $4
                WHERE p.discovery_enabled AND $3 BETWEEN GREATEST(enrolled_at - interval '5 minutes', now() - interval '30 days')
                    AND now() + interval '5 minutes'
                  AND NOT EXISTS (SELECT 1 FROM policy_versions later
                    WHERE later.organization_id = p.organization_id AND later.version > p.version AND NOT later.discovery_enabled)
            ), recorded AS (
                INSERT INTO ai_app_observations (organization_id, installation_id, app_id, observed_at)
                SELECT organization_id, $1, $2, $3 FROM eligible
                ON CONFLICT (organization_id, app_id, installation_id) DO UPDATE SET observed_at = EXCLUDED.observed_at
                WHERE ai_app_observations.observed_at < EXCLUDED.observed_at
            )
            SELECT EXISTS (SELECT 1 FROM eligible)
            """, installationId, observation.AppId, observation.ObservedAt.UtcDateTime, observation.PolicyVersion);
        return (bool)(await command.ExecuteScalarAsync(ct))!;
    }

    public async Task<IReadOnlyList<DiscoveredApp>> DiscoveredApps(Guid organizationId, CancellationToken ct)
    {
        await using var command = Command("""
            SELECT catalog.app_id, COALESCE(c.status, 'unreviewed'), count(o.installation_id), max(o.observed_at)
            FROM unnest($2::text[]) WITH ORDINALITY AS catalog(app_id, position)
            LEFT JOIN ai_app_classifications c ON c.organization_id = $1 AND c.app_id = catalog.app_id
            LEFT JOIN ai_app_observations o ON o.organization_id = $1 AND o.app_id = catalog.app_id
                AND o.observed_at >= now() - interval '30 days'
            GROUP BY catalog.app_id, catalog.position, c.status ORDER BY catalog.position
            """, organizationId, DiscoveryCatalog.AppIds);
        var apps = new List<DiscoveredApp>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct))
            apps.Add(new(rows.GetString(0), rows.GetString(1), rows.GetInt64(2), rows.IsDBNull(3) ? null : rows.GetDateTime(3)));
        return apps;
    }

    public async Task ClassifyApp(Guid organizationId, string appId, string status, CancellationToken ct)
    {
        await using var command = Command("""
            WITH changed AS (
                INSERT INTO ai_app_classifications (organization_id, app_id, status) VALUES ($1, $2, $3)
                ON CONFLICT (organization_id, app_id) DO UPDATE SET status = EXCLUDED.status
                WHERE ai_app_classifications.status IS DISTINCT FROM EXCLUDED.status
                RETURNING organization_id, app_id, status
            )
            INSERT INTO control_audit (organization_id, action, app_id, classification)
            SELECT organization_id, 'app_classified', app_id, status FROM changed
            """, organizationId, appId, status);
        await command.ExecuteNonQueryAsync(ct);
    }

    public async Task<AuditPage> AuditHistory(Guid organizationId, AuditFilters filters, CancellationToken ct)
    {
        await using var command = Command("""
            SELECT id, occurred_at, action, policy_version, restored_from, installation_id, app_id, classification
            FROM control_audit WHERE organization_id = $1
                AND ($2::text IS NULL OR action = $2)
                AND ($3::timestamptz IS NULL OR occurred_at >= $3)
                AND ($4::timestamptz IS NULL OR occurred_at < $4)
                AND ($5::timestamptz IS NULL OR (occurred_at, id) < ($5, $6::uuid))
            ORDER BY occurred_at DESC, id DESC LIMIT $7
            """, organizationId, (object?)filters.Action ?? DBNull.Value, (object?)filters.Since?.UtcDateTime ?? DBNull.Value,
            (object?)filters.Until?.UtcDateTime ?? DBNull.Value, (object?)filters.BeforeAt?.UtcDateTime ?? DBNull.Value,
            (object?)filters.BeforeId ?? DBNull.Value, filters.Limit + 1);
        var entries = new List<AuditEntry>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct))
            entries.Add(new(rows.GetGuid(0), rows.GetDateTime(1), rows.GetString(2), rows.IsDBNull(3) ? null : rows.GetInt32(3),
                rows.IsDBNull(4) ? null : rows.GetInt32(4), rows.IsDBNull(5) ? null : rows.GetGuid(5),
                rows.IsDBNull(6) ? null : rows.GetString(6), rows.IsDBNull(7) ? null : rows.GetString(7)));
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
        new(rows.GetFieldValue<string[]>(6), rows.GetFieldValue<string[]>(7)));
}
