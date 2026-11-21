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
            INSERT INTO enrollment_grants (token_hash, organization_id, expires_at)
            VALUES ($1, $2, now() + interval '10 minutes') RETURNING expires_at
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
            )
            INSERT INTO installations (id, organization_id, token_hash)
            SELECT $2, organization_id, $3 FROM redeemed
            """, Tokens.Hash(grant), installationId, Tokens.Hash(token));
        return await command.ExecuteNonQueryAsync(ct) == 1 ? new(installationId, token) : null;
    }

    public async Task<Policy?> Publish(Guid organizationId, string? mode, int? restoredFrom, CancellationToken ct)
    {
        await using var command = Command("""
            WITH selection AS (
                SELECT COALESCE($2::text, (SELECT mode FROM policy_versions
                    WHERE organization_id = $1 AND version = $3::integer)) AS mode
            ), next_version AS (
                UPDATE organizations SET policy_version = policy_version + 1
                WHERE id = $1 AND EXISTS (SELECT 1 FROM selection WHERE mode IS NOT NULL)
                RETURNING id, policy_version
            ), published AS (
                INSERT INTO policy_versions (organization_id, version, mode)
                SELECT id, policy_version, mode FROM next_version CROSS JOIN selection
                RETURNING organization_id, version, mode, published_at
            ), audit AS (
                INSERT INTO policy_audit (organization_id, version, restored_from)
                SELECT organization_id, version, $3 FROM published
            )
            SELECT version, mode, published_at, $3 FROM published
            """, organizationId, (object?)mode ?? DBNull.Value, (object?)restoredFrom ?? DBNull.Value);
        await using var rows = await command.ExecuteReaderAsync(ct);
        return await rows.ReadAsync(ct) ? ReadPolicy(rows) : null;
    }

    public async Task<IReadOnlyList<Policy>> PolicyHistory(Guid organizationId, CancellationToken ct)
    {
        await using var command = Command("""
            SELECT p.version, p.mode, p.published_at, a.restored_from
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
            SELECT p.version, p.mode, p.published_at, a.restored_from
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
            )
            """, installationId, request.PolicyVersion, (object?)request.ChatGptCoverage ?? DBNull.Value);
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
            UPDATE installations SET revoked_at = COALESCE(revoked_at, now())
            WHERE organization_id = $1 AND id = $2
            """, organizationId, installationId);
        return await command.ExecuteNonQueryAsync(ct) == 1;
    }

    public async Task<bool> Ingest(Guid installationId, PolicyEvent request, CancellationToken ct)
    {
        await using var command = Command("""
            WITH active AS (
                SELECT organization_id FROM installations WHERE id = $1 AND revoked_at IS NULL FOR SHARE
            ), eligible AS (
                SELECT p.organization_id FROM active
                JOIN policy_versions p ON p.organization_id = active.organization_id AND p.version = $4
                WHERE p.mode = CASE WHEN $5 = 'warn_override' THEN 'warn' ELSE $5 END
            ), written AS (
                INSERT INTO security_events (organization_id, installation_id, event_id, occurred_at, policy_version, decision, app_id)
                SELECT organization_id, $1, $2, $3, $4, $5, $6 FROM eligible
                ON CONFLICT (installation_id, event_id) DO NOTHING
            )
            SELECT EXISTS (SELECT 1 FROM eligible)
            """, installationId, request.EventId, request.Timestamp.UtcDateTime, request.PolicyVersion, request.Decision, request.AppId);
        return (bool)(await command.ExecuteScalarAsync(ct))!;
    }

    public async Task<IReadOnlyList<StoredEvent>> Events(Guid organizationId, string? appId, string? decision,
        DateTimeOffset? since, CancellationToken ct)
    {
        await using var command = Command("""
            SELECT event_id, installation_id, occurred_at, received_at, policy_version, decision, app_id
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
                rows.GetInt32(4), rows.GetString(5), rows.GetString(6)));
        return events;
    }

    private NpgsqlCommand Command(string sql, params object[] values)
    {
        var command = dataSource.CreateCommand(sql);
        foreach (var value in values) command.Parameters.Add(new NpgsqlParameter { Value = value });
        return command;
    }

    private static Policy ReadPolicy(NpgsqlDataReader rows) => new(rows.GetInt32(0), rows.GetString(1),
        rows.GetDateTime(2), rows.IsDBNull(3) ? null : rows.GetInt32(3));
}
