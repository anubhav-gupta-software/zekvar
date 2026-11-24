using System.Data;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Npgsql;

namespace Control;

internal sealed partial class ControlStore
{
    private readonly NpgsqlDataSource dataSource;
    private readonly ControlSso? sso;
    private readonly AlertWebhooks alertWebhooks;

    public ControlStore(NpgsqlDataSource dataSource, ControlSso? sso, AlertWebhooks alertWebhooks) =>
        (this.dataSource, this.sso, this.alertWebhooks) = (dataSource, sso, alertWebhooks);

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
        await ApplyMigration(connection, 17, "017_upload_types.sql", ct);
        await ApplyMigration(connection, 18, "018_custom_app_catalog.sql", ct);
        await ApplyMigration(connection, 19, "019_prompt_exceptions.sql", ct);
        await ApplyMigration(connection, 20, "020_claude_prompt_protection.sql", ct);
        await ApplyMigration(connection, 21, "021_control_sso.sql", ct);
        await ApplyMigration(connection, 22, "022_browser_release.sql", ct);
        await ApplyMigration(connection, 23, "023_enrollment_batches.sql", ct);
        await ApplyMigration(connection, 24, "024_ai_enforcement_report.sql", ct);
        await ApplyMigration(connection, 25, "025_composer_readiness.sql", ct);
        await ApplyMigration(connection, 26, "026_private_key_detection.sql", ct);
        await ApplyMigration(connection, 27, "027_file_content_inspection.sql", ct);
        await ApplyMigration(connection, 28, "028_event_rollout_attribution.sql", ct);
        await ApplyMigration(connection, 29, "029_extension_deployment.sql", ct);
        await ApplyMigration(connection, 30, "030_ai_app_access.sql", ct);
        await ApplyMigration(connection, 31, "031_event_triage.sql", ct);
        await ApplyMigration(connection, 32, "032_file_content_block.sql", ct);
        await ApplyMigration(connection, 33, "033_organization_identifiers.sql", ct);
        await ApplyMigration(connection, 34, "034_incident_cases.sql", ct);
        await ApplyMigration(connection, 35, "035_ai_discovery_presets.sql", ct);
        await ApplyMigration(connection, 36, "036_social_security_number.sql", ct);
        await ApplyMigration(connection, 37, "037_security_alerts.sql", ct);
        await ApplyMigration(connection, 38, "038_alert_webhook_delivery.sql", ct);
        await ApplyMigration(connection, 39, "039_security_event_feed.sql", ct);
        await ApplyMigration(connection, 40, "040_browser_hardening.sql", ct);
        await ApplyMigration(connection, 41, "041_clipboard_paste.sql", ct);
        await ApplyMigration(connection, 42, "042_browser_fleet_batches.sql", ct);
        await ApplyMigration(connection, 43, "043_policy_templates.sql", ct);
        await ApplyMigration(connection, 44, "044_github_tokens.sql", ct);
        await ApplyMigration(connection, 45, "045_prompt_exception_requests.sql", ct);
        await ApplyMigration(connection, 46, "046_prompt_app_modes.sql", ct);
        await ApplyMigration(connection, 47, "047_extension_inventory_changes.sql", ct);
        await ApplyMigration(connection, 48, "048_extension_access_alerts.sql", ct);
        await ApplyMigration(connection, 49, "049_policy_composer_gate.sql", ct);

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
                ), event_stream AS (
                    INSERT INTO organization_event_streams (organization_id)
                    SELECT id FROM org ON CONFLICT DO NOTHING
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

    public async Task<Enrollment?> Enroll(string grant, bool scopedEnrollment, CancellationToken ct)
    {
        var installationId = Guid.NewGuid();
        var token = Tokens.Generate();
        await using var command = Command("""
            WITH redeemed AS (
                UPDATE enrollment_grants g SET redeemed_at = now()
                WHERE g.token_hash = $1 AND g.redeemed_at IS NULL AND g.expires_at > now()
                    AND (g.batch_id IS NULL OR EXISTS (SELECT 1 FROM enrollment_batches b WHERE b.organization_id = g.organization_id
                        AND b.id = g.batch_id AND b.cancelled_at IS NULL AND (b.policy_group_id IS NULL OR $4)))
                RETURNING organization_id, batch_id
            ), scope AS (
                SELECT r.organization_id, r.batch_id, b.policy_group_id, p.name
                FROM redeemed r LEFT JOIN enrollment_batches b ON b.organization_id = r.organization_id AND b.id = r.batch_id
                LEFT JOIN policy_groups p ON p.organization_id = r.organization_id AND p.id = b.policy_group_id
            ), enrolled AS (
                INSERT INTO installations (id, organization_id, token_hash, policy_group_id, assignment_version, assignment_aware)
                SELECT $2, organization_id, $3, policy_group_id, CASE WHEN policy_group_id IS NULL THEN 0 ELSE 1 END,
                    policy_group_id IS NOT NULL FROM scope RETURNING organization_id, id, enrolled_at
            )
            INSERT INTO control_audit (organization_id, occurred_at, action, installation_id, enrollment_batch_change)
            SELECT e.organization_id, e.enrolled_at, 'browser_enrolled', e.id, CASE WHEN s.batch_id IS NOT NULL THEN
                jsonb_build_object('batchId', s.batch_id, 'groupId', s.policy_group_id, 'groupName', s.name, 'count', 1) END
            FROM enrolled e JOIN scope s ON e.organization_id = s.organization_id
            """, Tokens.Hash(grant), installationId, Tokens.Hash(token), scopedEnrollment);
        return await command.ExecuteNonQueryAsync(ct) == 1 ? new(installationId, token) : null;
    }

    public async Task<IReadOnlyList<Policy>> PolicyHistory(Guid organizationId, CancellationToken ct, Guid? groupId = null)
    {
        await using var command = Command("""
            SELECT p.version, p.mode, p.published_at, a.restored_from, p.github_pat_mode, p.discovery_enabled,
                p.allowed_domains, p.blocked_domains, p.payment_card_mode, p.chatgpt_upload_mode, p.gemini_upload_mode,
                p.allowed_paths, p.blocked_paths, p.extension_inventory_enabled, p.chatgpt_upload_types, p.gemini_upload_types,
                p.custom_apps, p.prompt_exceptions, p.claude_prompt_enabled, p.private_key_mode, p.chatgpt_file_inspection, p.gemini_file_inspection,
                p.blocked_ai_app_hosts, p.chatgpt_file_content_block, p.gemini_file_content_block, p.identifier_protection, p.extension_deployment,
                p.preset_discovery_enabled, p.ssn_mode, p.browser_hardening, p.clipboard_mode, p.github_token_mode, p.prompt_app_modes
            FROM policy_versions p LEFT JOIN policy_audit a USING (organization_id, version)
            WHERE p.organization_id = $1 AND p.policy_group_id IS NOT DISTINCT FROM $2::uuid ORDER BY p.version DESC LIMIT 100
            """, organizationId, (object?)groupId ?? DBNull.Value);
        var policies = new List<Policy>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct)) policies.Add(ReadPolicy(rows));
        return policies;
    }

    public async Task<Policy?> CurrentPolicy(Guid installationId, bool assignmentAware, bool claudeAware, string? extensionVersion, bool privateKeyAware,
        bool fileInspectionAware, bool aiAppAccessAware, bool fileBlockAware, bool identifiersAware, bool presetDiscoveryAware,
        bool ssnAware, bool clipboardAware, bool githubTokenAware, bool promptAppModesAware, CancellationToken ct)
    {
        await using var command = Command("""
            WITH active AS (
                UPDATE installations SET last_seen_at = GREATEST(last_seen_at, now()), assignment_aware = $2,
                    extension_version = CASE WHEN $4::text IS NOT NULL AND
                        (extension_version_reported_at IS NULL OR extension_version_reported_at <= now())
                        THEN $4 ELSE extension_version END,
                    extension_version_reported_at = CASE WHEN $4::text IS NOT NULL
                        THEN GREATEST(extension_version_reported_at, now()) ELSE extension_version_reported_at END
                WHERE id = $1 AND revoked_at IS NULL AND (assignment_version = 0 OR $2)
                RETURNING organization_id, id, policy_group_id, assignment_version
            ), effective AS (
                SELECT i.organization_id, i.id, i.assignment_version, i.policy_group_id,
                    COALESCE(g.policy_version, o.policy_version) AS version
                FROM active i JOIN organizations o ON o.id = i.organization_id
                LEFT JOIN policy_groups g ON g.organization_id = o.id AND g.id = i.policy_group_id
            ), delivery AS (
                INSERT INTO policy_deliveries (organization_id, installation_id, assignment_version, policy_version,
                    exception_scope, claude_prompt, private_key, file_inspection, rollout_group_id, rollout_attributed, ai_app_access, file_content_block,
                    identifiers, preset_discovery, ssn, clipboard_paste, github_token, prompt_app_modes)
                SELECT e.organization_id, e.id, e.assignment_version, e.version, e.policy_group_id IS NOT DISTINCT FROM p.policy_group_id,
                    $3 AND p.claude_prompt_enabled, $5 AND p.private_key_mode <> 'off',
                    $6 AND (p.chatgpt_file_inspection AND (NOT p.chatgpt_file_content_block OR $8)
                        OR p.gemini_file_inspection AND (NOT p.gemini_file_content_block OR $8)), e.policy_group_id, true,
                    $7 AND cardinality(p.blocked_ai_app_hosts) > 0, $8 AND (p.chatgpt_file_content_block OR p.gemini_file_content_block),
                    $9 AND p.identifier_protection->>'mode' <> 'off', $10 AND p.discovery_enabled AND p.preset_discovery_enabled,
                    $11 AND p.ssn_mode <> 'off', $12 AND p.clipboard_mode <> 'off', $13 AND p.github_token_mode <> 'off',
                    $14 AND p.prompt_app_modes <> '{}'::jsonb
                FROM effective e JOIN policy_versions p ON p.organization_id = e.organization_id AND p.version = e.version
                ON CONFLICT (installation_id, assignment_version, policy_version) DO UPDATE
                SET claude_prompt = policy_deliveries.claude_prompt OR EXCLUDED.claude_prompt,
                    private_key = policy_deliveries.private_key OR EXCLUDED.private_key,
                    file_inspection = policy_deliveries.file_inspection OR EXCLUDED.file_inspection,
                    ai_app_access = policy_deliveries.ai_app_access OR EXCLUDED.ai_app_access,
                    file_content_block = policy_deliveries.file_content_block OR EXCLUDED.file_content_block,
                    identifiers = policy_deliveries.identifiers OR EXCLUDED.identifiers,
                    preset_discovery = policy_deliveries.preset_discovery OR EXCLUDED.preset_discovery,
                    ssn = policy_deliveries.ssn OR EXCLUDED.ssn,
                    clipboard_paste = policy_deliveries.clipboard_paste OR EXCLUDED.clipboard_paste,
                    github_token = policy_deliveries.github_token OR EXCLUDED.github_token,
                    prompt_app_modes = policy_deliveries.prompt_app_modes OR EXCLUDED.prompt_app_modes,
                    rollout_group_id = CASE WHEN policy_deliveries.rollout_attributed THEN policy_deliveries.rollout_group_id
                        ELSE EXCLUDED.rollout_group_id END,
                    rollout_attributed = true
                WHERE (EXCLUDED.claude_prompt AND NOT policy_deliveries.claude_prompt)
                    OR (EXCLUDED.private_key AND NOT policy_deliveries.private_key)
                    OR (EXCLUDED.file_inspection AND NOT policy_deliveries.file_inspection)
                    OR (EXCLUDED.ai_app_access AND NOT policy_deliveries.ai_app_access)
                    OR (EXCLUDED.file_content_block AND NOT policy_deliveries.file_content_block)
                    OR (EXCLUDED.identifiers AND NOT policy_deliveries.identifiers)
                    OR (EXCLUDED.preset_discovery AND NOT policy_deliveries.preset_discovery)
                    OR (EXCLUDED.ssn AND NOT policy_deliveries.ssn)
                    OR (EXCLUDED.clipboard_paste AND NOT policy_deliveries.clipboard_paste)
                    OR (EXCLUDED.github_token AND NOT policy_deliveries.github_token)
                    OR (EXCLUDED.prompt_app_modes AND NOT policy_deliveries.prompt_app_modes)
                    OR NOT policy_deliveries.rollout_attributed
            )
            SELECT p.version, p.mode, p.published_at, a.restored_from, p.github_pat_mode, p.discovery_enabled,
                p.allowed_domains, p.blocked_domains, p.payment_card_mode, p.chatgpt_upload_mode, p.gemini_upload_mode,
                p.allowed_paths, p.blocked_paths, p.extension_inventory_enabled, p.chatgpt_upload_types, p.gemini_upload_types,
                p.custom_apps, p.prompt_exceptions, p.claude_prompt_enabled, p.private_key_mode, p.chatgpt_file_inspection, p.gemini_file_inspection,
                p.blocked_ai_app_hosts, p.chatgpt_file_content_block, p.gemini_file_content_block, p.identifier_protection,
                e.assignment_version, e.policy_group_id IS NOT DISTINCT FROM p.policy_group_id, p.preset_discovery_enabled, p.ssn_mode,
                p.clipboard_mode, p.github_token_mode, p.prompt_app_modes
            FROM effective e JOIN policy_versions p ON p.organization_id = e.organization_id AND p.version = e.version
            LEFT JOIN policy_audit a ON a.organization_id = p.organization_id AND a.version = p.version
            """, installationId, assignmentAware, claudeAware, (object?)extensionVersion ?? DBNull.Value, privateKeyAware,
            fileInspectionAware, aiAppAccessAware, fileBlockAware, identifiersAware, presetDiscoveryAware, ssnAware, clipboardAware, githubTokenAware,
            promptAppModesAware);
        await using var rows = await command.ExecuteReaderAsync(ct);
        if (!await rows.ReadAsync(ct)) return null;
        var policy = ReadPolicy(rows, includeDeployment: false);
        return policy with { AssignmentVersion = rows.GetInt32(26), PromptExceptions = rows.GetBoolean(27) ? policy.PromptExceptions : [] };
    }

    public async Task<bool> RecordHeartbeat(Guid installationId, Heartbeat request, bool scopedCoverage, CancellationToken ct)
    {
        await using var command = Command("""
            WITH updated AS (
            UPDATE installations i SET last_seen_at = GREATEST(i.last_seen_at, now()),
                applied_policy_version = CASE WHEN (p.payment_card_mode = 'off' OR $7)
                    AND (p.chatgpt_upload_mode = 'off' AND p.gemini_upload_mode = 'off' OR $8)
                    AND (cardinality(p.allowed_paths) + cardinality(p.blocked_paths) = 0 OR $9)
                    AND ($10 OR (p.chatgpt_upload_mode = 'off' OR cardinality(p.chatgpt_upload_types) = 0)
                        AND (p.gemini_upload_mode = 'off' OR cardinality(p.gemini_upload_types) = 0))
                    AND (NOT p.discovery_enabled OR p.custom_apps = '[]'::jsonb OR $11)
                    AND (NOT p.claude_prompt_enabled OR $14)
                    AND (p.private_key_mode = 'off' OR $16)
                    AND (NOT (p.chatgpt_file_inspection OR p.gemini_file_inspection) OR $17)
                    AND (cardinality(p.blocked_ai_app_hosts) = 0 OR $18)
                    AND (NOT (p.chatgpt_file_content_block OR p.gemini_file_content_block) OR $19)
                    AND (p.identifier_protection->>'mode' = 'off' OR $20)
                    AND (p.ssn_mode = 'off' OR $21)
                    AND (p.clipboard_mode = 'off' OR $22)
                    AND (p.github_token_mode = 'off' OR $23)
                    AND (p.prompt_app_modes = '{}'::jsonb OR $24)
                    AND ($12 OR i.policy_group_id IS DISTINCT FROM p.policy_group_id OR NOT EXISTS (
                        SELECT 1 FROM jsonb_array_elements(p.prompt_exceptions) AS entries(entry)
                        WHERE (entry->>'expiresAt')::timestamptz > now()
                            AND (entry->>'appId' <> 'claude' OR p.claude_prompt_enabled)
                            AND (entry->>'ruleId' <> 'pem-private-key' OR p.private_key_mode <> 'off'
                                AND COALESCE(p.prompt_app_modes->>(entry->>'appId'), p.private_key_mode) IN ('warn', 'block'))
                            AND (entry->>'ruleId' <> 'organization-identifier' OR p.identifier_protection->>'mode' <> 'off'
                                AND COALESCE(p.prompt_app_modes->>(entry->>'appId'), p.identifier_protection->>'mode') IN ('warn', 'block'))
                            AND (entry->>'ruleId' <> 'us-social-security-number' OR p.ssn_mode <> 'off'
                                AND COALESCE(p.prompt_app_modes->>(entry->>'appId'), p.ssn_mode) IN ('warn', 'block'))
                            AND (entry->>'ruleId' <> 'github-app-or-fine-grained-token' OR p.github_token_mode <> 'off'
                                AND COALESCE(p.prompt_app_modes->>(entry->>'appId'), p.github_token_mode) IN ('warn', 'block'))))
                    THEN GREATEST(i.applied_policy_version, $2)
                    WHEN i.applied_policy_version = $2 THEN NULL ELSE i.applied_policy_version END,
                chatgpt_coverage = COALESCE($3::text, i.chatgpt_coverage),
                chatgpt_checked_at = CASE WHEN $3::text IS NULL THEN i.chatgpt_checked_at ELSE now() END,
                gemini_coverage = COALESCE($6::text, i.gemini_coverage),
                gemini_checked_at = CASE WHEN $6::text IS NULL THEN i.gemini_checked_at ELSE now() END,
                claude_coverage = CASE WHEN $13::text IS NOT NULL AND $2 >= COALESCE(i.claude_coverage_version, 0)
                    THEN $13 ELSE i.claude_coverage END,
                claude_checked_at = CASE WHEN $13::text IS NOT NULL AND $2 >= COALESCE(i.claude_coverage_version, 0)
                    THEN now() ELSE i.claude_checked_at END,
                claude_coverage_version = CASE WHEN $13::text IS NOT NULL THEN GREATEST(i.claude_coverage_version, $2)
                    ELSE i.claude_coverage_version END
            FROM policy_versions p
            WHERE i.id = $1 AND i.revoked_at IS NULL AND i.assignment_version = $5
                AND p.organization_id = i.organization_id AND p.version = $2
                AND ($4 OR cardinality(p.allowed_domains) + cardinality(p.blocked_domains) = 0)
                AND ($13::text IS NULL OR p.claude_prompt_enabled AND $14)
                AND (($5 = 0 AND p.policy_group_id IS NULL AND NOT $14 AND NOT $16 AND NOT $17 AND NOT $18 AND NOT $19 AND NOT $20
                    AND NOT $21 AND NOT $22 AND NOT $23 AND NOT $24)
                    OR EXISTS (SELECT 1 FROM policy_deliveries d
                    WHERE d.installation_id = i.id AND d.assignment_version = $5 AND d.policy_version = $2
                        AND (NOT $14 OR d.claude_prompt) AND (NOT $16 OR d.private_key) AND (NOT $17 OR d.file_inspection)
                        AND (NOT $18 OR d.ai_app_access) AND (NOT $19 OR d.file_content_block) AND (NOT $20 OR d.identifiers)
                        AND (NOT $21 OR d.ssn) AND (NOT $22 OR d.clipboard_paste) AND (NOT $23 OR d.github_token)
                        AND (NOT $24 OR d.prompt_app_modes)))
            RETURNING i.id, i.organization_id
            ), observed AS (
                INSERT INTO composer_observations (organization_id, installation_id, app_id, policy_version, assignment_version, coverage)
                SELECT u.organization_id, u.id, report.app_id, $2, $5, report.coverage
                FROM updated u CROSS JOIN (VALUES ('chatgpt', $3::text), ('gemini', $6::text), ('claude', $13::text)) report(app_id, coverage)
                WHERE $15 AND report.coverage IS NOT NULL
                ON CONFLICT (installation_id, app_id) DO UPDATE SET policy_version = EXCLUDED.policy_version,
                    assignment_version = EXCLUDED.assignment_version, coverage = EXCLUDED.coverage,
                    checked_at = GREATEST(composer_observations.checked_at, EXCLUDED.checked_at)
                WHERE (composer_observations.assignment_version, composer_observations.policy_version, composer_observations.checked_at)
                    <= (EXCLUDED.assignment_version, EXCLUDED.policy_version, EXCLUDED.checked_at)
            )
            SELECT EXISTS (SELECT FROM updated)
            """, installationId, request.PolicyVersion, (object?)request.ChatGptCoverage ?? DBNull.Value,
            request.DomainRulesApplied, request.AssignmentVersion, (object?)request.GeminiCoverage ?? DBNull.Value,
            request.PaymentCardModeApplied, request.UploadControlsApplied, request.PathRulesApplied, request.UploadTypesApplied,
            request.CustomDiscoveryApplied, request.PromptExceptionsApplied, (object?)request.ClaudeCoverage ?? DBNull.Value,
            request.ClaudePromptApplied, scopedCoverage, request.PrivateKeyModeApplied, request.FileInspectionApplied, request.AiAppAccessApplied,
            request.FileContentBlockApplied, request.IdentifiersApplied, request.SsnModeApplied, request.ClipboardModeApplied, request.GithubTokenModeApplied,
            request.PromptAppModesApplied);
        return (bool)(await command.ExecuteScalarAsync(ct))!;
    }

    public async Task<BrowserHealthView?> BrowserHealth(Guid organizationId, BrowserHealthFilter filter, CancellationToken ct)
    {
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var snapshot = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        if (filter.GroupId is { } groupId)
        {
            await using var group = BrowserRead(snapshot,
                "SELECT EXISTS (SELECT FROM policy_groups WHERE organization_id = $1 AND id = $2)", organizationId, groupId);
            if (await group.ExecuteScalarAsync(ct) is not true) return null;
        }

        var releases = await BrowserReleases(organizationId, ct, filter, snapshot);
        var installations = await Installations(organizationId, ct, filter, snapshot);
        var (readiness, checks) = await BrowserComposerReadiness(organizationId, filter, installations, snapshot, ct);
        var active = releases.Sum(row => row.Installations);
        if (filter.Scoped)
        {
            await using var count = BrowserRead(snapshot,
                "SELECT count(*) FROM installations WHERE organization_id = $1 AND revoked_at IS NULL", organizationId);
            active = (long)(await count.ExecuteScalarAsync(ct))!;
        }
        await snapshot.CommitAsync(ct);
        return new(active, releases, installations.Select(row => checks.TryGetValue(row.InstallationId, out var composers)
            ? row with { ComposerReadiness = composers } : row).ToArray(), readiness);
    }

    public async Task<IReadOnlyList<Installation>> Installations(Guid organizationId, CancellationToken ct,
        BrowserHealthFilter filter = default, NpgsqlTransaction? snapshot = null)
    {
        await using var command = BrowserRead(snapshot, """
            SELECT i.id, i.enrolled_at, i.last_seen_at, i.applied_policy_version, i.revoked_at, i.chatgpt_coverage, i.chatgpt_checked_at,
                i.policy_group_id, g.name, p.version, i.assignment_aware, i.gemini_coverage, i.gemini_checked_at,
                p.claude_prompt_enabled, CASE WHEN i.claude_coverage_version = p.version AND i.revoked_at IS NULL THEN i.claude_coverage END,
                CASE WHEN i.claude_coverage_version = p.version AND i.revoked_at IS NULL THEN i.claude_checked_at END,
                i.extension_version, i.extension_version_reported_at
            FROM installations i JOIN organizations o ON o.id = i.organization_id
            LEFT JOIN policy_groups g ON g.organization_id = o.id AND g.id = i.policy_group_id
            JOIN policy_versions p ON p.organization_id = i.organization_id AND p.version = COALESCE(g.policy_version, o.policy_version)
            WHERE i.organization_id = $1 AND (NOT $2 OR i.policy_group_id IS NOT DISTINCT FROM $3::uuid)
                AND ($4::text IS NULL OR i.extension_version = $4 OR ($4 = 'unreported' AND i.extension_version IS NULL))
            ORDER BY i.enrolled_at DESC, i.id LIMIT 100
            """, organizationId, filter.Scoped, (object?)filter.GroupId ?? DBNull.Value, (object?)filter.Version ?? DBNull.Value);
        var installations = new List<Installation>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct))
            installations.Add(new(rows.GetGuid(0), rows.GetDateTime(1), rows.GetDateTime(2),
                rows.IsDBNull(3) ? null : rows.GetInt32(3), rows.IsDBNull(4) ? null : rows.GetDateTime(4),
                rows.IsDBNull(5) ? null : rows.GetString(5), rows.IsDBNull(6) ? null : rows.GetDateTime(6),
                rows.IsDBNull(7) ? null : rows.GetGuid(7), rows.IsDBNull(8) ? null : rows.GetString(8), rows.GetInt32(9), rows.GetBoolean(10),
                rows.IsDBNull(11) ? null : rows.GetString(11), rows.IsDBNull(12) ? null : rows.GetDateTime(12), rows.GetBoolean(13),
                rows.IsDBNull(14) ? null : rows.GetString(14), rows.IsDBNull(15) ? null : rows.GetDateTime(15),
                rows.IsDBNull(16) ? null : rows.GetString(16), rows.IsDBNull(17) ? null : rows.GetDateTime(17)));
        return installations;
    }

    public async Task<IReadOnlyList<BrowserReleaseCount>> BrowserReleases(Guid organizationId, CancellationToken ct,
        BrowserHealthFilter filter = default, NpgsqlTransaction? snapshot = null)
    {
        await using var command = BrowserRead(snapshot, """
            WITH counts AS (
                SELECT extension_version, count(*) AS installations, count(*) FILTER (
                    WHERE extension_version_reported_at > now() - interval '90 seconds') AS recent_reports
                FROM installations WHERE organization_id = $1 AND revoked_at IS NULL
                    AND (NOT $2 OR policy_group_id IS NOT DISTINCT FROM $3::uuid)
                GROUP BY extension_version
            ), ranked AS (
                SELECT *, row_number() OVER (PARTITION BY extension_version IS NULL
                    ORDER BY installations DESC, extension_version) AS position FROM counts
            ), buckets AS (
                SELECT CASE WHEN position <= 8 THEN extension_version END AS version,
                    CASE WHEN extension_version IS NULL THEN 'unreported' WHEN position <= 8 THEN 'release' ELSE 'other' END AS kind,
                    sum(installations)::bigint AS installations, sum(recent_reports)::bigint AS recent_reports
                FROM ranked GROUP BY 1, 2
            )
            SELECT version, kind, installations, recent_reports FROM buckets
            ORDER BY CASE kind WHEN 'release' THEN 0 WHEN 'other' THEN 1 ELSE 2 END, installations DESC, version
            """, organizationId, filter.Scoped, (object?)filter.GroupId ?? DBNull.Value);
        await using var rows = await command.ExecuteReaderAsync(ct);
        var releases = new List<BrowserReleaseCount>();
        while (await rows.ReadAsync(ct))
            releases.Add(new(rows.GetString(1), rows.IsDBNull(0) ? null : rows.GetString(0), rows.GetInt64(2), rows.GetInt64(3)));
        return releases;
    }

    private NpgsqlCommand BrowserRead(NpgsqlTransaction? snapshot, string sql, params object[] values)
    {
        if (snapshot is null) return Command(sql, values);
        var command = new NpgsqlCommand(sql, snapshot.Connection, snapshot);
        AddParameters(command, values);
        return command;
    }

    public async Task<bool> Revoke(RequestIdentity identity, Guid installationId, CancellationToken ct)
    {
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        // Acquire the installation lock before deleting inventory so a report committed while waiting is visible.
        await using var locked = BrowserRead(transaction, """
            SELECT 1 FROM installations WHERE organization_id = $1 AND id = $2 FOR UPDATE
            """, identity.OrganizationId, installationId);
        if (await locked.ExecuteScalarAsync(ct) is null) return false;
        var result = await RevokeInstallations(identity, [installationId], transaction, ct);
        await transaction.CommitAsync(ct);
        return result.Found > 0;
    }

    private async Task<(int Found, Guid[] Changed)> RevokeInstallations(RequestIdentity identity, Guid[] installationIds,
        NpgsqlTransaction transaction, CancellationToken ct)
    {
        await using var command = BrowserRead(transaction, """
            WITH revoked AS (
                UPDATE installations SET revoked_at = now() WHERE organization_id = $1 AND id = ANY($2) AND revoked_at IS NULL
                RETURNING organization_id, id, revoked_at
            ), cleared AS (
                DELETE FROM extension_inventory_snapshots s USING revoked r WHERE s.installation_id = r.id
            ), cleared_inventory_changes AS (
                DELETE FROM extension_inventory_change_batches b USING revoked r WHERE b.installation_id = r.id
            ), cleared_composers AS (
                DELETE FROM composer_observations o USING revoked r WHERE o.installation_id = r.id
            ), audit AS (
                INSERT INTO control_audit (organization_id, occurred_at, action, installation_id, actor_access_id)
                SELECT organization_id, revoked_at, 'browser_revoked', id, $3 FROM revoked
            )
            SELECT (SELECT count(*)::integer FROM installations WHERE organization_id = $1 AND id = ANY($2)),
                ARRAY(SELECT id FROM revoked ORDER BY id)
            """, identity.OrganizationId, installationIds, (object?)identity.Access?.Id ?? DBNull.Value);
        await using var rows = await command.ExecuteReaderAsync(ct);
        await rows.ReadAsync(ct);
        return (rows.GetInt32(0), rows.GetFieldValue<Guid[]>(1));
    }

    public async Task<bool> Ingest(Guid installationId, PolicyEvent request, CancellationToken ct)
    {
        await using var command = Command("""
            WITH active AS (
                SELECT organization_id, assignment_version FROM installations WHERE id = $1 AND revoked_at IS NULL FOR SHARE
            ), eligible AS (
                SELECT p.organization_id, COALESCE(p.policy_group_id, d.rollout_group_id) AS rollout_group_id,
                    p.policy_group_id IS NOT NULL OR COALESCE(d.rollout_attributed, false)
                        OR ($8 = 0 AND active.assignment_version = 0) AS rollout_attributed
                FROM active
                JOIN policy_versions p ON p.organization_id = active.organization_id AND p.version = $4
                LEFT JOIN policy_deliveries d ON d.organization_id = active.organization_id AND d.installation_id = $1
                    AND d.assignment_version = $8 AND d.policy_version = $4
                LEFT JOIN retention_cutoffs r ON r.organization_id = active.organization_id
                CROSS JOIN LATERAL (SELECT CASE $7 WHEN 'github-classic-pat' THEN p.github_pat_mode
                    WHEN 'github-app-or-fine-grained-token' THEN p.github_token_mode
                    WHEN 'payment-card-number' THEN p.payment_card_mode
                    WHEN 'pem-private-key' THEN p.private_key_mode
                    WHEN 'organization-identifier' THEN p.identifier_protection->>'mode'
                    WHEN 'us-social-security-number' THEN p.ssn_mode
                    WHEN 'ai-file-upload' THEN CASE $6 WHEN 'chatgpt' THEN p.chatgpt_upload_mode WHEN 'gemini' THEN p.gemini_upload_mode END
                    ELSE p.mode END AS mode, $9::text IS NOT NULL AND $7 <> 'ai-file-upload' AS file_content) AS base
                CROSS JOIN LATERAL (SELECT CASE WHEN $9 IS NULL AND NOT $11 AND base.mode <> 'off'
                    THEN COALESCE(p.prompt_app_modes->>$6, base.mode) ELSE base.mode END AS mode, base.file_content) AS detector
                WHERE (CASE WHEN $11 THEN p.clipboard_mode = $5 AND d.clipboard_paste AND detector.mode <> 'off'
                    ELSE (detector.file_content AND (detector.mode <> 'off' OR $7 = 'file-inspection-unavailable') AND
                        CASE $6 WHEN 'chatgpt' THEN p.chatgpt_file_inspection AND (p.chatgpt_file_content_block = ($5 = 'block'))
                            WHEN 'gemini' THEN p.gemini_file_inspection AND (p.gemini_file_content_block = ($5 = 'block')) ELSE false END
                    OR NOT detector.file_content AND (detector.mode = CASE WHEN $5 = 'warn_override' THEN 'warn' ELSE $5 END
                    OR ($5 = 'exception_applied' AND detector.mode IN ('warn', 'block') AND $3 >= p.published_at
                        AND $3 <= now() + interval '2 minutes'
                        AND EXISTS (SELECT 1 FROM jsonb_array_elements(p.prompt_exceptions) AS entries(entry)
                            WHERE entry->>'appId' = $6 AND entry->>'ruleId' = $7 AND $3 < (entry->>'expiresAt')::timestamptz)))) END)
                  AND (r.event_cutoff IS NULL OR $3 >= r.event_cutoff)
                  AND ($6 <> 'claude' OR p.claude_prompt_enabled)
                  AND ($9 IS NOT NULL OR $11 OR NOT (p.prompt_app_modes ? $6) OR d.prompt_app_modes)
                  AND (($8 = 0 AND p.policy_group_id IS NULL AND $5 <> 'exception_applied' AND $6 <> 'claude'
                        AND $7 NOT IN ('pem-private-key', 'organization-identifier', 'us-social-security-number', 'github-app-or-fine-grained-token')
                        AND NOT detector.file_content AND NOT $11)
                    OR (d.installation_id IS NOT NULL
                        AND ($6 <> 'claude' OR d.claude_prompt)
                        AND ($7 <> 'pem-private-key' OR d.private_key)
                        AND ($7 <> 'organization-identifier' OR d.identifiers)
                        AND ($7 <> 'us-social-security-number' OR d.ssn)
                        AND ($7 <> 'github-app-or-fine-grained-token' OR d.github_token)
                        AND (NOT detector.file_content OR d.file_inspection AND ($5 <> 'block' OR d.file_content_block))
                        AND ($5 <> 'exception_applied' OR d.exception_scope)))
            ), written AS (
                INSERT INTO security_events (organization_id, installation_id, event_id, occurred_at, policy_version, decision, app_id, rule_id, upload_method,
                    rollout_group_id, rollout_attributed, clipboard_paste)
                SELECT organization_id, $1, $2, $3, $4, $5, $6, $7, $9, rollout_group_id, rollout_attributed, $11 FROM eligible
                ON CONFLICT (installation_id, event_id) DO NOTHING
                RETURNING organization_id, installation_id, event_id, app_id, rollout_group_id, rollout_attributed, received_at, decision
            ), counted AS (
                INSERT INTO security_alert_windows (organization_id, setting_revision, app_id, rollout_group_id, rollout_attributed,
                    window_start, first_received_at, threshold)
                SELECT w.organization_id, settings.revision, w.app_id, w.rollout_group_id, w.rollout_attributed,
                    date_bin(interval '15 minutes', w.received_at, timestamptz '2000-01-01 00:00:00Z'), w.received_at, settings.threshold
                FROM written w JOIN security_alert_settings settings ON settings.organization_id = w.organization_id AND settings.enabled
                WHERE w.decision = 'block' AND w.app_id IN ('chatgpt', 'claude', 'gemini')
                ON CONFLICT (organization_id, setting_revision, app_id, rollout_group_id, rollout_attributed, window_start) DO UPDATE
                SET block_count = security_alert_windows.block_count + 1,
                    first_received_at = LEAST(security_alert_windows.first_received_at, EXCLUDED.first_received_at),
                    triggered_at = COALESCE(security_alert_windows.triggered_at,
                        CASE WHEN security_alert_windows.block_count + 1 >= security_alert_windows.threshold THEN clock_timestamp() END)
                RETURNING organization_id, id, block_count, threshold
            ), linked AS (
                INSERT INTO security_alert_events (organization_id, alert_id, installation_id, event_id)
                SELECT c.organization_id, c.id, w.installation_id, w.event_id
                FROM counted c JOIN written w USING (organization_id)
            ), queued AS (
                INSERT INTO alert_webhook_deliveries (organization_id, alert_id, route_fingerprint)
                SELECT c.organization_id, c.id, route.value FROM counted c
                JOIN organizations o ON o.id = c.organization_id
                JOIN jsonb_each_text($10::jsonb) AS route ON route.key = o.slug
                WHERE c.block_count = c.threshold
            )
            SELECT EXISTS (SELECT 1 FROM eligible)
            """, installationId, request.EventId, request.Timestamp.UtcDateTime, request.PolicyVersion, request.Decision, request.AppId,
            request.RuleId, request.AssignmentVersion, (object?)request.UploadMethod ?? DBNull.Value, alertWebhooks.Routing, request.ClipboardPaste);
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
        var rollout = EventRolloutFilter.Parse(filters.RolloutGroup) ?? throw new ArgumentException("Invalid event rollout filter.");
        var assignee = TriageAssigneeFilter.Parse(filters.TriageAssignee) ?? throw new ArgumentException("Invalid triage assignee filter.");
        var status = string.IsNullOrEmpty(filters.TriageStatus) ? null : filters.TriageStatus;
        var triageJoin = status is TriageStatus.Investigating or TriageStatus.Resolved || assignee.Id.HasValue
            ? EventTriageJoin : $"LEFT {EventTriageJoin}";
        await using var command = Command($"""
            SELECT {EventFields}
            FROM {EventSources} {triageJoin}
            WHERE e.organization_id = $1 AND {EventRetained}
                AND ($2::text IS NULL OR e.decision = $2)
                AND ($3::timestamptz IS NULL OR e.occurred_at >= $3)
                AND ($4::text IS NULL OR e.app_id = $4)
                AND ($5::timestamptz IS NULL OR e.occurred_at < $5)
                AND ($6::uuid IS NULL OR e.installation_id = $6)
                AND ($7::timestamptz IS NULL OR (e.received_at, e.event_id, e.installation_id) < ($7, $8::uuid, $9::uuid))
                AND ($11::boolean IS NULL OR e.rollout_attributed = $11
                    AND (e.rollout_group_id = $12::uuid OR ($12 IS NULL AND e.rollout_group_id IS NULL)))
                AND ($13::text IS NULL OR t.status = $13 OR ($13 = 'needs_review' AND t.status IS NULL))
                AND (NOT $14 OR t.assignee_id IS NULL)
                AND ($15::uuid IS NULL OR t.assignee_id = $15)
            ORDER BY e.received_at DESC, e.event_id DESC, e.installation_id DESC LIMIT $10::integer
            """, organizationId, (object?)filters.Decision ?? DBNull.Value, (object?)filters.Since?.UtcDateTime ?? DBNull.Value,
            (object?)filters.AppId ?? DBNull.Value, (object?)filters.Until?.UtcDateTime ?? DBNull.Value,
            (object?)filters.InstallationId ?? DBNull.Value, (object?)cursor?.ReceivedAt.UtcDateTime ?? DBNull.Value,
            (object?)cursor?.EventId ?? DBNull.Value, (object?)cursor?.InstallationId ?? DBNull.Value, (object?)limit ?? DBNull.Value,
            (object?)rollout.Attributed ?? DBNull.Value, (object?)rollout.GroupId ?? DBNull.Value,
            (object?)status ?? DBNull.Value, assignee.RequireUnassigned, (object?)assignee.Id ?? DBNull.Value);
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct)) yield return ReadEvent(rows);
    }

    public async Task<bool> ObserveApp(Guid installationId, AppObservation observation, CancellationToken ct)
    {
        var presetHosts = DiscoveryCatalog.PresetHosts(observation.AppId);
        await using var command = Command("""
            WITH active AS (
                SELECT organization_id, enrolled_at, policy_group_id FROM installations
                WHERE id = $1 AND revoked_at IS NULL AND assignment_version = $5 FOR SHARE
            ), eligible AS (
                SELECT p.organization_id FROM active
                JOIN policy_versions p ON p.organization_id = active.organization_id AND p.version = $4
                LEFT JOIN retention_cutoffs r ON r.organization_id = active.organization_id
                WHERE p.discovery_enabled AND ($6 OR p.custom_apps @> $7::jsonb)
                  AND (cardinality($8::text[]) = 0 OR (p.preset_discovery_enabled AND NOT ($8 <@ ARRAY(
                    SELECT entry->>'host' FROM jsonb_array_elements(p.custom_apps) AS entry))))
                  AND $3 BETWEEN GREATEST(enrolled_at - interval '5 minutes', now() - interval '30 days')
                    AND now() + interval '5 minutes'
                  AND (r.observation_cutoff IS NULL OR $3 >= r.observation_cutoff)
                  AND ((cardinality($8::text[]) = 0 AND $5 = 0 AND p.policy_group_id IS NULL) OR EXISTS (SELECT 1 FROM policy_deliveries d
                    WHERE d.installation_id = $1 AND d.assignment_version = $5 AND d.policy_version = $4
                      AND (cardinality($8::text[]) = 0 OR d.preset_discovery)))
                  AND NOT EXISTS (SELECT 1 FROM policy_versions later
                    WHERE later.organization_id = p.organization_id AND later.version > p.version
                      AND (NOT later.discovery_enabled OR (NOT $6 AND NOT (later.custom_apps @> $7::jsonb))
                        OR (cardinality($8::text[]) > 0 AND (NOT later.preset_discovery_enabled OR $8 <@ ARRAY(
                            SELECT entry->>'host' FROM jsonb_array_elements(later.custom_apps) AS entry))))
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
            """, installationId, observation.AppId, observation.ObservedAt.UtcDateTime, observation.PolicyVersion, observation.AssignmentVersion,
            DiscoveryCatalog.IsBuiltIn(observation.AppId), JsonSerializer.Serialize(new[] { new { id = observation.AppId } }), presetHosts);
        return (bool)(await command.ExecuteScalarAsync(ct))!;
    }

    private const string ActiveCustomCatalog = """
        SELECT DISTINCT ON (entry->>'id') entry->>'id' AS app_id, entry->>'host' AS host, entry->>'name' AS name
        FROM policy_versions p CROSS JOIN LATERAL jsonb_array_elements(p.custom_apps) AS entry
        WHERE p.organization_id = $1 AND p.version IN (
            SELECT policy_version FROM organizations WHERE id = $1
            UNION SELECT policy_version FROM policy_groups WHERE organization_id = $1 AND policy_version IS NOT NULL
        )
        ORDER BY entry->>'id', p.version DESC
        """;

    public async Task<IReadOnlyList<DiscoveredApp>> DiscoveredApps(Guid organizationId, CancellationToken ct)
    {
        await using var command = Command($"""
            WITH custom AS ({ActiveCustomCatalog}), catalog AS (
                SELECT app_id, position, NULL::text AS host, NULL::text AS name
                FROM unnest($2::text[]) WITH ORDINALITY AS built_in(app_id, position)
                UNION ALL SELECT app_id, cardinality($2::text[]) + 1, host, name FROM custom
            )
            SELECT catalog.app_id, COALESCE(c.status, 'unreviewed'), count(o.installation_id), max(o.observed_at),
                catalog.host, catalog.name
            FROM catalog
            LEFT JOIN retention_cutoffs r ON r.organization_id = $1
            LEFT JOIN ai_app_classifications c ON c.organization_id = $1 AND c.app_id = catalog.app_id
            LEFT JOIN ai_app_observations o ON o.organization_id = $1 AND o.app_id = catalog.app_id
                AND o.observed_at >= GREATEST(now() - interval '30 days', r.observation_cutoff)
            GROUP BY catalog.app_id, catalog.position, catalog.host, catalog.name, c.status
            ORDER BY catalog.position, catalog.name, catalog.app_id
            """, organizationId, DiscoveryCatalog.AppIds);
        var apps = new List<DiscoveredApp>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct))
        {
            var appId = rows.GetString(0);
            apps.Add(new(appId, rows.GetString(1), rows.GetInt64(2), rows.IsDBNull(3) ? null : rows.GetDateTime(3),
                rows.IsDBNull(4) ? null : rows.GetString(4), rows.IsDBNull(5) ? DiscoveryCatalog.PresetName(appId) : rows.GetString(5)));
        }
        return apps;
    }

    public async Task<bool> ClassifyApp(RequestIdentity identity, string appId, string status, CancellationToken ct)
    {
        await using var command = Command($"""
            WITH custom AS ({ActiveCustomCatalog}), allowed AS (
                SELECT $1 AS organization_id WHERE $5 OR EXISTS (SELECT 1 FROM custom WHERE app_id = $2)
            ), changed AS (
                INSERT INTO ai_app_classifications (organization_id, app_id, status)
                SELECT organization_id, $2, $3 FROM allowed
                ON CONFLICT (organization_id, app_id) DO UPDATE SET status = EXCLUDED.status
                WHERE ai_app_classifications.status IS DISTINCT FROM EXCLUDED.status
                RETURNING organization_id, app_id, status
            ), audit AS (
                INSERT INTO control_audit (organization_id, action, app_id, classification, actor_access_id)
                SELECT organization_id, 'app_classified', app_id, status, $4 FROM changed
            )
            SELECT EXISTS (SELECT 1 FROM allowed)
            """, identity.OrganizationId, appId, status, (object?)identity.Access?.Id ?? DBNull.Value, DiscoveryCatalog.IsBuiltIn(appId));
        return (bool)(await command.ExecuteScalarAsync(ct))!;
    }

    public async Task<AuditPage> AuditHistory(Guid organizationId, AuditFilters filters, CancellationToken ct)
    {
        await using var command = Command("""
            SELECT a.id, occurred_at, action, policy_version, restored_from, installation_id, app_id, classification, retention, cleanup, group_change,
                actor.id, actor.display_name, actor.role, subject.id, subject.display_name, subject.role, a.review_change, a.enrollment_batch_change,
                a.event_triage_change, a.incident_case_change, a.security_alert_change, a.event_feed_key_change, a.fleet_change, a.template_change,
                a.composer_gate
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
                rows.IsDBNull(17) ? null : JsonSerializer.Deserialize<PolicyReviewAudit>(rows.GetString(17), JsonSerializerOptions.Web),
                rows.IsDBNull(18) ? null : JsonSerializer.Deserialize<EnrollmentBatchChange>(rows.GetString(18), JsonSerializerOptions.Web),
                rows.IsDBNull(19) ? null : JsonSerializer.Deserialize<EventTriageChange>(rows.GetString(19), JsonSerializerOptions.Web),
                rows.IsDBNull(20) ? null : JsonSerializer.Deserialize<IncidentCaseChange>(rows.GetString(20), JsonSerializerOptions.Web),
                rows.IsDBNull(21) ? null : JsonSerializer.Deserialize<SecurityAlertChange>(rows.GetString(21), JsonSerializerOptions.Web),
                rows.IsDBNull(22) ? null : JsonSerializer.Deserialize<EventFeedKeyChange>(rows.GetString(22), JsonSerializerOptions.Web),
                rows.IsDBNull(23) ? null : JsonSerializer.Deserialize<FleetChange>(rows.GetString(23), JsonSerializerOptions.Web),
                rows.IsDBNull(24) ? null : JsonSerializer.Deserialize<PolicyTemplateAudit>(rows.GetString(24), JsonSerializerOptions.Web),
                rows.IsDBNull(25) ? null : JsonSerializer.Deserialize<PolicyComposerGate>(rows.GetString(25), JsonSerializerOptions.Web)));
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

    private static Policy ReadPolicy(NpgsqlDataReader rows, bool includeDeployment = true) => new(rows.GetInt32(0), rows.GetString(1),
        rows.GetDateTime(2), rows.IsDBNull(3) ? null : rows.GetInt32(3), rows.GetString(4), rows.GetBoolean(5),
        new(rows.GetFieldValue<string[]>(6), rows.GetFieldValue<string[]>(7)), rows.GetString(8), new(rows.GetString(9), rows.GetString(10)),
        new(rows.GetFieldValue<string[]>(11), rows.GetFieldValue<string[]>(12)), rows.GetBoolean(13),
        new(rows.GetFieldValue<string[]>(14), rows.GetFieldValue<string[]>(15)),
        JsonSerializer.Deserialize<CustomApp[]>(rows.GetString(16), JsonSerializerOptions.Web),
        JsonSerializer.Deserialize<PromptException[]>(rows.GetString(17), JsonSerializerOptions.Web), ClaudePromptEnabled: rows.GetBoolean(18),
        PrivateKeyMode: rows.GetString(19), FileInspection: new(rows.GetBoolean(20), rows.GetBoolean(21)),
        BlockedAiAppHosts: rows.GetFieldValue<string[]>(22),
        FileContentModes: new(FileContentMode(rows.GetBoolean(20), rows.GetBoolean(23)), FileContentMode(rows.GetBoolean(21), rows.GetBoolean(24))),
        IdentifierProtection: JsonSerializer.Deserialize<IdentifierProtection>(rows.GetString(25), JsonSerializerOptions.Web),
        ExtensionDeployment: includeDeployment ? JsonSerializer.Deserialize<ExtensionDeployment>(rows.GetString(26), JsonSerializerOptions.Web) : null,
        PresetDiscoveryEnabled: rows.GetBoolean(rows.GetOrdinal("preset_discovery_enabled")), SsnMode: rows.GetString(rows.GetOrdinal("ssn_mode")),
        BrowserHardening: includeDeployment ? JsonSerializer.Deserialize<BrowserHardening>(rows.GetString(rows.GetOrdinal("browser_hardening")), JsonSerializerOptions.Web) : null,
        ClipboardMode: rows.GetString(rows.GetOrdinal("clipboard_mode")), GithubTokenMode: rows.GetString(rows.GetOrdinal("github_token_mode")),
        PromptAppModes: JsonSerializer.Deserialize<PromptAppModes>(rows.GetString(rows.GetOrdinal("prompt_app_modes")), JsonSerializerOptions.Web));

    private static string FileContentMode(bool enabled, bool block) => block ? "block" : enabled ? "monitor" : "off";
}
