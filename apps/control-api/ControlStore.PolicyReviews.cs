using System.Text.Json;
using Npgsql;

namespace Control;

internal sealed partial class ControlStore
{
    public async Task<bool> PolicyReviewRequired(Guid organizationId, CancellationToken ct)
    {
        await using var command = Command("SELECT require_policy_review FROM organizations WHERE id = $1", organizationId);
        return await command.ExecuteScalarAsync(ct) is true;
    }

    public async Task<PolicyChangeResult> ChangePolicy(RequestIdentity identity, PublishPolicy? request, int? restoredFrom,
        bool expectReview, CancellationToken ct, Guid? groupId = null, Guid? sourceGroupId = null, int? expectedSourceVersion = null,
        CustomApp[]? customApps = null, PromptException[]? promptExceptions = null,
        (Guid Id, int Revision, int ExpectedVersion)? template = null, int? expectedBaselineVersion = null)
    {
        var org = identity.OrganizationId;
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        var required = await LockPolicySettings(transaction, org, ct);
        if (expectReview && !required) return new(Error: "review_mode_changed");
        if (required && (identity.Access is not { Role: AccessRoles.Administrator } author ||
            !await ActiveAdministrators(transaction, org, [author.Id], ct))) return new(Error: "named_administrator_required");

        var target = await ReadPolicyScope(transaction, org, groupId, ct);
        if (target is null || ((template?.ExpectedVersion ?? request?.ExpectedVersion ?? expectedBaselineVersion) is { } expected && target.Version != expected))
            return new();
        var before = await ReadPolicySnapshot(transaction, org, target.Version, ct);
        if (before is null) return new();
        if (groupId.HasValue && !target.Published) before = before with { PromptExceptions = [] };

        Policy? candidate = before;
        string? sourceGroupName = null;
        PolicyTemplateOrigin? templateOrigin = null;
        if (template is { } sourceTemplate)
        {
            templateOrigin = await ReadTemplateOrigin(transaction, org, sourceTemplate.Id, sourceTemplate.Revision, ct);
            if (templateOrigin is null) return new(Error: "template_unavailable");
            candidate = await ReadPolicySnapshot(transaction, org, templateOrigin.SourceVersion, ct);
        }
        else if (sourceGroupId is not null)
        {
            var source = await ReadPolicyScope(transaction, org, sourceGroupId, ct);
            if (source is not { Published: true } || source.Version != expectedSourceVersion) return new();
            sourceGroupName = source.Name;
            candidate = await ReadPolicySnapshot(transaction, org, source.Version, ct);
        }
        else if (restoredFrom is { } restore)
        {
            candidate = await ReadPolicySnapshot(transaction, org, restore, ct, exactScope: true, groupId);
        }
        else if (request is not null)
        {
            if (PromptException.IntroducesExpired(promptExceptions, before.PromptExceptions)) return new(Error: "exception_expired");
            candidate = ApplyPolicySettings(before, request, customApps, promptExceptions);
        }
        if (candidate is null) return new();
        if (request is null) candidate = candidate with { PromptExceptions = before.PromptExceptions };
        if (candidate.DomainRules.Allow.Length + candidate.DomainRules.Block.Length + candidate.PathRules.Allow.Length +
            candidate.PathRules.Block.Length + (candidate.BlockedAiAppHosts?.Length ?? 0) > 50) return new(Error: "navigation_rule_limit");
        if (!AiAppAccess.InCatalog(candidate.BlockedAiAppHosts, candidate.CustomApps)) return new(Error: "ai_app_access_unknown_host");

        if (!required)
        {
            var auditGroup = sourceGroupId is not null ? new PolicyGroupChange(sourceGroupId, sourceGroupName, null, expectedSourceVersion) :
                groupId is not null ? new PolicyGroupChange(groupId, target.Name, null, null) : null;
            var published = await WritePolicy(transaction, identity, candidate, groupId, restoredFrom, auditGroup, ct);
            if (templateOrigin is not null) await AuditTemplate(transaction, identity, new("applied", templateOrigin, groupId, published.Version), ct);
            await transaction.CommitAsync(ct);
            return new(published);
        }

        var operation = sourceGroupId is not null ? "promote" : restoredFrom is not null ? "restore" : "publish";
        var sourceVersion = restoredFrom ?? expectedSourceVersion;
        if (templateOrigin is not null && await FindPendingTemplateReview(transaction, identity, groupId, before.Version, templateOrigin, ct) is { } pending)
            return new(ReviewId: pending);
        var id = Guid.NewGuid();
        await using var insert = new NpgsqlCommand("""
            INSERT INTO policy_reviews (id, organization_id, requested_by, operation, group_id, source_group_id, source_version, base_version, snapshots)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
            """, connection, transaction);
        AddParameters(insert, id, org, identity.Access!.Id, operation, (object?)groupId ?? DBNull.Value,
            (object?)sourceGroupId ?? DBNull.Value, (object?)sourceVersion ?? DBNull.Value, before.Version,
            JsonSerializer.Serialize(new PolicySnapshots(before, candidate, templateOrigin), JsonSerializerOptions.Web));
        await insert.ExecuteNonQueryAsync(ct);
        await AuditPolicyReview(transaction, identity, "policy_review_requested",
            new(id, operation, "pending", groupId, before.Version, sourceVersion), ct);
        await transaction.CommitAsync(ct);
        return new(ReviewId: id);
    }

    public async Task<PolicyReviewQueue> PolicyReviews(Guid organizationId, CancellationToken ct)
    {
        var required = await PolicyReviewRequired(organizationId, ct);
        await using var command = Command($"""
            WITH entries AS ({ReviewSelection} WHERE r.organization_id = $1),
            recent AS (SELECT * FROM entries WHERE status <> 'pending' ORDER BY requested_at DESC, id DESC LIMIT 100)
            SELECT * FROM entries WHERE status = 'pending'
            UNION ALL SELECT * FROM recent ORDER BY requested_at DESC, id DESC
            """, organizationId);
        var entries = new List<PolicyReview>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct)) entries.Add(ReadReview(rows));
        return new(required, entries);
    }

    public async Task SetPolicyReviewRequired(RequestIdentity identity, bool required, CancellationToken ct)
    {
        var org = identity.OrganizationId;
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        if (await LockPolicySettings(transaction, org, ct) == required) return;

        await using var update = new NpgsqlCommand("UPDATE organizations SET require_policy_review = $2 WHERE id = $1", connection, transaction);
        AddParameters(update, org, required);
        await update.ExecuteNonQueryAsync(ct);
        var cancelled = 0;
        if (!required)
        {
            await using var cancel = new NpgsqlCommand("""
                UPDATE policy_reviews SET status = 'cancelled', decided_at = now()
                WHERE organization_id = $1 AND status = 'pending' AND expires_at > clock_timestamp()
                """, connection, transaction);
            AddParameters(cancel, org);
            cancelled = await cancel.ExecuteNonQueryAsync(ct);
        }
        await AuditPolicyReview(transaction, identity, "policy_review_setting_changed", new(Required: required, Cancelled: cancelled), ct);
        await transaction.CommitAsync(ct);
    }

    public async Task<PolicyChangeResult> DecidePolicyReview(RequestIdentity identity, Guid id, bool approve, CancellationToken ct)
    {
        if (identity.Access is not { Role: AccessRoles.Administrator } reviewer) return new(Error: "named_administrator_required");
        var org = identity.OrganizationId;
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        if (!await LockPolicySettings(transaction, org, ct)) return new(Error: "review_mode_changed");

        PolicyReview? review;
        await using (var command = new NpgsqlCommand(ReviewSelection + " WHERE r.organization_id = $1 AND r.id = $2", connection, transaction))
        {
            AddParameters(command, org, id);
            await using var rows = await command.ExecuteReaderAsync(ct);
            review = await rows.ReadAsync(ct) ? ReadReview(rows) : null;
        }
        if (review is null) return new(Error: "review_unavailable");
        if (review.Status != "pending") return new(Error: "review_closed");
        var isRequester = reviewer.Id == review.Requester.Id;
        if (approve && (isRequester || StringComparer.OrdinalIgnoreCase.Equals(reviewer.Name, review.Requester.Name)))
            return new(Error: "self_approval");
        if (!await ActiveAdministrators(transaction, org, [reviewer.Id], ct)) return new(Error: "named_administrator_required");

        Policy? published = null;
        var status = isRequester ? "withdrawn" : "rejected";
        if (approve)
        {
            var current = await ReadPolicyScope(transaction, org, review.GroupId, ct);
            var source = review.SourceGroupId is { } sourceId ? await ReadPolicyScope(transaction, org, sourceId, ct) : null;
            if (current?.Version != review.Snapshots.Before.Version ||
                (review.Operation == "promote" && (source is not { Published: true } || source.Version != review.SourceVersion)) ||
                (review.Snapshots.Template is { } pinned && await ReadTemplateOrigin(transaction, org, pinned.TemplateId, pinned.Revision, ct) is null) ||
                PromptException.IntroducesExpired(review.Snapshots.Candidate.PromptExceptions, review.Snapshots.Before.PromptExceptions) ||
                !await ActiveAdministrators(transaction, org, [review.Requester.Id], ct))
            {
                status = "stale";
            }
            else
            {
                var group = review.SourceGroupId is not null ?
                    new PolicyGroupChange(review.SourceGroupId, review.SourceGroupName, null, review.SourceVersion) :
                    review.GroupId is not null ? new PolicyGroupChange(review.GroupId, review.GroupName, null, null) : null;
                var restoredFrom = review.Operation == "restore" ? review.SourceVersion : null;
                published = await WritePolicy(transaction, identity, review.Snapshots.Candidate, review.GroupId, restoredFrom, group, ct);
                if (review.Snapshots.Template is { } templateSource)
                    await AuditTemplate(transaction, identity, new("applied", templateSource, review.GroupId, published.Version), ct);
                status = "approved";
            }
        }

        await using var update = new NpgsqlCommand("""
            UPDATE policy_reviews SET status = $3, decided_by = $4, decided_at = now(), published_version = $5
            WHERE organization_id = $1 AND id = $2 AND status = 'pending' AND expires_at > clock_timestamp()
            """, connection, transaction);
        AddParameters(update, org, id, status, reviewer.Id, (object?)published?.Version ?? DBNull.Value);
        if (await update.ExecuteNonQueryAsync(ct) != 1) return new(Error: "review_closed");
        await AuditPolicyReview(transaction, identity, "policy_review_decided",
            new(id, review.Operation, status, review.GroupId, review.Snapshots.Before.Version, review.SourceVersion, published?.Version), ct);
        await transaction.CommitAsync(ct);
        return status == "stale" ? new(Error: "review_stale") : new(published);
    }

    // All changes to the requirement, the review queue, and policy versions serialize per organization.
    private static async Task<bool> LockPolicySettings(NpgsqlTransaction transaction, Guid org, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("SELECT require_policy_review FROM organizations WHERE id = $1 FOR NO KEY UPDATE",
            transaction.Connection, transaction);
        AddParameters(command, org);
        return (bool)(await command.ExecuteScalarAsync(ct))!;
    }

    private async Task<bool> ActiveAdministrators(NpgsqlTransaction transaction, Guid org, Guid[] ids, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            SELECT id FROM control_access WHERE organization_id = $1 AND id = ANY($2) AND role = 'administrator'
                AND revoked_at IS NULL AND (expires_at > clock_timestamp() OR (oidc_issuer = $3::text AND
                    organization_id = (SELECT id FROM organizations WHERE slug = $4::text)))
            ORDER BY id FOR SHARE
            """, transaction.Connection, transaction);
        AddParameters(command, org, ids, (object?)sso?.Issuer ?? DBNull.Value, (object?)sso?.OrganizationSlug ?? DBNull.Value);
        var count = 0;
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct)) count++;
        return count == ids.Length;
    }

    private static async Task<PolicyScope?> ReadPolicyScope(NpgsqlTransaction transaction, Guid org, Guid? groupId, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            SELECT COALESCE(g.policy_version, o.policy_version), g.name, g.policy_version IS NOT NULL
            FROM organizations o LEFT JOIN policy_groups g ON g.organization_id = o.id AND g.id = $2::uuid
            WHERE o.id = $1 AND ($2 IS NULL OR g.id IS NOT NULL)
            """, transaction.Connection, transaction);
        AddParameters(command, org, (object?)groupId ?? DBNull.Value);
        await using var rows = await command.ExecuteReaderAsync(ct);
        return await rows.ReadAsync(ct) ? new(rows.GetInt32(0), rows.IsDBNull(1) ? null : rows.GetString(1), rows.GetBoolean(2)) : null;
    }

    private static async Task<Policy?> ReadPolicySnapshot(NpgsqlTransaction transaction, Guid org, int version, CancellationToken ct,
        bool exactScope = false, Guid? groupId = null)
    {
        await using var command = new NpgsqlCommand("""
            SELECT p.version, p.mode, p.published_at, a.restored_from, p.github_pat_mode, p.discovery_enabled,
                p.allowed_domains, p.blocked_domains, p.payment_card_mode, p.chatgpt_upload_mode, p.gemini_upload_mode,
                p.allowed_paths, p.blocked_paths, p.extension_inventory_enabled, p.chatgpt_upload_types, p.gemini_upload_types,
                p.custom_apps, p.prompt_exceptions, p.claude_prompt_enabled, p.private_key_mode, p.chatgpt_file_inspection, p.gemini_file_inspection,
                p.blocked_ai_app_hosts, p.chatgpt_file_content_block, p.gemini_file_content_block, p.identifier_protection, p.extension_deployment,
                p.preset_discovery_enabled, p.ssn_mode, p.browser_hardening, p.clipboard_mode, p.github_token_mode
            FROM policy_versions p LEFT JOIN policy_audit a USING (organization_id, version)
            WHERE p.organization_id = $1 AND p.version = $2 AND (NOT $3 OR p.policy_group_id IS NOT DISTINCT FROM $4::uuid)
            """, transaction.Connection, transaction);
        AddParameters(command, org, version, exactScope, (object?)groupId ?? DBNull.Value);
        await using var rows = await command.ExecuteReaderAsync(ct);
        return await rows.ReadAsync(ct) ? ReadPolicy(rows) : null;
    }

    private static Policy ApplyPolicySettings(Policy current, PublishPolicy request, CustomApp[]? customApps,
        PromptException[]? promptExceptions) => current with
    {
        Mode = request.Mode ?? current.Mode,
        GithubPatMode = request.GithubPatMode ?? current.GithubPatMode,
        DiscoveryEnabled = request.DiscoveryEnabled ?? current.DiscoveryEnabled,
        PresetDiscoveryEnabled = request.PresetDiscoveryEnabled ?? current.PresetDiscoveryEnabled,
        CustomApps = customApps ?? current.CustomApps,
        PromptExceptions = promptExceptions ?? current.PromptExceptions,
        DomainRules = request.DomainRules ?? current.DomainRules,
        PaymentCardMode = request.PaymentCardMode ?? current.PaymentCardMode,
        UploadModes = new(request.UploadModes?.Chatgpt ?? current.UploadModes.Chatgpt, request.UploadModes?.Gemini ?? current.UploadModes.Gemini),
        UploadTypes = new(request.UploadTypes?.Chatgpt ?? current.UploadTypes?.Chatgpt, request.UploadTypes?.Gemini ?? current.UploadTypes?.Gemini),
        PathRules = request.PathRules ?? current.PathRules,
        ExtensionInventoryEnabled = request.ExtensionInventoryEnabled ?? current.ExtensionInventoryEnabled,
        ClaudePromptEnabled = request.ClaudePromptEnabled ?? current.ClaudePromptEnabled,
        PrivateKeyMode = request.PrivateKeyMode ?? current.PrivateKeyMode,
        SsnMode = request.SsnMode ?? current.SsnMode,
        IdentifierProtection = request.IdentifierProtection ?? current.IdentifierProtection,
        ExtensionDeployment = request.ExtensionDeployment ?? current.ExtensionDeployment,
        BrowserHardening = request.BrowserHardening ?? current.BrowserHardening,
        ClipboardMode = request.ClipboardMode ?? current.ClipboardMode,
        GithubTokenMode = request.GithubTokenMode ?? current.GithubTokenMode,
        BlockedAiAppHosts = request.BlockedAiAppHosts ?? current.BlockedAiAppHosts,
        FileContentModes = new(
            ResolveFileContentMode(request.FileContentModes?.Chatgpt, request.FileInspection?.Chatgpt, current.EffectiveFileContentModes().Chatgpt!),
            ResolveFileContentMode(request.FileContentModes?.Gemini, request.FileInspection?.Gemini, current.EffectiveFileContentModes().Gemini!))
    };

    private static string ResolveFileContentMode(string? requested, bool? legacy, string current) => requested ?? (legacy switch
    {
        false => "off",
        true when current == "off" => "monitor",
        _ => current
    });

    private static async Task<Policy> WritePolicy(NpgsqlTransaction transaction, RequestIdentity identity, Policy policy,
        Guid? targetGroupId, int? restoredFrom, PolicyGroupChange? groupAudit, CancellationToken ct)
    {
        var content = policy.EffectiveFileContentModes();
        var inspectChatgpt = content.Chatgpt != "off";
        var inspectGemini = content.Gemini != "off";
        await using var command = new NpgsqlCommand("""
            WITH next_version AS (
                UPDATE organizations SET policy_sequence = policy_sequence + 1,
                    policy_version = CASE WHEN $2::uuid IS NULL THEN policy_sequence + 1 ELSE policy_version END
                WHERE id = $1 RETURNING id, policy_sequence
            ), published AS (
                INSERT INTO policy_versions (organization_id, version, policy_group_id, mode, github_pat_mode, discovery_enabled,
                    allowed_domains, blocked_domains, payment_card_mode, chatgpt_upload_mode, gemini_upload_mode, allowed_paths, blocked_paths,
                    extension_inventory_enabled, chatgpt_upload_types, gemini_upload_types, custom_apps, prompt_exceptions, claude_prompt_enabled,
                    private_key_mode, chatgpt_file_inspection, gemini_file_inspection, extension_deployment, blocked_ai_app_hosts,
                    chatgpt_file_content_block, gemini_file_content_block, identifier_protection, preset_discovery_enabled, ssn_mode,
                    browser_hardening, clipboard_mode, github_token_mode)
                SELECT id, policy_sequence, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $16, $17, $18, $19::jsonb, $20::jsonb,
                    $21, $22, $23, $24, $25::jsonb, $26, $27, $28, $29::jsonb, $30, $31, $32::jsonb, $33, $34
                FROM next_version
                RETURNING organization_id, version, published_at
            ), group_pointer AS (
                UPDATE policy_groups g SET policy_version = p.version FROM published p WHERE g.organization_id = p.organization_id AND g.id = $2
            ), history AS (
                INSERT INTO policy_audit (organization_id, version, restored_from)
                SELECT organization_id, version, $13 FROM published
            ), audit AS (
                INSERT INTO control_audit (organization_id, occurred_at, action, policy_version, restored_from, group_change, actor_access_id)
                SELECT organization_id, published_at, CASE WHEN $13::integer IS NULL THEN 'policy_published' ELSE 'policy_restored' END,
                    version, $13, $14::jsonb, $15 FROM published
            )
            SELECT version, published_at FROM published
            """, transaction.Connection, transaction);
        AddParameters(command, identity.OrganizationId, (object?)targetGroupId ?? DBNull.Value, policy.Mode, policy.GithubPatMode,
            policy.DiscoveryEnabled, policy.DomainRules.Allow, policy.DomainRules.Block, policy.PaymentCardMode, policy.UploadModes.Chatgpt!,
            policy.UploadModes.Gemini!, policy.PathRules.Allow, policy.PathRules.Block, (object?)restoredFrom ?? DBNull.Value,
            groupAudit is null ? DBNull.Value : JsonSerializer.Serialize(groupAudit, JsonSerializerOptions.Web),
            (object?)identity.Access?.Id ?? DBNull.Value, policy.ExtensionInventoryEnabled,
            policy.UploadTypes?.Chatgpt ?? Array.Empty<string>(), policy.UploadTypes?.Gemini ?? Array.Empty<string>(),
            JsonSerializer.Serialize(policy.CustomApps ?? [], JsonSerializerOptions.Web),
            JsonSerializer.Serialize(policy.PromptExceptions ?? [], JsonSerializerOptions.Web), policy.ClaudePromptEnabled, policy.PrivateKeyMode ?? "off",
            inspectChatgpt, inspectGemini,
            JsonSerializer.Serialize(policy.ExtensionDeployment ?? ExtensionDeployment.Empty, JsonSerializerOptions.Web), policy.BlockedAiAppHosts ?? [],
            content.Chatgpt == "block", content.Gemini == "block",
            JsonSerializer.Serialize(policy.IdentifierProtection ?? IdentifierProtection.Disabled, JsonSerializerOptions.Web),
            policy.PresetDiscoveryEnabled ?? false, policy.SsnMode ?? "off",
            JsonSerializer.Serialize(policy.BrowserHardening ?? BrowserHardening.Empty, JsonSerializerOptions.Web), policy.ClipboardMode ?? "off",
            policy.GithubTokenMode ?? "off");
        await using var rows = await command.ExecuteReaderAsync(ct);
        await rows.ReadAsync(ct);
        return policy with { Version = rows.GetInt32(0), PublishedAt = rows.GetDateTime(1), RestoredFrom = restoredFrom,
            UploadTypes = new(policy.UploadTypes?.Chatgpt ?? [], policy.UploadTypes?.Gemini ?? []), CustomApps = policy.CustomApps ?? [],
            PromptExceptions = policy.PromptExceptions ?? [], FileInspection = new(inspectChatgpt, inspectGemini), FileContentModes = content,
            IdentifierProtection = policy.IdentifierProtection ?? IdentifierProtection.Disabled, PresetDiscoveryEnabled = policy.PresetDiscoveryEnabled ?? false,
            SsnMode = policy.SsnMode ?? "off",
            BrowserHardening = policy.BrowserHardening ?? BrowserHardening.Empty,
            ClipboardMode = policy.ClipboardMode ?? "off",
            GithubTokenMode = policy.GithubTokenMode ?? "off",
            ExtensionDeployment = policy.ExtensionDeployment ?? ExtensionDeployment.Empty, BlockedAiAppHosts = policy.BlockedAiAppHosts ?? [] };
    }

    private static async Task AuditPolicyReview(NpgsqlTransaction transaction, RequestIdentity identity, string action,
        PolicyReviewAudit details, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            INSERT INTO control_audit (organization_id, action, actor_access_id, review_change) VALUES ($1, $2, $3, $4::jsonb)
            """, transaction.Connection, transaction);
        AddParameters(command, identity.OrganizationId, action, (object?)identity.Access?.Id ?? DBNull.Value,
            JsonSerializer.Serialize(details, JsonSerializerOptions.Web));
        await command.ExecuteNonQueryAsync(ct);
    }

    private const string ReviewSelection = """
        SELECT r.id, CASE WHEN r.status = 'pending' AND r.expires_at <= clock_timestamp() THEN 'expired' ELSE r.status END AS status,
            r.operation, r.group_id, g.name AS group_name, r.source_group_id, s.name AS source_name,
            r.source_version, r.requested_at, r.expires_at, r.decided_at, r.published_version,
            author.id AS author_id, author.display_name AS author_name, author.role AS author_role,
            reviewer.id AS reviewer_id, reviewer.display_name AS reviewer_name, reviewer.role AS reviewer_role, r.snapshots
        FROM policy_reviews r JOIN control_access author ON author.organization_id = r.organization_id AND author.id = r.requested_by
        LEFT JOIN control_access reviewer ON reviewer.organization_id = r.organization_id AND reviewer.id = r.decided_by
        LEFT JOIN policy_groups g ON g.organization_id = r.organization_id AND g.id = r.group_id
        LEFT JOIN policy_groups s ON s.organization_id = r.organization_id AND s.id = r.source_group_id
        """;

    private static PolicyReview ReadReview(NpgsqlDataReader rows) => new(rows.GetGuid(0), rows.GetString(1), rows.GetString(2),
        rows.IsDBNull(3) ? null : rows.GetGuid(3), rows.IsDBNull(4) ? null : rows.GetString(4),
        rows.IsDBNull(5) ? null : rows.GetGuid(5), rows.IsDBNull(6) ? null : rows.GetString(6),
        rows.IsDBNull(7) ? null : rows.GetInt32(7), rows.GetDateTime(8), rows.GetDateTime(9),
        rows.IsDBNull(10) ? null : rows.GetDateTime(10), rows.IsDBNull(11) ? null : rows.GetInt32(11),
        ReadAccessIdentity(rows, 12)!, ReadAccessIdentity(rows, 15),
        JsonSerializer.Deserialize<PolicySnapshots>(rows.GetString(18), JsonSerializerOptions.Web)!);
}
