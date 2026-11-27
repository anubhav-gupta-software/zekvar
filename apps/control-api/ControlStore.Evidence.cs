using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;

namespace Control;

internal sealed partial class ControlStore
{
    // Records one export before content is sent. FinishExport later stores the delivered count and whether it completed.
    public async Task<Guid> BeginExport(RequestIdentity identity, string resource, object scope, CancellationToken ct)
    {
        await using var command = Command("""
            INSERT INTO control_access_log (organization_id, action, resource, actor_access_id, scope, completed)
            VALUES ($1, 'data_exported', $2, $3, $4::jsonb, false) RETURNING id
            """, identity.OrganizationId, resource, (object?)identity.Access?.Id ?? DBNull.Value, AccessScope(scope));
        return (Guid)(await command.ExecuteScalarAsync(ct))!;
    }

    public async Task FinishExport(Guid organizationId, Guid id, long records, bool completed, CancellationToken ct)
    {
        await using var command = Command("""
            UPDATE control_access_log SET records = $3, completed = $4, last_at = statement_timestamp()
            WHERE organization_id = $1 AND id = $2
            """, organizationId, id, records, completed);
        await command.ExecuteNonQueryAsync(ct);
    }

    public async Task RecordExport(RequestIdentity identity, string resource, object scope, long records, CancellationToken ct)
    {
        await using var command = Command("""
            INSERT INTO control_access_log (organization_id, action, resource, actor_access_id, scope, records)
            VALUES ($1, 'data_exported', $2, $3, $4::jsonb, $5)
            """, identity.OrganizationId, resource, (object?)identity.Access?.Id ?? DBNull.Value, AccessScope(scope), records);
        await command.ExecuteNonQueryAsync(ct);
    }

    // Views are summarized per actor, resource, and UTC hour so dashboards that refresh do not flood the audit log.
    public Task RecordView(RequestIdentity identity, string resource, object scope, long records, CancellationToken ct) =>
        RecordRollup(identity.OrganizationId, "data_viewed", resource, identity.Access?.Id, null,
            $"view|{resource}|{identity.Access?.Id.ToString("D") ?? "owner"}|", scope, records, ct);

    public Task RecordFeedRead(Guid organizationId, Guid keyId, long records, CancellationToken ct) =>
        RecordRollup(organizationId, "event_feed_read", "event_feed", null, keyId, $"feed|{keyId:D}|", new { }, records, ct);

    private async Task RecordRollup(Guid organizationId, string action, string resource, Guid? actor, Guid? keyId, string prefix,
        object scope, long records, CancellationToken ct)
    {
        await using var command = Command("""
            WITH hour AS (SELECT to_char(date_trunc('hour', statement_timestamp() AT TIME ZONE 'UTC'), 'YYYY-MM-DD"T"HH24":00:00Z"') AS start)
            INSERT INTO control_access_log (organization_id, action, resource, actor_access_id, event_feed_key_id, scope, records, rollup_key)
            SELECT $1, $2, $3, $4, $5, $6::jsonb || jsonb_build_object('hour', hour.start), $7, $8 || hour.start FROM hour
            ON CONFLICT (organization_id, rollup_key) WHERE rollup_key IS NOT NULL DO UPDATE
            SET requests = control_access_log.requests + 1, records = control_access_log.records + EXCLUDED.records,
                last_at = GREATEST(control_access_log.last_at, EXCLUDED.last_at)
            """, organizationId, action, resource, (object?)actor ?? DBNull.Value, (object?)keyId ?? DBNull.Value, AccessScope(scope),
            records, prefix);
        await command.ExecuteNonQueryAsync(ct);
    }

    private static string AccessScope(object scope) => JsonSerializer.Serialize(scope, JsonSerializerOptions.Web);

    public async Task TouchCredential(RequestIdentity identity, CancellationToken ct)
    {
        await using var command = Command(identity.Access is null
            ? """
                UPDATE admin_memberships SET last_used_at = statement_timestamp()
                WHERE organization_id = $1 AND (last_used_at IS NULL OR last_used_at < statement_timestamp() - interval '1 minute')
                """
            : """
                UPDATE control_access SET last_used_at = statement_timestamp()
                WHERE organization_id = $1 AND id = $2 AND (last_used_at IS NULL OR last_used_at < statement_timestamp() - interval '1 minute')
                """, identity.OrganizationId);
        if (identity.Access is { } access) command.Parameters.Add(new NpgsqlParameter { Value = access.Id });
        await command.ExecuteNonQueryAsync(ct);
    }

    public async Task<AccessReviewReport> AccessReview(Guid organizationId, int staleDays, CancellationToken ct)
    {
        await using var command = Command("""
            WITH now AS (SELECT statement_timestamp() AS at),
            credentials AS (
                SELECT 'owner_token' AS kind, NULL::uuid AS id, 'Organization owner token' AS name, 'owner' AS role, NULL::text AS issuer,
                    NULL::text AS subject, NULL::timestamptz AS issued_at, NULL::timestamptz AS expires_at, m.last_used_at,
                    'active' AS status, 'deployment_configuration' AS created_by
                FROM admin_memberships m WHERE m.organization_id = $1
                UNION ALL
                SELECT CASE WHEN c.oidc_subject IS NULL THEN 'control_token' ELSE 'sso_identity' END, c.id, c.display_name, c.role,
                    c.oidc_issuer, c.oidc_subject, c.issued_at, c.expires_at, c.last_used_at,
                    CASE WHEN c.revoked_at IS NOT NULL THEN 'revoked' WHEN c.expires_at <= now.at THEN 'expired' ELSE 'active' END,
                    CASE WHEN EXISTS (SELECT 1 FROM control_audit a WHERE a.organization_id = c.organization_id
                        AND a.action = 'access_issued' AND a.subject_access_id = c.id) OR c.oidc_subject IS NOT NULL
                        THEN 'organization_owner' ELSE 'operator_recovery' END
                FROM control_access c, now WHERE c.organization_id = $1
                    AND (c.revoked_at IS NULL OR c.revoked_at > now.at - interval '90 days')
                UNION ALL
                SELECT 'event_feed_key', k.id, k.display_name, 'event_feed', NULL, NULL, k.issued_at, k.expires_at, k.last_used_at,
                    CASE WHEN k.revoked_at IS NOT NULL THEN 'revoked' WHEN k.expires_at <= now.at THEN 'expired' ELSE 'active' END,
                    'organization_owner'
                FROM event_feed_keys k, now WHERE k.organization_id = $1
                    AND (k.revoked_at IS NULL OR k.revoked_at > now.at - interval '90 days')
            )
            SELECT kind, id, name, role, issuer, subject, issued_at, expires_at, last_used_at, status, created_by,
                status = 'active' AND COALESCE(last_used_at, issued_at, '-infinity') < now.at - $2 * interval '24 hours' AS stale, now.at
            FROM credentials, now
            ORDER BY status <> 'active', CASE kind WHEN 'owner_token' THEN 0 ELSE 1 END, issued_at DESC NULLS FIRST, id
            """, organizationId, staleDays);
        var entries = new List<AccessReviewCredential>();
        DateTime generatedAt = DateTime.UtcNow;
        await using (var rows = await command.ExecuteReaderAsync(ct))
        {
            while (await rows.ReadAsync(ct))
            {
                generatedAt = rows.GetDateTime(12);
                entries.Add(new(rows.GetString(0), rows.IsDBNull(1) ? null : rows.GetGuid(1), rows.GetString(2), rows.GetString(3),
                    rows.IsDBNull(4) ? null : rows.GetString(4), rows.IsDBNull(5) ? null : rows.GetString(5),
                    rows.IsDBNull(6) ? null : rows.GetDateTime(6), rows.IsDBNull(7) ? null : rows.GetDateTime(7),
                    rows.IsDBNull(8) ? null : rows.GetDateTime(8), rows.GetString(9), rows.GetString(10), rows.GetBoolean(11)));
            }
        }
        var attestations = await Attestations(organizationId, "access_review", 10, ct);
        return new(generatedAt, staleDays, Fingerprint(entries), entries,
            new(entries.Count(entry => entry.Status == "active"), entries.Count(entry => entry.Stale),
                entries.Count(entry => entry.Kind == "sso_identity" && entry.Status == "active"),
                entries.Count(entry => entry.Kind == "event_feed_key" && entry.Status == "active")),
            attestations);
    }

    // Binds an attestation to the exact active credentials, roles, expiries, and stale flags that were reviewed.
    private static string Fingerprint(IEnumerable<AccessReviewCredential> entries) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(
        string.Join('\n', entries.Where(entry => entry.Status == "active")
            .Select(entry => $"{entry.Kind}|{entry.Id}|{entry.Role}|{entry.Subject}|{entry.ExpiresAt:O}|{entry.Stale}").Order(StringComparer.Ordinal)))));

    public async Task<(JsonObject? Attestation, string? Error)> AttestAccessReview(RequestIdentity identity, AttestAccessReview request,
        CancellationToken ct)
    {
        var report = await AccessReview(identity.OrganizationId, request.StaleDays, ct);
        if (report.Fingerprint != request.ExpectedFingerprint) return (null, "access_review_changed");
        var details = new JsonObject
        {
            ["reviewer"] = request.Reviewer!.Trim(), ["notes"] = request.Notes?.Trim() ?? "", ["staleDays"] = request.StaleDays,
            ["fingerprint"] = report.Fingerprint, ["reportGeneratedAt"] = report.GeneratedAt,
            ["activeCredentials"] = report.Summary.Active, ["staleCredentials"] = report.Summary.Stale,
            ["staleCredentialIds"] = new JsonArray(report.Credentials.Where(entry => entry.Stale && entry.Id is not null)
                .Select(entry => (JsonNode)JsonValue.Create(entry.Id!.Value.ToString("D"))).ToArray()),
        };
        return (await Attest(identity, "access_review", request.RequestId, details, ct), null);
    }

    public async Task<JsonObject?> Attest(RequestIdentity identity, string kind, Guid id, JsonObject details, CancellationToken ct)
    {
        await using var command = Command("""
            INSERT INTO control_attestations (organization_id, id, kind, actor_access_id, details) VALUES ($1, $2, $3, $4, $5::jsonb)
            ON CONFLICT DO NOTHING RETURNING occurred_at
            """, identity.OrganizationId, id, kind, (object?)identity.Access?.Id ?? DBNull.Value, details.ToJsonString());
        if (await command.ExecuteScalarAsync(ct) is not DateTime at) return null;
        details["id"] = id;
        details["kind"] = kind;
        details["recordedAt"] = at;
        return details;
    }

    private async Task<JsonArray> Attestations(Guid organizationId, string? kind, int limit, CancellationToken ct, DateTime? since = null)
    {
        await using var command = Command("""
            SELECT COALESCE(jsonb_agg(entry ORDER BY occurred_at DESC), '[]'::jsonb)::text FROM (
                SELECT t.occurred_at, t.details || jsonb_build_object('id', t.id, 'kind', t.kind, 'recordedAt', t.occurred_at,
                    'recordedBy', COALESCE(c.display_name, 'Organization owner token')) AS entry
                FROM control_attestations t LEFT JOIN retention_cutoffs r ON r.organization_id = t.organization_id
                LEFT JOIN control_access c ON c.organization_id = t.organization_id AND c.id = t.actor_access_id
                WHERE t.organization_id = $1 AND ($2::text IS NULL OR t.kind = $2) AND ($4::timestamptz IS NULL OR t.occurred_at >= $4)
                    AND (r.audit_cutoff IS NULL OR t.occurred_at >= r.audit_cutoff)
                ORDER BY t.occurred_at DESC, t.id DESC LIMIT $3) recent
            """, organizationId, (object?)kind ?? DBNull.Value, limit, (object?)since ?? DBNull.Value);
        return JsonNode.Parse((string)(await command.ExecuteScalarAsync(ct))!)!.AsArray();
    }

    public async Task<JsonObject> EvidencePack(RequestIdentity identity, int days, CancellationToken ct)
    {
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var snapshot = await connection.BeginTransactionAsync(System.Data.IsolationLevel.RepeatableRead, ct);
        async Task<JsonNode> Query(string sql, params object[] values)
        {
            await using var command = BrowserRead(snapshot, sql, values);
            return JsonNode.Parse((string)(await command.ExecuteScalarAsync(ct))!)!;
        }
        var org = identity.OrganizationId;
        var generatedAt = (await Query("SELECT to_jsonb(statement_timestamp())::text")).GetValue<DateTimeOffset>().UtcDateTime;
        var since = generatedAt.AddDays(-days);
        var pack = new JsonObject
        {
            ["schemaVersion"] = 1,
            ["organization"] = identity.OrganizationSlug,
            ["generatedAt"] = generatedAt,
            ["period"] = new JsonObject { ["since"] = since, ["until"] = generatedAt, ["days"] = days },
            ["contentPolicy"] = "Metadata only. Excludes security event records, prompt text, file contents, detection terms, credentials, and secrets.",
            ["policyVersions"] = await Query("""
                SELECT COALESCE(jsonb_agg(jsonb_build_object('version', p.version, 'scope', COALESCE(g.name, 'Organization baseline'),
                    'groupId', p.policy_group_id, 'publishedAt', p.published_at, 'restoredFrom', h.restored_from,
                    'publishedBy', COALESCE(c.display_name, CASE WHEN a.id IS NULL THEN NULL ELSE 'Organization owner token' END),
                    'rolloutPlanId', a.rollout_change->>'planId', 'composerGate', a.composer_gate IS NOT NULL)
                    ORDER BY p.version DESC), '[]'::jsonb)::text
                FROM policy_versions p LEFT JOIN policy_groups g ON g.organization_id = p.organization_id AND g.id = p.policy_group_id
                LEFT JOIN policy_audit h ON h.organization_id = p.organization_id AND h.version = p.version
                LEFT JOIN control_audit a ON a.organization_id = p.organization_id AND a.policy_version = p.version
                    AND a.action IN ('policy_published', 'policy_restored')
                LEFT JOIN control_access c ON c.organization_id = p.organization_id AND c.id = a.actor_access_id
                WHERE p.organization_id = $1 AND p.published_at >= $2
                """, org, since),
            ["changeApprovals"] = new JsonObject
            {
                ["reviewRequired"] = await Query("SELECT to_jsonb(require_policy_review)::text FROM organizations WHERE id = $1", org),
                ["policyReviews"] = await Query("""
                    SELECT COALESCE(jsonb_agg(jsonb_build_object('id', r.id, 'operation', r.operation, 'status', CASE WHEN r.status = 'pending'
                        AND r.expires_at <= statement_timestamp() THEN 'expired' ELSE r.status END, 'scope', COALESCE(g.name, 'Organization baseline'),
                        'baseVersion', r.base_version, 'publishedVersion', r.published_version, 'requestedAt', r.requested_at,
                        'requestedBy', jsonb_build_object('id', author.id, 'name', author.display_name, 'role', author.role),
                        'decidedAt', r.decided_at, 'decidedBy', CASE WHEN reviewer.id IS NOT NULL THEN
                            jsonb_build_object('id', reviewer.id, 'name', reviewer.display_name, 'role', reviewer.role) END,
                        'independent', reviewer.id IS NULL OR reviewer.id <> author.id) ORDER BY r.requested_at DESC), '[]'::jsonb)::text
                    FROM policy_reviews r JOIN control_access author ON author.organization_id = r.organization_id AND author.id = r.requested_by
                    LEFT JOIN control_access reviewer ON reviewer.organization_id = r.organization_id AND reviewer.id = r.decided_by
                    LEFT JOIN policy_groups g ON g.organization_id = r.organization_id AND g.id = r.group_id
                    WHERE r.organization_id = $1 AND r.requested_at >= $2
                    """, org, since),
                ["rolloutPlans"] = await Query("""
                    SELECT COALESCE(jsonb_agg(jsonb_build_object('id', p.id, 'name', p.name, 'status', p.status, 'sourceVersion', p.source_version,
                        'stages', p.stage_count, 'requiresReview', p.requires_review, 'createdAt', p.created_at,
                        'createdBy', COALESCE(creator.display_name, 'Organization owner token'), 'approvedBy', approver.display_name,
                        'decidedAt', p.decided_at, 'finishedAt', p.finished_at) ORDER BY p.created_at DESC), '[]'::jsonb)::text
                    FROM rollout_plans p LEFT JOIN control_access creator ON creator.organization_id = p.organization_id AND creator.id = p.created_by
                    LEFT JOIN control_access approver ON approver.organization_id = p.organization_id AND approver.id = p.approved_by
                    WHERE p.organization_id = $1 AND p.created_at >= $2
                    """, org, since),
            },
            ["retention"] = await Query("""
                SELECT jsonb_build_object('securityEventDays', r.event_days, 'aiObservationDays', r.observation_days, 'auditDays', r.audit_days,
                    'lastChangedAt', (SELECT max(occurred_at) FROM control_audit a WHERE a.organization_id = o.id AND a.action = 'retention_changed'),
                    'lastCleanupAt', (SELECT max(occurred_at) FROM control_audit a WHERE a.organization_id = o.id AND a.action = 'retention_cleanup'))::text
                FROM organizations o LEFT JOIN organization_retention r ON r.organization_id = o.id WHERE o.id = $1
                """, org),
            ["auditSummary"] = await Query("""
                SELECT jsonb_build_object('changes', COALESCE((SELECT jsonb_object_agg(action, count) FROM (
                        SELECT action, count(*) FROM control_audit a LEFT JOIN retention_cutoffs r ON r.organization_id = a.organization_id
                        WHERE a.organization_id = $1 AND a.occurred_at >= $2 AND (r.audit_cutoff IS NULL OR a.occurred_at >= r.audit_cutoff)
                        GROUP BY action) c), '{}'::jsonb),
                    'access', COALESCE((SELECT jsonb_object_agg(action || ':' || resource, jsonb_build_object('entries', entries,
                        'requests', requests, 'records', records)) FROM (
                        SELECT action, resource, count(*) AS entries, sum(requests) AS requests, sum(records) AS records
                        FROM control_access_log l LEFT JOIN retention_cutoffs r ON r.organization_id = l.organization_id
                        WHERE l.organization_id = $1 AND l.occurred_at >= $2 AND (r.audit_cutoff IS NULL OR l.occurred_at >= r.audit_cutoff)
                        GROUP BY action, resource) l), '{}'::jsonb))::text
                """, org, since),
        };
        await snapshot.CommitAsync(ct);
        pack["accessReviews"] = await Attestations(org, "access_review", 100, ct, since);
        var drills = await Attestations(org, null, 100, ct, since);
        pack["backupAndRestoreDrills"] = new JsonArray(drills.Where(entry => entry?["kind"]?.GetValue<string>() is "backup_drill" or "restore_drill")
            .Select(entry => entry!.DeepClone()).ToArray());
        var status = await DataProtectionStatus(org, ct);
        pack["dataProtection"] = new JsonObject
        {
            ["applicationEncryption"] = status.Enabled, ["activeKeyId"] = status.ActiveKeyId, ["sealedValues"] = status.SealedValues,
            ["valuesOnActiveKey"] = status.ActiveKeyValues, ["plaintextValues"] = status.PlaintextValues,
        };
        return pack;
    }
}

internal sealed record AccessReviewCredential(string Kind, Guid? Id, string Name, string Role, string? Issuer, string? Subject,
    DateTime? IssuedAt, DateTime? ExpiresAt, DateTime? LastUsedAt, string Status, string CreatedBy, bool Stale);
internal sealed record AccessReviewSummary(int Active, int Stale, int SsoIdentities, int EventFeedKeys);
internal sealed record AccessReviewReport(DateTime GeneratedAt, int StaleDays, string Fingerprint, IReadOnlyList<AccessReviewCredential> Credentials,
    AccessReviewSummary Summary, JsonArray Attestations);
internal sealed record AttestAccessReview(Guid RequestId, string? Reviewer, string? Notes, int StaleDays, string? ExpectedFingerprint)
{
    public bool IsValid() => RequestId != Guid.Empty && Reviewer?.Trim() is { Length: >= 2 and <= 64 } reviewer && !reviewer.Any(char.IsControl) &&
        (Notes is null || Notes.Trim() is { Length: <= 1000 } notes && !notes.Any(character => char.IsControl(character) && character is not '\n')) &&
        StaleDays is >= 1 and <= 365 && ExpectedFingerprint is { Length: 64 } && ExpectedFingerprint.All(char.IsAsciiHexDigitLower);
}
internal sealed record RecordDrill(Guid RequestId, string? Kind, DateTimeOffset PerformedAt, string? Outcome, string? Operator,
    string? ArchiveSha256, int? RecoveryMinutes, string? Notes)
{
    public bool IsValid(DateTimeOffset now) => RequestId != Guid.Empty && Kind is "backup_drill" or "restore_drill" &&
        PerformedAt <= now.AddMinutes(5) && PerformedAt > now.AddYears(-2) && Outcome is "succeeded" or "failed" &&
        Operator?.Trim() is { Length: >= 2 and <= 64 } name && !name.Any(char.IsControl) &&
        (ArchiveSha256 is null || ArchiveSha256 is { Length: 64 } && ArchiveSha256.All(char.IsAsciiHexDigitLower)) &&
        RecoveryMinutes is null or >= 0 and <= 10080 &&
        (Notes is null || Notes.Trim() is { Length: <= 1000 } notes && !notes.Any(character => char.IsControl(character) && character is not '\n'));

    public JsonObject Details() => new()
    {
        ["performedAt"] = PerformedAt.UtcDateTime, ["outcome"] = Outcome, ["operator"] = Operator!.Trim(), ["archiveSha256"] = ArchiveSha256,
        ["recoveryMinutes"] = RecoveryMinutes, ["notes"] = Notes?.Trim() ?? "",
    };
}
