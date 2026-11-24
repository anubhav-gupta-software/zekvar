using System.Data;
using System.Text.Json;
using Npgsql;

namespace Control;

internal sealed partial class ControlStore
{
    private const string CurrentTemplate = """
        SELECT t.id, t.name, t.current_revision, r.source_version, t.archived_at
        FROM policy_templates t JOIN policy_template_revisions r ON r.organization_id = t.organization_id
            AND r.template_id = t.id AND r.revision = t.current_revision
        """;

    public async Task<IReadOnlyList<PolicyTemplate>> ListTemplates(Guid org, CancellationToken ct)
    {
        await using var command = Command(CurrentTemplate + " WHERE t.organization_id = $1 AND t.archived_at IS NULL ORDER BY lower(t.name), t.id", org);
        var templates = new List<PolicyTemplate>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct)) templates.Add(ReadTemplate(rows));
        return templates;
    }

    public async Task<PolicyTemplateDetails?> TemplateDetails(Guid org, Guid id, CancellationToken ct)
    {
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var snapshot = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        var (template, archived) = await ReadCurrentTemplate(snapshot, org, id, ct);
        if (template is null || archived) return null;
        await using var command = BrowserRead(snapshot, """
            SELECT revision, source_version, created_at FROM policy_template_revisions
            WHERE organization_id = $1 AND template_id = $2 ORDER BY revision DESC LIMIT 100
            """, org, id);
        var revisions = new List<PolicyTemplateRevision>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct)) revisions.Add(new(rows.GetInt32(0), rows.GetInt32(1), rows.GetDateTime(2)));
        return new(template, revisions);
    }

    public async Task<PolicyTemplateResult> CreateTemplate(RequestIdentity identity, string name, int sourceVersion, CancellationToken ct)
    {
        var org = identity.OrganizationId;
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await LockPolicySettings(transaction, org, ct);
        if (!await HasTemplateSource(transaction, org, sourceVersion, ct)) return new(Error: "template_source_unavailable");
        await using var capacity = BrowserRead(transaction, "SELECT count(*) FROM policy_templates WHERE organization_id = $1 AND archived_at IS NULL", org);
        if ((long)(await capacity.ExecuteScalarAsync(ct))! >= 100) return new(Error: "template_limit");
        var id = Guid.NewGuid();
        await using var create = BrowserRead(transaction, """
            INSERT INTO policy_templates (organization_id, id, name) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING
            """, org, id, name);
        if (await create.ExecuteNonQueryAsync(ct) == 0) return new(Error: "template_name_exists");
        var template = new PolicyTemplate(id, name, 1, sourceVersion);
        await InsertTemplateRevision(transaction, org, template, ct);
        await AuditTemplate(transaction, identity, new("created", TemplateOrigin(template)), ct);
        await transaction.CommitAsync(ct);
        return new(template);
    }

    public async Task<PolicyTemplateResult> ReviseTemplate(RequestIdentity identity, Guid id, RevisePolicyTemplate request, CancellationToken ct)
    {
        var org = identity.OrganizationId;
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await LockPolicySettings(transaction, org, ct);
        var (current, archived) = await ReadCurrentTemplate(transaction, org, id, ct);
        if (current is null || archived) return new(Error: "template_unavailable");
        if (current.SourceVersion == request.SourceVersion &&
            (current.Revision == request.ExpectedRevision || current.Revision - 1 == request.ExpectedRevision)) return new(current);
        if (current.Revision != request.ExpectedRevision) return new(Error: "template_revision_changed");
        if (!await HasTemplateSource(transaction, org, request.SourceVersion, ct)) return new(Error: "template_source_unavailable");

        var revision = current with { Revision = current.Revision + 1, SourceVersion = request.SourceVersion };
        await InsertTemplateRevision(transaction, org, revision, ct);
        await using var update = BrowserRead(transaction, "UPDATE policy_templates SET current_revision = $3 WHERE organization_id = $1 AND id = $2",
            org, id, revision.Revision);
        await update.ExecuteNonQueryAsync(ct);
        await AuditTemplate(transaction, identity, new("revised", TemplateOrigin(revision)), ct);
        await transaction.CommitAsync(ct);
        return new(revision);
    }

    public async Task<PolicyTemplateResult> ArchiveTemplate(RequestIdentity identity, Guid id, int expectedRevision, CancellationToken ct)
    {
        var org = identity.OrganizationId;
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await LockPolicySettings(transaction, org, ct);
        var (current, archived) = await ReadCurrentTemplate(transaction, org, id, ct);
        if (current is null) return new(Error: "template_unavailable");
        if (current.Revision != expectedRevision) return new(Error: "template_revision_changed");
        if (archived) return new(current);
        await using var update = BrowserRead(transaction, "UPDATE policy_templates SET archived_at = now() WHERE organization_id = $1 AND id = $2", org, id);
        await update.ExecuteNonQueryAsync(ct);
        await AuditTemplate(transaction, identity, new("archived", TemplateOrigin(current)), ct);
        await transaction.CommitAsync(ct);
        return new(current);
    }

    public async Task<PolicyTemplatePreview?> CompareTemplate(Guid org, Guid id, int revision, Guid? groupId, CancellationToken ct)
    {
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var snapshot = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        var origin = await ReadTemplateOrigin(snapshot, org, id, revision, ct);
        var scope = await ReadPolicyScope(snapshot, org, groupId, ct);
        if (origin is null || scope is null) return null;
        var before = await ReadPolicySnapshot(snapshot, org, scope.Version, ct);
        var candidate = await ReadPolicySnapshot(snapshot, org, origin.SourceVersion, ct);
        if (before is null || candidate is null) return null;
        if (groupId.HasValue && !scope.Published) before = before with { PromptExceptions = [] };
        return new(origin, scope.Name, before, candidate with { PromptExceptions = before.PromptExceptions });
    }

    private async Task<PolicyTemplateOrigin?> ReadTemplateOrigin(NpgsqlTransaction transaction, Guid org, Guid id, int revision, CancellationToken ct)
    {
        await using var command = BrowserRead(transaction, """
            SELECT t.id, t.name, r.revision, r.source_version FROM policy_templates t
            JOIN policy_template_revisions r ON t.organization_id = r.organization_id AND t.id = r.template_id
            WHERE t.organization_id = $1 AND t.id = $2 AND r.revision = $3 AND t.archived_at IS NULL
            """, org, id, revision);
        await using var rows = await command.ExecuteReaderAsync(ct);
        return await rows.ReadAsync(ct) ? TemplateOrigin(ReadTemplate(rows)) : null;
    }

    private async Task<(PolicyTemplate? Template, bool Archived)> ReadCurrentTemplate(NpgsqlTransaction transaction, Guid org, Guid id, CancellationToken ct)
    {
        await using var command = BrowserRead(transaction, CurrentTemplate + " WHERE t.organization_id = $1 AND t.id = $2", org, id);
        await using var rows = await command.ExecuteReaderAsync(ct);
        return await rows.ReadAsync(ct) ? (ReadTemplate(rows), !rows.IsDBNull(4)) : (null, false);
    }

    private static PolicyTemplate ReadTemplate(NpgsqlDataReader rows) => new(rows.GetGuid(0), rows.GetString(1), rows.GetInt32(2), rows.GetInt32(3));
    private static PolicyTemplateOrigin TemplateOrigin(PolicyTemplate template) => new(template.Id, template.Name, template.Revision, template.SourceVersion);

    private async Task<bool> HasTemplateSource(NpgsqlTransaction transaction, Guid org, int version, CancellationToken ct)
    {
        await using var command = BrowserRead(transaction, "SELECT EXISTS (SELECT FROM policy_versions WHERE organization_id = $1 AND version = $2)",
            org, version);
        return await command.ExecuteScalarAsync(ct) is true;
    }

    private async Task InsertTemplateRevision(NpgsqlTransaction transaction, Guid org, PolicyTemplate template, CancellationToken ct)
    {
        await using var command = BrowserRead(transaction, """
            INSERT INTO policy_template_revisions (organization_id, template_id, revision, source_version) VALUES ($1, $2, $3, $4)
            """, org, template.Id, template.Revision, template.SourceVersion);
        await command.ExecuteNonQueryAsync(ct);
    }

    private async Task AuditTemplate(NpgsqlTransaction transaction, RequestIdentity identity, PolicyTemplateAudit audit, CancellationToken ct)
    {
        await using var command = BrowserRead(transaction, """
            INSERT INTO control_audit (organization_id, action, actor_access_id, template_change) VALUES ($1, 'policy_template_changed', $2, $3::jsonb)
            """, identity.OrganizationId, (object?)identity.Access?.Id ?? DBNull.Value, JsonSerializer.Serialize(audit, JsonSerializerOptions.Web));
        await command.ExecuteNonQueryAsync(ct);
    }

    private async Task<Guid?> FindPendingTemplateReview(NpgsqlTransaction transaction, RequestIdentity identity, Guid? groupId, int baseVersion,
        PolicyTemplateOrigin source, CancellationToken ct)
    {
        await using var command = BrowserRead(transaction, """
            SELECT id FROM policy_reviews WHERE organization_id = $1 AND requested_by = $2 AND base_version = $3
                AND group_id IS NOT DISTINCT FROM $4::uuid AND status = 'pending' AND expires_at > clock_timestamp()
                AND snapshots->'template'->>'templateId' = $5 AND snapshots->'template'->'revision' = to_jsonb($6::integer)
            ORDER BY requested_at, id LIMIT 1
            """, identity.OrganizationId, identity.Access!.Id, baseVersion, (object?)groupId ?? DBNull.Value, source.TemplateId.ToString(), source.Revision);
        return await command.ExecuteScalarAsync(ct) as Guid?;
    }
}
