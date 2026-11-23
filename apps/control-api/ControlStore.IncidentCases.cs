using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Control;

internal sealed partial class ControlStore
{
    private const int CaseEventLimit = 100;
    private const string CaseRetained = "(c.status <> 'resolved' OR r.audit_cutoff IS NULL OR c.updated_at >= r.audit_cutoff)";
    private const string CaseFields = """
        c.id, c.category, c.created_at, c.revision, c.status, c.disposition, c.updated_at,
        a.id, a.display_name, a.revoked_at IS NULL AND (a.expires_at IS NULL OR a.expires_at > now())
        """;
    private const string CaseSources = """
        incident_cases c LEFT JOIN retention_cutoffs r ON r.organization_id = c.organization_id
        LEFT JOIN control_access a ON a.organization_id = c.organization_id AND a.id = c.assignee_id
        """;
    private const string RetainedCaseEventCount = $"""
        SELECT count(*)::int FROM incident_case_events links JOIN security_events e
        ON e.organization_id = links.organization_id AND e.installation_id = links.installation_id AND e.event_id = links.event_id
        WHERE links.organization_id = c.organization_id AND links.case_id = c.id AND {EventRetained}
        """;

    private static IncidentCase ReadCase(NpgsqlDataReader rows) => new(rows.GetGuid(0), rows.GetString(1), rows.GetDateTime(2),
        new(rows.GetInt32(3), rows.GetString(4), rows.IsDBNull(5) ? null : rows.GetString(5),
            rows.IsDBNull(7) ? null : new(rows.GetGuid(7), rows.GetString(8), rows.GetBoolean(9)), rows.GetDateTime(6)),
        rows.GetInt32(10));

    public async Task<IncidentCasePage> IncidentCases(Guid org, string? status, bool openOnly, IncidentCaseCursor? cursor, CancellationToken ct)
    {
        const int size = 100;
        await using var command = Command($"""
            SELECT {CaseFields}, ({RetainedCaseEventCount})
            FROM {CaseSources}
            WHERE c.organization_id = $1 AND {CaseRetained} AND (NOT $2 OR c.status <> 'resolved')
                AND ($3::text IS NULL OR c.status = $3)
                AND ($4::timestamptz IS NULL OR (c.created_at, c.id) < ($4, $5::uuid))
            ORDER BY c.created_at DESC, c.id DESC LIMIT $6
            """, org, openOnly, (object?)status ?? DBNull.Value, (object?)cursor?.CreatedAt.UtcDateTime ?? DBNull.Value,
            (object?)cursor?.Id ?? DBNull.Value, size + 1);
        var cases = new List<IncidentCase>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct)) cases.Add(ReadCase(rows));
        if (cases.Count <= size) return new(cases.ToArray(), null);
        cases.RemoveAt(size);
        return new(cases.ToArray(), new(cases[^1].CreatedAt, cases[^1].Id));
    }

    public async Task<IncidentCaseDetails?> IncidentCaseDetail(Guid org, Guid id, CancellationToken ct)
    {
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        var entry = await ReadIncidentCase(transaction, org, id, false, ct);
        if (entry is null) return null;
        await using var events = new NpgsqlCommand($"""
            SELECT {EventFields}
            FROM {EventSources} LEFT {EventTriageJoin}
            JOIN incident_case_events links ON links.organization_id = e.organization_id
                AND links.installation_id = e.installation_id AND links.event_id = e.event_id
            WHERE links.organization_id = $1 AND links.case_id = $2 AND {EventRetained}
            ORDER BY e.occurred_at DESC, e.event_id DESC, e.installation_id DESC
            """, connection, transaction);
        AddParameters(events, org, id);
        var retainedEvents = new List<StoredEvent>();
        await using (var rows = await events.ExecuteReaderAsync(ct))
            while (await rows.ReadAsync(ct)) retainedEvents.Add(ReadEvent(rows));

        await using var audit = new NpgsqlCommand("""
            SELECT a.id, a.occurred_at, a.incident_case_change, actor.id, actor.display_name, actor.role
            FROM control_audit a LEFT JOIN retention_cutoffs r ON r.organization_id = a.organization_id
            LEFT JOIN control_access actor ON actor.organization_id = a.organization_id AND actor.id = a.actor_access_id
            WHERE a.organization_id = $1 AND a.action = 'incident_case_changed' AND a.incident_case_change->>'caseId' = $2::uuid::text
                AND (r.audit_cutoff IS NULL OR a.occurred_at >= r.audit_cutoff)
            ORDER BY a.occurred_at DESC, a.id DESC LIMIT 50
            """, connection, transaction);
        AddParameters(audit, org, id);
        var activity = new List<IncidentCaseActivity>();
        await using (var rows = await audit.ExecuteReaderAsync(ct))
            while (await rows.ReadAsync(ct))
                activity.Add(new(rows.GetGuid(0), rows.GetDateTime(1), ReadAccessIdentity(rows, 3),
                    JsonSerializer.Deserialize<IncidentCaseChange>(rows.GetString(2), JsonSerializerOptions.Web)!));
        await transaction.CommitAsync(ct);
        return new(entry with { EventCount = retainedEvents.Count }, retainedEvents.ToArray(), activity.ToArray());
    }

    private static async Task<IncidentCase?> ReadIncidentCase(NpgsqlTransaction transaction, Guid org, Guid id, bool forUpdate, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand($"""
            SELECT {CaseFields}, 0 FROM {CaseSources}
            WHERE c.organization_id = $1 AND c.id = $2 AND {CaseRetained}
            {(forUpdate ? "FOR UPDATE OF c" : "")}
            """, transaction.Connection, transaction);
        AddParameters(command, org, id);
        await using var rows = await command.ExecuteReaderAsync(ct);
        return await rows.ReadAsync(ct) ? ReadCase(rows) : null;
    }

    private static async Task<IncidentCaseReference?> FindCaseForEvent(NpgsqlTransaction transaction,
        Guid org, Guid installationId, Guid eventId, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand($"""
            SELECT c.id, c.category, c.revision, c.status
            FROM incident_case_events links JOIN incident_cases c ON c.organization_id = links.organization_id AND c.id = links.case_id
            LEFT JOIN retention_cutoffs r ON r.organization_id = c.organization_id
            WHERE links.organization_id = $1 AND links.installation_id = $2 AND links.event_id = $3 AND {CaseRetained}
            """, transaction.Connection, transaction);
        AddParameters(command, org, installationId, eventId);
        await using var rows = await command.ExecuteReaderAsync(ct);
        return await rows.ReadAsync(ct) ? new(rows.GetGuid(0), rows.GetString(1), rows.GetInt32(2), rows.GetString(3)) : null;
    }

    public async Task<IncidentCaseResult> CreateIncidentCase(RequestIdentity identity, CreateIncidentCase request, CancellationToken ct)
    {
        var org = identity.OrganizationId;
        var fingerprint = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{request.InstallationId:D}/{request.EventId:D}/{request.Category}")));
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        var existing = await ExistingCaseCreation(transaction, org, request.RequestId, fingerprint, ct);
        if (existing is not null) return existing;
        if (!await LockEvent(transaction, org, request.InstallationId, request.EventId, ct) ||
            await ReadEventDetail(transaction, org, request.InstallationId, request.EventId, ct) is null) return new();
        existing = await ExistingCaseCreation(transaction, org, request.RequestId, fingerprint, ct);
        if (existing is not null) return existing;
        if (await FindCaseForEvent(transaction, org, request.InstallationId, request.EventId, ct) is not null)
            return new(Error: "event_in_case");

        await using var insert = new NpgsqlCommand("""
            INSERT INTO incident_cases (organization_id, id, category, creation_fingerprint)
            VALUES ($1, $2, $3, $4) ON CONFLICT (organization_id, id) DO NOTHING
            """, connection, transaction);
        AddParameters(insert, org, request.RequestId, request.Category!, fingerprint);
        if (await insert.ExecuteNonQueryAsync(ct) == 0)
            return await ExistingCaseCreation(transaction, org, request.RequestId, fingerprint, ct) ?? new(Error: "case_request_conflict");

        if (!await AttachCaseEvent(transaction, org, request.RequestId, request.InstallationId, request.EventId, ct))
            return new(Error: "event_in_case");
        await WriteCaseAudit(transaction, identity, new(request.RequestId, request.Category!, 1, "created",
            After: EventTriage.Initial.State(), InstallationId: request.InstallationId, EventId: request.EventId), ct);
        await transaction.CommitAsync(ct);
        return new(request.RequestId);
    }

    private static async Task<IncidentCaseResult?> ExistingCaseCreation(NpgsqlTransaction transaction,
        Guid org, Guid id, string fingerprint, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand($"""
            SELECT c.creation_fingerprint, {CaseRetained}
            FROM incident_cases c LEFT JOIN retention_cutoffs r ON r.organization_id = c.organization_id
            WHERE c.organization_id = $1 AND c.id = $2
            """, transaction.Connection, transaction);
        AddParameters(command, org, id);
        await using var rows = await command.ExecuteReaderAsync(ct);
        if (!await rows.ReadAsync(ct)) return null;
        if (!rows.GetBoolean(1)) return new();
        return rows.GetString(0) == fingerprint ? new(id) : new(Error: "case_request_conflict");
    }

    public async Task<IncidentCaseResult> ChangeCaseTriage(RequestIdentity identity, Guid id, SetEventTriage request, CancellationToken ct)
    {
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        var current = await ReadIncidentCase(transaction, identity.OrganizationId, id, true, ct);
        if (current is null) return new();
        var desired = new EventTriageState(request.Status!, request.Disposition, request.AssigneeId);
        if (current.Triage.State() == desired && RetryRevision(current.Triage.Revision, request.ExpectedRevision)) return new(id);
        if (current.Triage.Revision != request.ExpectedRevision) return new(Error: "case_stale");
        if (request.AssigneeId is { } assignee && assignee != current.Triage.Assignee?.Id &&
            await FindActiveTriageAssignee(transaction, identity.OrganizationId, assignee, ct) is null)
            return new(Error: "event_assignee_unavailable");

        await using var command = new NpgsqlCommand("""
            UPDATE incident_cases SET status = $3, disposition = $4, assignee_id = $5,
                revision = revision + 1, updated_at = statement_timestamp()
            WHERE organization_id = $1 AND id = $2
            """, connection, transaction);
        AddParameters(command, identity.OrganizationId, id, desired.Status, (object?)desired.Disposition ?? DBNull.Value,
            (object?)desired.AssigneeId ?? DBNull.Value);
        await command.ExecuteNonQueryAsync(ct);
        await WriteCaseAudit(transaction, identity, new(id, current.Category, current.Triage.Revision + 1, "triage_updated",
            current.Triage.State(), desired), ct);
        await transaction.CommitAsync(ct);
        return new(id);
    }

    public async Task<IncidentCaseResult> ChangeCaseMembership(RequestIdentity identity, Guid caseId, SetCaseMembership request, CancellationToken ct)
    {
        var org = identity.OrganizationId;
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        // Always take the event lock before the case lock. Case creation follows the same order.
        if (!await LockEvent(transaction, org, request.InstallationId, request.EventId, ct) ||
            await ReadEventDetail(transaction, org, request.InstallationId, request.EventId, ct) is null) return new();
        var current = await ReadIncidentCase(transaction, org, caseId, true, ct);
        if (current is null) return new();
        var linked = await FindCaseForEvent(transaction, org, request.InstallationId, request.EventId, ct);
        if (linked is not null && linked.Id != caseId) return new(Error: "event_in_case");
        if ((linked?.Id == caseId) == request.Linked && RetryRevision(current.Triage.Revision, request.ExpectedRevision)) return new(caseId);
        if (current.Triage.Revision != request.ExpectedRevision) return new(Error: "case_stale");
        if (current.Triage.Status == TriageStatus.Resolved) return new(Error: "case_resolved");
        if (request.Linked == true)
        {
            await using var count = new NpgsqlCommand($"""
                SELECT ({RetainedCaseEventCount})
                FROM incident_cases c LEFT JOIN retention_cutoffs r ON r.organization_id = c.organization_id
                WHERE c.organization_id = $1 AND c.id = $2
                """, connection, transaction);
            AddParameters(count, org, caseId);
            if ((int)(await count.ExecuteScalarAsync(ct))! >= CaseEventLimit) return new(Error: "case_event_limit");
            if (!await AttachCaseEvent(transaction, org, caseId, request.InstallationId, request.EventId, ct))
                return new(Error: "event_in_case");
        }
        else
        {
            await using var remove = new NpgsqlCommand("""
                DELETE FROM incident_case_events WHERE organization_id = $1 AND case_id = $2 AND installation_id = $3 AND event_id = $4
                """, connection, transaction);
            AddParameters(remove, org, caseId, request.InstallationId, request.EventId);
            await remove.ExecuteNonQueryAsync(ct);
        }
        await using var touch = new NpgsqlCommand("""
            UPDATE incident_cases SET revision = revision + 1, updated_at = statement_timestamp()
            WHERE organization_id = $1 AND id = $2
            """, connection, transaction);
        AddParameters(touch, org, caseId);
        await touch.ExecuteNonQueryAsync(ct);
        await WriteCaseAudit(transaction, identity, new(caseId, current.Category, current.Triage.Revision + 1,
            request.Linked == true ? "event_added" : "event_removed", InstallationId: request.InstallationId, EventId: request.EventId), ct);
        await transaction.CommitAsync(ct);
        return new(caseId);
    }

    private static async Task<bool> AttachCaseEvent(NpgsqlTransaction transaction, Guid org, Guid caseId, Guid installationId, Guid eventId,
        CancellationToken ct)
    {
        // The event lock and absence of a retained link permit reclaiming a link to a logically expired case.
        await using var command = new NpgsqlCommand($"""
            INSERT INTO incident_case_events (organization_id, case_id, installation_id, event_id)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (installation_id, event_id) DO UPDATE SET case_id = EXCLUDED.case_id
            WHERE incident_case_events.organization_id = EXCLUDED.organization_id AND EXISTS (
                SELECT 1 FROM incident_cases c LEFT JOIN retention_cutoffs r ON r.organization_id = c.organization_id
                WHERE c.organization_id = $1 AND c.id = incident_case_events.case_id AND NOT {CaseRetained})
            """, transaction.Connection, transaction);
        AddParameters(command, org, caseId, installationId, eventId);
        return await command.ExecuteNonQueryAsync(ct) == 1;
    }

    private static async Task WriteCaseAudit(NpgsqlTransaction transaction, RequestIdentity identity, IncidentCaseChange change, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            INSERT INTO control_audit (organization_id, occurred_at, action, actor_access_id, incident_case_change)
            VALUES ($1, statement_timestamp(), 'incident_case_changed', $2, $3::jsonb)
            """, transaction.Connection, transaction);
        AddParameters(command, identity.OrganizationId, (object?)identity.Access?.Id ?? DBNull.Value, JsonSerializer.Serialize(change, JsonSerializerOptions.Web));
        await command.ExecuteNonQueryAsync(ct);
    }
}
