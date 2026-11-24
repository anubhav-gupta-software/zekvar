using System.Data;
using System.Text.Json;
using Npgsql;

namespace Control;

internal sealed partial class ControlStore
{
    public async Task<FleetPage?> ReadFleet(Guid organizationId, BrowserHealthFilter filter, FleetCursor? before, CancellationToken ct)
    {
        const int pageSize = 50;
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var snapshot = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        if (filter.GroupId is { } groupId)
        {
            await using var scope = BrowserRead(snapshot, "SELECT EXISTS (SELECT FROM policy_groups WHERE organization_id = $1 AND id = $2)", organizationId, groupId);
            if (await scope.ExecuteScalarAsync(ct) is not true) return null;
        }
        await using var command = BrowserRead(snapshot, """
            SELECT i.id, i.enrolled_at, i.last_seen_at, i.policy_group_id, g.name, i.assignment_version,
                i.assignment_aware, COALESCE(g.policy_version, o.policy_version), i.extension_version
            FROM installations i JOIN organizations o ON o.id = i.organization_id
            LEFT JOIN policy_groups g ON g.organization_id = i.organization_id AND g.id = i.policy_group_id
            WHERE i.organization_id = $1 AND i.revoked_at IS NULL
                AND (NOT $2 OR i.policy_group_id IS NOT DISTINCT FROM $3::uuid)
                AND ($4::timestamptz IS NULL OR (i.enrolled_at, i.id) < ($4, $5::uuid))
            ORDER BY i.enrolled_at DESC, i.id DESC LIMIT $6
            """, organizationId, filter.Scoped, (object?)filter.GroupId ?? DBNull.Value,
            (object?)before?.EnrolledAt ?? DBNull.Value, (object?)before?.InstallationId ?? DBNull.Value, pageSize + 1);
        var entries = new List<FleetBrowser>(pageSize + 1);
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct)) entries.Add(new(rows.GetGuid(0), rows.GetDateTime(1), rows.GetDateTime(2),
            rows.IsDBNull(3) ? null : rows.GetGuid(3), rows.IsDBNull(4) ? null : rows.GetString(4), rows.GetInt32(5), rows.GetBoolean(6),
            rows.GetInt32(7), rows.IsDBNull(8) ? null : rows.GetString(8)));
        if (entries.Count <= pageSize) return new(entries, null);
        entries.RemoveAt(pageSize);
        return new(entries, new(entries[^1].EnrolledAt, entries[^1].InstallationId));
    }

    public async Task<FleetOutcome> ApplyFleetChange(RequestIdentity identity, FleetRequest request, CancellationToken ct)
    {
        var organizationId = identity.OrganizationId;
        var selections = request.Selections!.Select(entry => entry!).OrderBy(entry => entry.InstallationId).ToArray();
        var installationIds = selections.Select(entry => entry.InstallationId).ToArray();
        var fingerprint = Tokens.Hash(JsonSerializer.Serialize(new
        {
            request.Operation, request.GroupId, request.ExpectedPolicyVersion, Selections = selections, Actor = identity.Access?.Id
        }, JsonSerializerOptions.Web));
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        // Policy publishing and other fleet batches use this same organization row lock.
        await using var tenant = BrowserRead(transaction, "SELECT policy_version FROM organizations WHERE id = $1 FOR NO KEY UPDATE", organizationId);
        var baseline = (int)(await tenant.ExecuteScalarAsync(ct))!;
        var replay = await ReadFleetReceipt(transaction, organizationId, request.RequestId, fingerprint, ct);
        if (replay is not null) return replay;

        string? groupName = null;
        if (request.Operation == "assign")
        {
            if (request.GroupId is { } groupId)
            {
                await using var group = BrowserRead(transaction, """
                    SELECT name, COALESCE(policy_version, $3) FROM policy_groups WHERE organization_id = $1 AND id = $2
                    """, organizationId, groupId, baseline);
                await using var row = await group.ExecuteReaderAsync(ct);
                if (!await row.ReadAsync(ct)) return new(Error: "fleet_target_unavailable");
                groupName = row.GetString(0);
                if (row.GetInt32(1) != request.ExpectedPolicyVersion) return new(Error: "fleet_policy_changed");
            }
            else if (baseline != request.ExpectedPolicyVersion) return new(Error: "fleet_policy_changed");
        }

        var selectionError = await LockFleetSelection(transaction, organizationId, selections, request, ct);
        if (selectionError is not null) return new(Error: selectionError);
        var changed = request.Operation == "assign"
            ? await AssignFleetGroup(transaction, identity, installationIds, request.GroupId, groupName, ct)
            : (await RevokeInstallations(identity, installationIds, transaction, ct)).Changed;
        var receipt = new FleetChange(request.RequestId, request.Operation!, request.GroupId, groupName,
            request.ExpectedPolicyVersion, installationIds.Length, changed);
        await using var audit = BrowserRead(transaction, """
            INSERT INTO control_audit (organization_id, action, actor_access_id, fleet_change, fleet_request_hash)
            VALUES ($1, 'browser_fleet_changed', $2, $3::jsonb, $4)
            """, organizationId, (object?)identity.Access?.Id ?? DBNull.Value, JsonSerializer.Serialize(receipt, JsonSerializerOptions.Web), fingerprint);
        await audit.ExecuteNonQueryAsync(ct);
        await transaction.CommitAsync(ct);
        return new(receipt);
    }

    private async Task<FleetOutcome?> ReadFleetReceipt(NpgsqlTransaction transaction, Guid organizationId, Guid batchId,
        string fingerprint, CancellationToken ct)
    {
        await using var command = BrowserRead(transaction, """
            SELECT a.fleet_request_hash, a.fleet_change, r.audit_cutoff IS NULL OR a.occurred_at >= r.audit_cutoff
            FROM control_audit a LEFT JOIN retention_cutoffs r USING (organization_id)
            WHERE a.organization_id = $1 AND a.action = 'browser_fleet_changed' AND a.fleet_change->>'batchId' = $2
            """, organizationId, batchId.ToString());
        await using var row = await command.ExecuteReaderAsync(ct);
        if (!await row.ReadAsync(ct)) return null;
        if (!row.GetBoolean(2) || row.GetString(0) != fingerprint) return new(Error: "fleet_request_conflict");
        return new(JsonSerializer.Deserialize<FleetChange>(row.GetString(1), JsonSerializerOptions.Web));
    }

    private async Task<string?> LockFleetSelection(NpgsqlTransaction transaction, Guid organizationId, FleetSelection[] selections,
        FleetRequest request, CancellationToken ct)
    {
        var versions = selections.ToDictionary(entry => entry.InstallationId, entry => entry.AssignmentVersion);
        await using var command = BrowserRead(transaction, """
            SELECT id, assignment_version, assignment_aware, policy_group_id FROM installations
            WHERE organization_id = $1 AND id = ANY($2) AND revoked_at IS NULL ORDER BY id FOR UPDATE
            """, organizationId, versions.Keys.ToArray());
        var found = 0;
        var stale = false;
        var upgrade = false;
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct))
        {
            found++;
            stale |= rows.GetInt32(1) != versions[rows.GetGuid(0)];
            var groupId = rows.IsDBNull(3) ? (Guid?)null : rows.GetGuid(3);
            upgrade |= request.Operation == "assign" && !rows.GetBoolean(2) && groupId != request.GroupId;
        }
        if (found != selections.Length) return "fleet_selection_unavailable";
        if (stale) return "fleet_selection_changed";
        return upgrade ? "fleet_upgrade_required" : null;
    }

    private async Task<Guid[]> AssignFleetGroup(NpgsqlTransaction transaction, RequestIdentity identity, Guid[] ids, Guid? groupId,
        string? groupName, CancellationToken ct)
    {
        await using var command = BrowserRead(transaction, $"""
            WITH target AS (
                SELECT id, policy_group_id, assignment_aware, $5::text AS group_name FROM installations
                WHERE organization_id = $1 AND id = ANY($2)
            ), {WriteGroupAssignments}
            SELECT ARRAY(SELECT id FROM changed ORDER BY id)
            """, identity.OrganizationId, ids, (object?)groupId ?? DBNull.Value, (object?)identity.Access?.Id ?? DBNull.Value,
            (object?)groupName ?? DBNull.Value);
        return (Guid[])(await command.ExecuteScalarAsync(ct))!;
    }
}
