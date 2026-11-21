namespace Control;

internal sealed partial class ControlStore
{
    public async Task<IReadOnlyList<PolicyGroup>> Groups(Guid organizationId, CancellationToken ct)
    {
        await using var command = Command("""
            SELECT g.id, g.name, COALESCE(g.policy_version, o.policy_version), g.policy_version,
                (SELECT count(*) FROM installations i WHERE i.organization_id = g.organization_id
                 AND i.policy_group_id = g.id AND i.revoked_at IS NULL)
            FROM policy_groups g JOIN organizations o ON o.id = g.organization_id
            WHERE g.organization_id = $1 ORDER BY lower(g.name), g.id
            """, organizationId);
        var groups = new List<PolicyGroup>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct))
            groups.Add(new(rows.GetGuid(0), rows.GetString(1), rows.GetInt32(2), rows.IsDBNull(3) ? null : rows.GetInt32(3), rows.GetInt64(4)));
        return groups;
    }

    public async Task<PolicyGroup?> CreateGroup(RequestIdentity identity, string name, CancellationToken ct)
    {
        await using var command = Command("""
            WITH created AS (
                INSERT INTO policy_groups (organization_id, name) VALUES ($1, $2) ON CONFLICT DO NOTHING
                RETURNING organization_id, id, name
            ), audit AS (
                INSERT INTO control_audit (organization_id, action, group_change, actor_access_id)
                SELECT organization_id, 'policy_group_created', jsonb_build_object('groupId', id, 'groupName', name), $3 FROM created
            )
            SELECT c.id, c.name, o.policy_version FROM created c JOIN organizations o ON o.id = c.organization_id
            """, identity.OrganizationId, name, (object?)identity.Access?.Id ?? DBNull.Value);
        await using var rows = await command.ExecuteReaderAsync(ct);
        return await rows.ReadAsync(ct) ? new(rows.GetGuid(0), rows.GetString(1), rows.GetInt32(2), null, 0) : null;
    }

    public async Task<string?> AssignGroup(RequestIdentity identity, Guid installationId, Guid? groupId, CancellationToken ct)
    {
        await using var command = Command("""
            WITH target AS (
                SELECT i.id, i.organization_id, i.policy_group_id, i.assignment_aware, g.name AS group_name
                FROM installations i LEFT JOIN policy_groups g ON g.organization_id = i.organization_id AND g.id = $3::uuid
                WHERE i.organization_id = $1 AND i.id = $2 AND i.revoked_at IS NULL AND ($3 IS NULL OR g.id IS NOT NULL)
                FOR UPDATE OF i
            ), changed AS (
                UPDATE installations i SET policy_group_id = $3, assignment_version = assignment_version + 1, applied_policy_version = NULL
                FROM target t WHERE i.id = t.id AND t.assignment_aware AND t.policy_group_id IS DISTINCT FROM $3
                RETURNING i.organization_id, i.id, i.policy_group_id, t.group_name
            ), audit AS (
                INSERT INTO control_audit (organization_id, action, group_change, actor_access_id)
                SELECT organization_id, 'policy_group_assigned', jsonb_build_object(
                    'groupId', policy_group_id, 'groupName', group_name, 'installationId', id), $4 FROM changed
            )
            SELECT CASE WHEN assignment_aware OR policy_group_id IS NOT DISTINCT FROM $3 THEN 'assigned' ELSE 'upgrade_required' END FROM target
            """, identity.OrganizationId, installationId, (object?)groupId ?? DBNull.Value, (object?)identity.Access?.Id ?? DBNull.Value);
        return (string?)await command.ExecuteScalarAsync(ct);
    }
}
