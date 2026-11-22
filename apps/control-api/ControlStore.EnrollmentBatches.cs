namespace Control;

internal sealed partial class ControlStore
{
    public async Task<(IssuedEnrollmentBatch? Batch, bool ScopeExists)> IssueEnrollmentBatch(RequestIdentity identity,
        CreateEnrollmentBatch request, CancellationToken ct)
    {
        var grants = Enumerable.Range(0, request.Count).Select(_ => Tokens.Generate()).ToArray();
        await using var command = Command("""
            WITH allowed AS (
                SELECT $3::uuid AS group_id, g.name FROM (SELECT 1) x
                LEFT JOIN policy_groups g ON g.organization_id = $1 AND g.id = $3
                WHERE $3 IS NULL OR g.id IS NOT NULL
            ), batch AS (
                INSERT INTO enrollment_batches (organization_id, id, policy_group_id, size, expires_at)
                SELECT $1, $2, group_id, cardinality($4::text[]), now() + interval '10 minutes' FROM allowed
                ON CONFLICT (organization_id, id) DO NOTHING
                RETURNING organization_id, id, policy_group_id, size, expires_at
            ), grants AS (
                INSERT INTO enrollment_grants (organization_id, batch_id, token_hash, expires_at)
                SELECT b.organization_id, b.id, hash, b.expires_at FROM batch b CROSS JOIN unnest($4::text[]) AS keys(hash)
            ), audit AS (
                INSERT INTO control_audit (organization_id, action, actor_access_id, enrollment_batch_change)
                SELECT organization_id, 'enrollment_batch_issued', $5, jsonb_build_object(
                    'batchId', id, 'groupId', policy_group_id, 'groupName', allowed.name, 'count', size)
                FROM batch CROSS JOIN allowed
            )
            SELECT (SELECT expires_at FROM batch), EXISTS (SELECT 1 FROM allowed)
            """, identity.OrganizationId, request.RequestId, (object?)request.GroupId ?? DBNull.Value,
            grants.Select(Tokens.Hash).ToArray(), (object?)identity.Access?.Id ?? DBNull.Value);
        await using var row = await command.ExecuteReaderAsync(ct);
        await row.ReadAsync(ct);
        return (row.IsDBNull(0) ? null : new(request.RequestId, row.GetDateTime(0), grants), row.GetBoolean(1));
    }

    public async Task<IReadOnlyList<EnrollmentBatch>> EnrollmentBatches(Guid organizationId, CancellationToken ct)
    {
        await using var command = Command("""
            WITH recent AS (
                SELECT * FROM enrollment_batches WHERE organization_id = $1 ORDER BY created_at DESC, id LIMIT 100
            )
            SELECT b.id, b.policy_group_id, p.name, b.size, g.redeemed, g.available, b.created_at, b.expires_at,
                CASE WHEN b.cancelled_at IS NOT NULL THEN 'cancelled' WHEN g.redeemed = b.size THEN 'used'
                    WHEN b.expires_at <= now() THEN 'expired' ELSE 'open' END
            FROM recent b LEFT JOIN policy_groups p ON p.organization_id = b.organization_id AND p.id = b.policy_group_id
            CROSS JOIN LATERAL (
                SELECT (count(*) FILTER (WHERE redeemed_at IS NOT NULL))::int AS redeemed,
                    (count(*) FILTER (WHERE redeemed_at IS NULL AND expires_at > now() AND b.cancelled_at IS NULL))::int AS available
                FROM enrollment_grants WHERE organization_id = b.organization_id AND batch_id = b.id
            ) g ORDER BY b.created_at DESC, b.id
            """, organizationId);
        var batches = new List<EnrollmentBatch>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct))
            batches.Add(new(rows.GetGuid(0), rows.IsDBNull(1) ? null : rows.GetGuid(1), rows.IsDBNull(2) ? null : rows.GetString(2),
                rows.GetInt32(3), rows.GetInt32(4), rows.GetInt32(5), rows.GetDateTime(6), rows.GetDateTime(7), rows.GetString(8)));
        return batches;
    }

    public async Task<bool> CancelEnrollmentBatch(RequestIdentity identity, Guid id, CancellationToken ct)
    {
        await using var command = Command("""
            WITH cancelled AS (
                UPDATE enrollment_batches SET cancelled_at = now()
                WHERE organization_id = $1 AND id = $2 AND cancelled_at IS NULL AND expires_at > now()
                RETURNING organization_id, id, policy_group_id
            ), deleted AS (
                DELETE FROM enrollment_grants g USING cancelled c WHERE g.organization_id = c.organization_id
                    AND g.batch_id = c.id AND g.redeemed_at IS NULL RETURNING g.batch_id
            ), audit AS (
                INSERT INTO control_audit (organization_id, action, actor_access_id, enrollment_batch_change)
                SELECT c.organization_id, 'enrollment_batch_cancelled', $3, jsonb_build_object('batchId', c.id,
                    'groupId', c.policy_group_id, 'groupName', p.name, 'count', (SELECT count(*) FROM deleted))
                FROM cancelled c LEFT JOIN policy_groups p ON p.organization_id = c.organization_id AND p.id = c.policy_group_id
            )
            SELECT EXISTS (SELECT 1 FROM enrollment_batches WHERE organization_id = $1 AND id = $2)
            """, identity.OrganizationId, id, (object?)identity.Access?.Id ?? DBNull.Value);
        return (bool)(await command.ExecuteScalarAsync(ct))!;
    }
}
