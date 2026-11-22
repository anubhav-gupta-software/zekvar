using Npgsql;

namespace Control;

internal sealed partial class ControlStore
{
    public async Task<RequestIdentity?> Authenticate(string token, bool browser, CancellationToken ct)
    {
        var sql = browser
            ? """
                SELECT organization_id, id, NULL::text, NULL::uuid, NULL::text, NULL::text FROM installations
                WHERE token_hash = $1 AND revoked_at IS NULL
                """
            : """
                SELECT o.id, NULL::uuid, o.slug, NULL::uuid, NULL::text, NULL::text
                FROM admin_memberships m JOIN organizations o ON o.id = m.organization_id WHERE m.token_hash = $1
                UNION ALL
                SELECT o.id, NULL::uuid, o.slug, c.id, c.display_name, c.role
                FROM control_access c JOIN organizations o ON o.id = c.organization_id
                WHERE c.token_hash = $1 AND c.revoked_at IS NULL AND c.expires_at > now()
                UNION ALL
                SELECT o.id, NULL::uuid, o.slug, c.id, c.display_name, c.role
                FROM control_sso_sessions s JOIN control_access c ON c.id = s.access_id
                JOIN organizations o ON o.id = c.organization_id
                WHERE s.token_hash = $1 AND s.expires_at > now() AND s.bridge_hash = $2::text
                  AND c.revoked_at IS NULL AND c.oidc_issuer = $3::text AND o.slug = $4::text
                """;
        var hash = Tokens.Hash(token);
        await using var command = browser ? Command(sql, hash) : Command(sql, hash,
            (object?)sso?.BridgeHash ?? DBNull.Value, (object?)sso?.Issuer ?? DBNull.Value, (object?)sso?.OrganizationSlug ?? DBNull.Value);
        await using var rows = await command.ExecuteReaderAsync(ct);
        if (!await rows.ReadAsync(ct)) return null;
        var identity = new RequestIdentity(rows.GetGuid(0), rows.IsDBNull(1) ? null : rows.GetGuid(1),
            rows.IsDBNull(2) ? null : rows.GetString(2), ReadAccessIdentity(rows, 3));
        // Reject ambiguous credentials even if a configured owner token collides with a delegated one.
        return await rows.ReadAsync(ct) ? null : identity;
    }

    public async Task<IReadOnlyList<ControlAccess>> ListAccess(Guid organizationId, CancellationToken ct)
    {
        await using var command = Command("""
            WITH scoped AS (
                SELECT id, display_name, role, issued_at, expires_at,
                    CASE WHEN revoked_at IS NOT NULL THEN 'revoked' WHEN expires_at <= now() THEN 'expired' ELSE 'active' END AS status,
                    oidc_issuer, oidc_subject
                FROM control_access WHERE organization_id = $1
            ), recent_inactive AS (
                SELECT * FROM scoped WHERE status <> 'active' ORDER BY issued_at DESC, id DESC LIMIT 100
            )
            SELECT * FROM scoped WHERE status = 'active'
            UNION ALL SELECT * FROM recent_inactive ORDER BY issued_at DESC, id DESC
            """, organizationId);
        var access = new List<ControlAccess>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct)) access.Add(ReadControlAccess(rows));
        return access;
    }

    public async Task<IssuedControlAccess> IssueAccess(Guid organizationId, string name, string role, int hours, CancellationToken ct)
    {
        var token = Tokens.Generate();
        await using var command = Command("""
            WITH issued AS (
                INSERT INTO control_access (organization_id, display_name, role, token_hash, expires_at)
                VALUES ($1, $2, $3, $4, now() + $5 * interval '1 hour')
                RETURNING organization_id, id, display_name, role, issued_at, expires_at
            ), audit AS (
                INSERT INTO control_audit (organization_id, occurred_at, action, subject_access_id)
                SELECT organization_id, issued_at, 'access_issued', id FROM issued
            )
            SELECT id, display_name, role, issued_at, expires_at, 'active', NULL::text, NULL::text FROM issued
            """, organizationId, name, role, Tokens.Hash(token), hours);
        await using var rows = await command.ExecuteReaderAsync(ct);
        await rows.ReadAsync(ct);
        return new(ReadControlAccess(rows), token);
    }

    public async Task<bool> RevokeAccess(Guid organizationId, Guid id, CancellationToken ct)
    {
        await using var command = Command("""
            WITH revoked AS (
                UPDATE control_access SET revoked_at = now(), token_hash = NULL
                WHERE organization_id = $1 AND id = $2 AND revoked_at IS NULL
                RETURNING organization_id, id, revoked_at
            ), sessions AS (
                DELETE FROM control_sso_sessions s USING revoked r WHERE s.access_id = r.id
            ), audit AS (
                INSERT INTO control_audit (organization_id, occurred_at, action, subject_access_id)
                SELECT organization_id, revoked_at, 'access_revoked', id FROM revoked
            )
            SELECT EXISTS (SELECT 1 FROM control_access WHERE organization_id = $1 AND id = $2)
            """, organizationId, id);
        return (bool)(await command.ExecuteScalarAsync(ct))!;
    }

    private static AccessIdentity? ReadAccessIdentity(NpgsqlDataReader rows, int first) => rows.IsDBNull(first)
        ? null : new(rows.GetGuid(first), rows.GetString(first + 1), rows.GetString(first + 2));

    private static ControlAccess ReadControlAccess(NpgsqlDataReader rows) =>
        new(rows.GetGuid(0), rows.GetString(1), rows.GetString(2), rows.GetDateTime(3), rows.IsDBNull(4) ? null : rows.GetDateTime(4),
            rows.GetString(5), rows.IsDBNull(6) ? null : rows.GetString(6), rows.IsDBNull(7) ? null : rows.GetString(7));
}
