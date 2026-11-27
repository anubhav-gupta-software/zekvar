using Npgsql;

namespace Control;

internal sealed partial class ControlStore
{
    public async Task<RequestIdentity?> Authenticate(string token, bool browser, CancellationToken ct)
    {
        var sql = browser
            ? """
                SELECT organization_id, id, NULL::text, NULL::uuid, NULL::text, NULL::text, NULL::text, NULL::text, false FROM installations
                WHERE token_hash = $1 AND revoked_at IS NULL AND NOT organization_offboarding(organization_id)
                """
            : """
                SELECT o.id, NULL::uuid, o.slug, NULL::uuid, NULL::text, NULL::text, NULL::text, NULL::text, organization_offboarding(o.id)
                FROM admin_memberships m JOIN organizations o ON o.id = m.organization_id WHERE m.token_hash = $1
                UNION ALL
                SELECT o.id, NULL::uuid, o.slug, c.id, c.display_name, c.role, NULL::text, NULL::text, false
                FROM control_access c JOIN organizations o ON o.id = c.organization_id
                WHERE c.token_hash = $1 AND c.revoked_at IS NULL AND c.expires_at > now() AND NOT organization_offboarding(o.id)
                UNION ALL
                SELECT o.id, NULL::uuid, o.slug, c.id, c.display_name, c.role, c.oidc_issuer, s.bridge_hash, false
                FROM control_sso_sessions s JOIN control_access c ON c.id = s.access_id
                JOIN organizations o ON o.id = c.organization_id
                WHERE s.token_hash = $1 AND s.expires_at > now() AND c.revoked_at IS NULL AND NOT organization_offboarding(o.id)
                """;
        await using var command = Command(sql, Tokens.Hash(token));
        await using var rows = await command.ExecuteReaderAsync(ct);
        RequestIdentity? identity = null;
        while (await rows.ReadAsync(ct))
        {
            var organization = rows.IsDBNull(2) ? null : rows.GetString(2);
            if (!rows.IsDBNull(7) && (organization is null || !sso.TryGetValue(organization, out var settings) ||
                rows.IsDBNull(6) || rows.GetString(6) != settings.Issuer || rows.GetString(7) != settings.BridgeHash)) continue;
            // Reject ambiguous credentials even if a configured owner token collides with a delegated one.
            if (identity is not null) return null;
            identity = new(rows.GetGuid(0), rows.IsDBNull(1) ? null : rows.GetGuid(1), organization, ReadAccessIdentity(rows, 3), rows.GetBoolean(8));
        }
        return identity;
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
