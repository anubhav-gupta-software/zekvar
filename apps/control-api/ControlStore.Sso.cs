namespace Control;

internal sealed partial class ControlStore
{
    public async Task<ControlAccess?> AddSsoIdentity(Guid organizationId, string issuer, string subject, string name, string role, CancellationToken ct)
    {
        await using var command = Command("""
            WITH issued AS (
                INSERT INTO control_access (organization_id, oidc_issuer, oidc_subject, display_name, role)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (organization_id, oidc_issuer, oidc_subject) WHERE revoked_at IS NULL AND oidc_subject IS NOT NULL DO NOTHING
                RETURNING organization_id, id, display_name, role, issued_at, expires_at, oidc_issuer, oidc_subject
            ), audit AS (
                INSERT INTO control_audit (organization_id, occurred_at, action, subject_access_id)
                SELECT organization_id, issued_at, 'access_issued', id FROM issued
            )
            SELECT id, display_name, role, issued_at, expires_at, 'active', oidc_issuer, oidc_subject FROM issued
            """, organizationId, issuer, subject, name, role);
        await using var rows = await command.ExecuteReaderAsync(ct);
        return await rows.ReadAsync(ct) ? ReadControlAccess(rows) : null;
    }

    public async Task<SsoSession?> ExchangeSsoIdentity(ControlSso settings, string subject, DateTimeOffset expiresAt, CancellationToken ct)
    {
        var token = Tokens.Generate();
        await using var command = Command("""
            WITH identity AS (
                SELECT c.id, c.organization_id FROM control_access c JOIN organizations o ON o.id = c.organization_id
                WHERE o.slug = $1 AND c.oidc_issuer = $2 AND c.oidc_subject = $3 AND c.revoked_at IS NULL
                    AND $6::timestamptz > now() AND NOT organization_offboarding(o.id) FOR UPDATE OF c
            ), session AS (
                INSERT INTO control_sso_sessions (access_id, token_hash, bridge_hash, expires_at)
                SELECT id, $4, $5, LEAST($6::timestamptz, now() + interval '1 hour') FROM identity
                RETURNING access_id, expires_at
            ), audit AS (
                INSERT INTO control_audit (organization_id, action, actor_access_id)
                SELECT i.organization_id, 'control_sso_signed_in', i.id FROM identity i JOIN session s ON s.access_id = i.id
            )
            SELECT expires_at FROM session
            """, settings.OrganizationSlug, settings.Issuer, subject, Tokens.Hash(token), settings.BridgeHash, expiresAt.UtcDateTime);
        return await command.ExecuteScalarAsync(ct) is DateTime expiry ? new(token, expiry) : null;
    }

    public async Task EndSsoSession(string token, CancellationToken ct)
    {
        await using var command = Command("DELETE FROM control_sso_sessions WHERE token_hash = $1", Tokens.Hash(token));
        await command.ExecuteNonQueryAsync(ct);
    }

    public async Task ExpireSsoSessions(CancellationToken ct)
    {
        await using var command = Command("DELETE FROM control_sso_sessions WHERE expires_at <= now()");
        await command.ExecuteNonQueryAsync(ct);
    }
}
