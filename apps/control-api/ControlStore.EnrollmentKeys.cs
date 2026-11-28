using Npgsql;

namespace Control;

internal sealed partial class ControlStore
{
    public const int ActiveEnrollmentKeyLimit = 20;
    public int EnrollmentKeyAttemptsPerMinute { get; init; } = 600;

    private const string EnrollmentKeyColumns = """
        k.id, k.label, k.policy_group_id, g.name, k.created_at, k.expires_at, k.max_redemptions, k.redeemed,
            (SELECT count(*)::integer FROM enrollment_key_redemptions r JOIN installations i
                ON i.organization_id = r.organization_id AND i.id = r.installation_id
             WHERE r.organization_id = k.organization_id AND r.key_id = k.id AND i.revoked_at IS NULL),
            k.last_redeemed_at, k.rejected, k.last_rejected_at, k.revoked_at, k.rotated_from,
            CASE WHEN k.revoked_at IS NOT NULL THEN 'revoked' WHEN k.expires_at <= now() THEN 'expired'
                WHEN k.redeemed >= k.max_redemptions THEN 'exhausted' ELSE 'active' END
        FROM enrollment_keys k LEFT JOIN policy_groups g ON g.organization_id = k.organization_id AND g.id = k.policy_group_id
        """;

    public async Task<IReadOnlyList<EnrollmentKey>> ListEnrollmentKeys(Guid organizationId, CancellationToken ct)
    {
        await using var command = Command($"""
            SELECT {EnrollmentKeyColumns}
            WHERE k.organization_id = $1
            ORDER BY (k.revoked_at IS NULL AND k.expires_at > now()) DESC, k.created_at DESC, k.id DESC LIMIT 100
            """, organizationId);
        var keys = new List<EnrollmentKey>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct)) keys.Add(ReadEnrollmentKey(rows));
        return keys;
    }

    public async Task<EnrollmentKey?> FindEnrollmentKey(Guid organizationId, Guid id, CancellationToken ct)
    {
        await using var command = Command($"SELECT {EnrollmentKeyColumns} WHERE k.organization_id = $1 AND k.id = $2", organizationId, id);
        await using var rows = await command.ExecuteReaderAsync(ct);
        return await rows.ReadAsync(ct) ? ReadEnrollmentKey(rows) : null;
    }

    public Task<EnrollmentKeyOutcome> IssueEnrollmentKey(RequestIdentity identity, CreateEnrollmentKey request, string label, CancellationToken ct) =>
        WriteEnrollmentKey(identity, request.RequestId, request.Days, null, null, (label, request.GroupId, request.MaxRedemptions), ct);

    public Task<EnrollmentKeyOutcome> RotateEnrollmentKey(RequestIdentity identity, Guid previousId, RotateEnrollmentKey request, CancellationToken ct) =>
        WriteEnrollmentKey(identity, request.RequestId, request.Days, previousId, request.OverlapHours, null, ct);

    private async Task<EnrollmentKeyOutcome> WriteEnrollmentKey(RequestIdentity identity, Guid id, int days, Guid? previousId, int? overlapHours,
        (string Label, Guid? GroupId, int? MaxRedemptions)? scope, CancellationToken ct)
    {
        var organizationId = identity.OrganizationId;
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        // Serialize issuance per tenant so the active-key limit holds under concurrent requests.
        await using (var tenant = BrowserRead(transaction, "SELECT id FROM organizations WHERE id = $1 FOR NO KEY UPDATE", organizationId))
            await tenant.ExecuteScalarAsync(ct);
        await using (var capacity = BrowserRead(transaction, """
            SELECT CASE WHEN EXISTS (SELECT 1 FROM enrollment_keys WHERE organization_id = $1 AND id = $2) THEN 'enrollment_key_exists'
                WHEN (SELECT count(*) FROM enrollment_keys WHERE organization_id = $1 AND revoked_at IS NULL AND expires_at > now()) >= $3
                THEN 'enrollment_key_limit' END
            """, organizationId, id, ActiveEnrollmentKeyLimit))
            if (await capacity.ExecuteScalarAsync(ct) is string error) return new(Error: error);

        string label;
        Guid? groupId;
        int? maxRedemptions;
        if (previousId is { } previous)
        {
            await using var old = BrowserRead(transaction, """
                SELECT label, policy_group_id, max_redemptions, revoked_at IS NULL AND expires_at > now()
                FROM enrollment_keys WHERE organization_id = $1 AND id = $2 FOR UPDATE
                """, organizationId, previous);
            await using var row = await old.ExecuteReaderAsync(ct);
            if (!await row.ReadAsync(ct)) return new(Error: "enrollment_key_unavailable");
            if (!row.GetBoolean(3)) return new(Error: "enrollment_key_inactive");
            (label, groupId, maxRedemptions) = (row.GetString(0), row.IsDBNull(1) ? null : row.GetGuid(1), row.IsDBNull(2) ? null : row.GetInt32(2));
        }
        else
        {
            (label, groupId, maxRedemptions) = scope!.Value;
            if (groupId is { } group)
            {
                await using var exists = BrowserRead(transaction,
                    "SELECT EXISTS (SELECT 1 FROM policy_groups WHERE organization_id = $1 AND id = $2)", organizationId, group);
                if (await exists.ExecuteScalarAsync(ct) is not true) return new(Error: "enrollment_key_group_unavailable");
            }
        }

        var token = EnrollmentKeyToken.Generate();
        await using (var insert = BrowserRead(transaction, """
            WITH shortened AS (
                UPDATE enrollment_keys SET expires_at = LEAST(expires_at, statement_timestamp() + $8 * interval '1 hour')
                WHERE organization_id = $1 AND id = $7 AND $8::integer IS NOT NULL
                RETURNING expires_at
            ), issued AS (
                INSERT INTO enrollment_keys (organization_id, id, label, token_hash, policy_group_id, expires_at, max_redemptions, rotated_from)
                VALUES ($1, $2, $3, $4, $5, statement_timestamp() + $6 * interval '24 hours', $9, $7)
                RETURNING organization_id, id, label, policy_group_id, expires_at, max_redemptions, rotated_from
            )
            INSERT INTO control_audit (organization_id, action, actor_access_id, enrollment_key_change)
            SELECT i.organization_id, 'enrollment_key_issued', $10, jsonb_strip_nulls(jsonb_build_object('keyId', i.id, 'label', i.label,
                'groupId', i.policy_group_id, 'groupName', g.name, 'expiresAt', i.expires_at, 'maxRedemptions', i.max_redemptions,
                'rotatedFrom', i.rotated_from, 'previousKeyExpiresAt', (SELECT expires_at FROM shortened)))
            FROM issued i LEFT JOIN policy_groups g ON g.organization_id = i.organization_id AND g.id = i.policy_group_id
            """, organizationId, id, label, Tokens.Hash(token), (object?)groupId ?? DBNull.Value, days,
            (object?)previousId ?? DBNull.Value, (object?)overlapHours ?? DBNull.Value, (object?)maxRedemptions ?? DBNull.Value,
            (object?)identity.Access?.Id ?? DBNull.Value))
            await insert.ExecuteNonQueryAsync(ct);
        await transaction.CommitAsync(ct);
        return new(new((await FindEnrollmentKey(organizationId, id, ct))!, token));
    }

    public async Task<bool> RevokeEnrollmentKey(RequestIdentity identity, Guid id, CancellationToken ct)
    {
        await using var command = Command("""
            WITH revoked AS (
                UPDATE enrollment_keys SET revoked_at = now()
                WHERE organization_id = $1 AND id = $2 AND revoked_at IS NULL
                RETURNING organization_id, id, label, policy_group_id, redeemed, max_redemptions, revoked_at
            ), audit AS (
                INSERT INTO control_audit (organization_id, occurred_at, action, actor_access_id, enrollment_key_change)
                SELECT r.organization_id, r.revoked_at, 'enrollment_key_revoked', $3, jsonb_strip_nulls(jsonb_build_object(
                    'keyId', r.id, 'label', r.label, 'groupId', r.policy_group_id, 'groupName', g.name,
                    'redeemed', r.redeemed, 'maxRedemptions', r.max_redemptions))
                FROM revoked r LEFT JOIN policy_groups g ON g.organization_id = r.organization_id AND g.id = r.policy_group_id
            )
            SELECT EXISTS (SELECT 1 FROM enrollment_keys WHERE organization_id = $1 AND id = $2)
            """, identity.OrganizationId, id, (object?)identity.Access?.Id ?? DBNull.Value);
        return (bool)(await command.ExecuteScalarAsync(ct))!;
    }

    public async Task<bool> EnrollmentKeyExists(Guid organizationId, Guid id, CancellationToken ct)
    {
        await using var command = Command("SELECT EXISTS (SELECT 1 FROM enrollment_keys WHERE organization_id = $1 AND id = $2)", organizationId, id);
        return (bool)(await command.ExecuteScalarAsync(ct))!;
    }

    // Each profile sends its own random nonce. The key row lock serializes redemptions, so the seat count
    // cannot exceed the maximum, and a retried nonce reuses its installation and seat instead of taking another.
    public async Task<EnrollmentKeyRedemption> RedeemEnrollmentKey(string key, string nonce, CancellationToken ct)
    {
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        Guid organizationId, keyId;
        Guid? groupId;
        string label;
        string? groupName;
        bool revoked, expired;
        int? maxRedemptions;
        int redeemed;
        await using (var locked = BrowserRead(transaction, """
            SELECT k.organization_id, k.id, k.label, k.policy_group_id, g.name, k.revoked_at IS NOT NULL, k.expires_at <= now(),
                k.max_redemptions, k.redeemed
            FROM enrollment_keys k LEFT JOIN policy_groups g ON g.organization_id = k.organization_id AND g.id = k.policy_group_id
            WHERE k.token_hash = $1 AND NOT organization_offboarding(k.organization_id) FOR UPDATE OF k
            """, Tokens.Hash(key)))
        await using (var row = await locked.ExecuteReaderAsync(ct))
        {
            if (!await row.ReadAsync(ct)) return new(Error: "enrollment_key_invalid");
            (organizationId, keyId, label) = (row.GetGuid(0), row.GetGuid(1), row.GetString(2));
            groupId = row.IsDBNull(3) ? null : row.GetGuid(3);
            groupName = row.IsDBNull(4) ? null : row.GetString(4);
            (revoked, expired) = (row.GetBoolean(5), row.GetBoolean(6));
            maxRedemptions = row.IsDBNull(7) ? null : row.GetInt32(7);
            redeemed = row.GetInt32(8);
        }

        async Task<EnrollmentKeyRedemption> Reject(string error, int retryAfter = 0)
        {
            await using var count = BrowserRead(transaction, """
                UPDATE enrollment_keys SET rejected = rejected + 1, last_rejected_at = now() WHERE organization_id = $1 AND id = $2
                """, organizationId, keyId);
            await count.ExecuteNonQueryAsync(ct);
            await transaction.CommitAsync(ct);
            return new(Error: error, RetryAfterSeconds: retryAfter);
        }

        if (revoked) return await Reject("enrollment_key_revoked");
        if (expired) return await Reject("enrollment_key_expired");
        await using (var window = BrowserRead(transaction, """
            UPDATE enrollment_keys SET
                attempt_window_started_at = CASE WHEN attempt_window_started_at IS NULL OR attempt_window_started_at <= now() - interval '1 minute'
                    THEN now() ELSE attempt_window_started_at END,
                attempt_window_count = CASE WHEN attempt_window_started_at IS NULL OR attempt_window_started_at <= now() - interval '1 minute'
                    THEN 1 ELSE attempt_window_count + 1 END
            WHERE organization_id = $1 AND id = $2
            -- A transaction that waited for the row lock can start before the window it joins, so clamp the hint.
            RETURNING attempt_window_count,
                LEAST(60, GREATEST(1, ceil(extract(epoch FROM attempt_window_started_at + interval '1 minute' - now()))))::integer
            """, organizationId, keyId))
        {
            int attempts, retryAfter;
            await using (var row = await window.ExecuteReaderAsync(ct))
            {
                await row.ReadAsync(ct);
                (attempts, retryAfter) = (row.GetInt32(0), row.GetInt32(1));
            }
            if (attempts > EnrollmentKeyAttemptsPerMinute) return await Reject("enrollment_key_rate_limited", retryAfter);
        }

        var nonceHash = Tokens.Hash(nonce);
        var token = Tokens.Generate();
        await using (var replay = BrowserRead(transaction, """
            SELECT r.installation_id, i.revoked_at IS NOT NULL FROM enrollment_key_redemptions r
            JOIN installations i ON i.organization_id = r.organization_id AND i.id = r.installation_id
            WHERE r.organization_id = $1 AND r.key_id = $2 AND r.nonce_hash = $3 FOR UPDATE OF i
            """, organizationId, keyId, nonceHash))
        {
            Guid? existing = null;
            bool existingRevoked = false, neverContacted = false;
            await using (var row = await replay.ExecuteReaderAsync(ct))
                if (await row.ReadAsync(ct)) (existing, existingRevoked, neverContacted) = (row.GetGuid(0), row.GetBoolean(1), row.GetBoolean(2));
            if (existing is { } installationId)
            {
                if (existingRevoked) return await Reject("installation_revoked");
                // Only an installation that has never contacted Control can still be waiting for its first response. Once it has used
                // its credential, a repeated nonce must not replace it: anyone holding the key and a seen nonce could take it over.
                if (!neverContacted) return await Reject("installation_exists");
                // The profile never received the earlier credential. Replace it so only this response's token works.
                await using var reissue = BrowserRead(transaction, "UPDATE installations SET token_hash = $2 WHERE id = $1",
                    installationId, Tokens.Hash(token));
                await reissue.ExecuteNonQueryAsync(ct);
                await transaction.CommitAsync(ct);
                return new(new(installationId, token));
            }
        }

        if (maxRedemptions is { } max && redeemed >= max) return await Reject("enrollment_key_exhausted");
        var installation = Guid.NewGuid();
        await using (var enroll = BrowserRead(transaction, """
            WITH enrolled AS (
                INSERT INTO installations (id, organization_id, token_hash, policy_group_id, assignment_version, assignment_aware)
                VALUES ($3, $1, $4, $5, CASE WHEN $5::uuid IS NULL THEN 0 ELSE 1 END, $5::uuid IS NOT NULL)
                RETURNING organization_id, id, enrolled_at
            ), redemption AS (
                INSERT INTO enrollment_key_redemptions (organization_id, key_id, nonce_hash, installation_id, redeemed_at)
                SELECT organization_id, $2, $6, id, enrolled_at FROM enrolled
            ), counted AS (
                UPDATE enrollment_keys SET redeemed = redeemed + 1, last_redeemed_at = now()
                WHERE organization_id = $1 AND id = $2 RETURNING redeemed, max_redemptions
            )
            INSERT INTO control_audit (organization_id, occurred_at, action, installation_id, enrollment_key_change)
            SELECT e.organization_id, e.enrolled_at, 'browser_enrolled', e.id, jsonb_strip_nulls(jsonb_build_object('keyId', $2::uuid,
                'label', $7::text, 'groupId', $5::uuid, 'groupName', $8::text, 'redeemed', c.redeemed, 'maxRedemptions', c.max_redemptions))
            FROM enrolled e CROSS JOIN counted c
            """, organizationId, keyId, installation, Tokens.Hash(token), (object?)groupId ?? DBNull.Value, nonceHash, label,
            (object?)groupName ?? DBNull.Value))
            await enroll.ExecuteNonQueryAsync(ct);
        await transaction.CommitAsync(ct);
        return new(new(installation, token));
    }

    private static EnrollmentKey ReadEnrollmentKey(NpgsqlDataReader rows) => new(rows.GetGuid(0), rows.GetString(1),
        rows.IsDBNull(2) ? null : rows.GetGuid(2), rows.IsDBNull(3) ? null : rows.GetString(3), rows.GetDateTime(4), rows.GetDateTime(5),
        rows.IsDBNull(6) ? null : rows.GetInt32(6), rows.GetInt32(7), rows.GetInt32(8), rows.IsDBNull(9) ? null : rows.GetDateTime(9),
        rows.GetInt32(10), rows.IsDBNull(11) ? null : rows.GetDateTime(11), rows.IsDBNull(12) ? null : rows.GetDateTime(12),
        rows.IsDBNull(13) ? null : rows.GetGuid(13), rows.GetString(14));
}
