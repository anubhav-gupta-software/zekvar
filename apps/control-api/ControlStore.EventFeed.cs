using System.Data;
using Npgsql;

namespace Control;

internal sealed partial class ControlStore
{
    public async Task<IReadOnlyList<EventFeedKey>> ListEventFeedKeys(Guid organizationId, CancellationToken ct)
    {
        await using var command = Command("""
            SELECT id, display_name, issued_at, expires_at,
                CASE WHEN revoked_at IS NOT NULL THEN 'revoked' WHEN expires_at <= now() THEN 'expired' ELSE 'active' END AS status
            FROM event_feed_keys WHERE organization_id = $1
            ORDER BY (revoked_at IS NULL AND expires_at > now()) DESC, issued_at DESC, id DESC LIMIT 100
            """, organizationId);
        var keys = new List<EventFeedKey>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct)) keys.Add(ReadEventFeedKey(rows));
        return keys;
    }

    public async Task<EventFeedKeyOutcome> IssueEventFeedKey(Guid organizationId, Guid id, string name, int days, CancellationToken ct)
    {
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        // Serialize issuance per tenant without holding the event ingestion counter lock.
        await using var tenant = BrowserRead(transaction, "SELECT id FROM organizations WHERE id = $1 FOR NO KEY UPDATE", organizationId);
        await tenant.ExecuteScalarAsync(ct);
        await using var capacity = BrowserRead(transaction, """
            SELECT CASE WHEN EXISTS (SELECT 1 FROM event_feed_keys WHERE organization_id = $1 AND id = $2) THEN 'event_feed_key_exists'
                WHEN (SELECT count(*) FROM event_feed_keys WHERE organization_id = $1 AND revoked_at IS NULL AND expires_at > now()) >= 20
                THEN 'event_feed_key_limit' END
            """, organizationId, id);
        if (await capacity.ExecuteScalarAsync(ct) is string error) return new(Error: error);

        var token = EventFeedToken.Generate();
        await using var insert = BrowserRead(transaction, """
            WITH issued AS (
                INSERT INTO event_feed_keys (organization_id, id, display_name, token_hash, expires_at)
                VALUES ($1, $2, $3, $4, statement_timestamp() + $5 * interval '24 hours')
                RETURNING organization_id, id, display_name, issued_at, expires_at
            ), audit AS (
                INSERT INTO control_audit (organization_id, occurred_at, action, event_feed_key_change)
                SELECT organization_id, issued_at, 'event_feed_key_issued',
                    jsonb_build_object('keyId', id, 'name', display_name, 'expiresAt', expires_at) FROM issued
            )
            SELECT id, display_name, issued_at, expires_at, 'active' FROM issued
            """, organizationId, id, name, Tokens.Hash(token), days);
        EventFeedKey key;
        await using (var rows = await insert.ExecuteReaderAsync(ct))
        {
            await rows.ReadAsync(ct);
            key = ReadEventFeedKey(rows);
        }
        await transaction.CommitAsync(ct);
        return new(new(key, token));
    }

    public async Task<bool> RevokeEventFeedKey(Guid organizationId, Guid id, CancellationToken ct)
    {
        await using var command = Command("""
            WITH revoked AS (
                UPDATE event_feed_keys SET revoked_at = now(), token_hash = NULL
                WHERE organization_id = $1 AND id = $2 AND revoked_at IS NULL
                RETURNING organization_id, id, display_name, revoked_at
            ), audit AS (
                INSERT INTO control_audit (organization_id, occurred_at, action, event_feed_key_change)
                SELECT organization_id, revoked_at, 'event_feed_key_revoked', jsonb_build_object('keyId', id, 'name', display_name) FROM revoked
            )
            SELECT EXISTS (SELECT 1 FROM event_feed_keys WHERE organization_id = $1 AND id = $2)
            """, organizationId, id);
        return (bool)(await command.ExecuteScalarAsync(ct))!;
    }

    public async Task<EventFeedRead> ReadEventFeed(string token, EventFeedCursor? after, int limit, CancellationToken ct)
    {
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var snapshot = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        await using var stream = BrowserRead(snapshot, """
            SELECT s.organization_id, s.stream_id, s.last_sequence, k.id
            FROM event_feed_keys k JOIN organization_event_streams s USING (organization_id)
            WHERE k.token_hash = $1 AND k.revoked_at IS NULL AND k.expires_at > now() AND NOT organization_offboarding(k.organization_id)
            """, Tokens.Hash(token));
        Guid organizationId;
        Guid streamId;
        long head;
        Guid keyId;
        await using (var cursor = await stream.ExecuteReaderAsync(ct))
        {
            if (!await cursor.ReadAsync(ct)) return new(false);
            organizationId = cursor.GetGuid(0);
            streamId = cursor.GetGuid(1);
            head = cursor.GetInt64(2);
            keyId = cursor.GetGuid(3);
        }
        if (after is { } checkpoint && (checkpoint.StreamId != streamId || checkpoint.Sequence > head))
        {
            await RecordFeedAccess(organizationId, keyId, 0, ct);
            return new(true);
        }

        await using var command = BrowserRead(snapshot, $"""
            SELECT e.event_id, e.installation_id, e.occurred_at, e.received_at, e.policy_version,
                e.app_id, e.rule_id, e.decision, e.rollout_attributed, e.rollout_group_id, e.upload_method, e.stream_sequence, e.clipboard_paste
            FROM security_events e LEFT JOIN retention_cutoffs r ON r.organization_id = e.organization_id
            WHERE e.organization_id = $1 AND e.stream_sequence > $2 AND e.stream_sequence <= $3 AND {EventRetained}
            ORDER BY e.stream_sequence LIMIT $4
            """, organizationId, after?.Sequence ?? 0, head, limit + 1);
        var entries = new List<EventFeedEntry>(limit);
        var next = head;
        var lastRead = after?.Sequence ?? 0;
        var hasMore = false;
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct))
        {
            if (entries.Count == limit)
            {
                next = lastRead;
                hasMore = true;
                break;
            }
            var rollout = !rows.GetBoolean(8) ? new EventRollout("unattributed")
                : rows.IsDBNull(9) ? new("baseline") : new("group", rows.GetGuid(9));
            entries.Add(new(rows.GetGuid(0), rows.GetGuid(1), rows.GetDateTime(2), rows.GetDateTime(3), rows.GetInt32(4),
                rows.GetString(5), rows.GetString(6), rows.GetString(7), rollout, rows.IsDBNull(10) ? null : rows.GetString(10), rows.GetBoolean(12)));
            lastRead = rows.GetInt64(11);
        }
        await rows.DisposeAsync();
        await snapshot.CommitAsync(ct);
        await RecordFeedAccess(organizationId, keyId, entries.Count, ct);
        return new(true, new(1, entries, new EventFeedCursor(streamId, next).ToString(), hasMore));
    }

    // SIEM collectors poll often, so reads are summarized per key per UTC hour with request and record counts.
    private async Task RecordFeedAccess(Guid organizationId, Guid keyId, long records, CancellationToken ct)
    {
        await RecordFeedRead(organizationId, keyId, records, ct);
        await using var touch = Command("""
            UPDATE event_feed_keys SET last_used_at = statement_timestamp()
            WHERE organization_id = $1 AND id = $2 AND (last_used_at IS NULL OR last_used_at < statement_timestamp() - interval '1 minute')
            """, organizationId, keyId);
        await touch.ExecuteNonQueryAsync(ct);
    }

    private static EventFeedKey ReadEventFeedKey(NpgsqlDataReader rows) =>
        new(rows.GetGuid(0), rows.GetString(1), rows.GetDateTime(2), rows.GetDateTime(3), rows.GetString(4));
}
