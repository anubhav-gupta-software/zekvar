using Npgsql;

namespace Control;

internal sealed partial class ControlStore
{
    public async Task<ClaimedAlertWebhook?> ClaimAlertWebhook(CancellationToken ct)
    {
        await using var command = Command($"""
            WITH due AS (
                SELECT d.organization_id, d.id, o.slug, a.id AS alert_id, a.app_id, a.rollout_attributed,
                    a.rollout_group_id, a.window_start, a.triggered_at, a.threshold
                FROM alert_webhook_deliveries d
                JOIN security_alert_windows a ON a.organization_id = d.organization_id AND a.id = d.alert_id
                JOIN organizations o ON o.id = d.organization_id
                LEFT JOIN retention_cutoffs r ON r.organization_id = d.organization_id
                WHERE d.status = 'pending' AND d.available_at <= now() AND (d.lease_until IS NULL OR d.lease_until <= now())
                  AND $1::jsonb ->> o.slug = d.route_fingerprint AND {AlertVisible}
                  AND NOT organization_offboarding(d.organization_id)
                ORDER BY d.available_at, d.id LIMIT 1 FOR UPDATE OF d SKIP LOCKED
            ), claimed AS (
                UPDATE alert_webhook_deliveries d SET attempts = LEAST(d.attempts + 1, $2),
                    lease_id = CASE WHEN d.attempts < $2 THEN gen_random_uuid() END,
                    lease_until = CASE WHEN d.attempts < $2 THEN now() + interval '30 seconds' END,
                    status = CASE WHEN d.attempts >= $2 THEN 'failed' ELSE d.status END,
                    failure_code = CASE WHEN d.attempts >= $2 THEN 'delivery_unconfirmed' END,
                    last_http_status = NULL,
                    last_attempt_at = CASE WHEN d.attempts < $2 THEN now() ELSE d.last_attempt_at END
                FROM due
                WHERE d.organization_id = due.organization_id AND d.id = due.id
                RETURNING d.organization_id, d.lease_id, d.route_fingerprint, d.attempts, d.id, due.slug, due.alert_id,
                    due.app_id, due.rollout_attributed, due.rollout_group_id, due.window_start, due.triggered_at, due.threshold
            )
            SELECT * FROM claimed WHERE lease_id IS NOT NULL
            """, alertWebhooks.Routing, AlertWebhookDispatcher.MaxAttempts);
        await using var rows = await command.ExecuteReaderAsync(ct);
        if (!await rows.ReadAsync(ct)) return null;
        var groupId = rows.IsDBNull(9) ? (Guid?)null : rows.GetGuid(9);
        var rollout = !rows.GetBoolean(8) ? "unattributed" : groupId.HasValue ? "group" : "baseline";
        var window = rows.GetDateTime(10);
        var payload = new AlertWebhookPayload(1, "security.alert.opened", rows.GetGuid(4), rows.GetString(5),
            rows.GetGuid(6), rows.GetString(7), rollout, groupId, window, window.AddMinutes(15), rows.GetDateTime(11), rows.GetInt32(12));
        return new(rows.GetGuid(0), rows.GetGuid(1), rows.GetString(2), rows.GetInt32(3), payload);
    }

    public async Task FinishAlertWebhook(ClaimedAlertWebhook job, AlertWebhookOutcome outcome, CancellationToken ct)
    {
        var succeeded = outcome.FailureCode is null;
        var retry = outcome.Retryable && job.Attempt < AlertWebhookDispatcher.MaxAttempts;
        var status = succeeded ? "sent" : retry ? "pending" : "failed";
        var backoff = retry ? TimeSpan.FromSeconds(15 * (1 << (job.Attempt - 1))) : TimeSpan.Zero;
        if (retry && outcome.RetryAfter is { } requested && requested > backoff)
            backoff = requested > TimeSpan.FromHours(1) ? TimeSpan.FromHours(1) : requested;
        await using var command = Command("""
            UPDATE alert_webhook_deliveries SET status = $4, failure_code = $5::text, last_http_status = $6::integer,
                available_at = now() + $7::interval, sent_at = CASE WHEN $4 = 'sent' THEN now() END,
                lease_id = NULL, lease_until = NULL
            WHERE organization_id = $1 AND id = $2 AND lease_id = $3 AND status = 'pending'
            """, job.OrganizationId, job.Payload.DeliveryId, job.LeaseId, status, (object?)outcome.FailureCode ?? DBNull.Value,
            (object?)outcome.HttpStatus ?? DBNull.Value, backoff);
        await command.ExecuteNonQueryAsync(ct);
    }

    private async Task<AlertWebhookDelivery?> ReadAlertWebhook(NpgsqlTransaction snapshot, Guid organizationId, Guid alertId, CancellationToken ct)
    {
        await using var command = BrowserRead(snapshot, """
            SELECT d.status, d.attempts, d.last_attempt_at, d.available_at, d.sent_at, d.failure_code, d.last_http_status,
                d.lease_until > now(), o.slug, d.route_fingerprint
            FROM alert_webhook_deliveries d JOIN organizations o ON o.id = d.organization_id
            WHERE d.organization_id = $1 AND d.alert_id = $2
            """, organizationId, alertId);
        await using var rows = await command.ExecuteReaderAsync(ct);
        if (!await rows.ReadAsync(ct)) return null;
        var status = rows.GetString(0);
        var attempts = rows.GetInt32(1);
        if (status == "pending")
            status = alertWebhooks.Find(rows.GetString(8), rows.GetString(9)) is null ? "paused"
                : !rows.IsDBNull(7) && rows.GetBoolean(7) ? "sending" : attempts == 0 ? "queued" : "retrying";
        return new(status, attempts, rows.IsDBNull(2) ? null : rows.GetDateTime(2),
            status is "queued" or "retrying" ? rows.GetDateTime(3) : null, rows.IsDBNull(4) ? null : rows.GetDateTime(4),
            rows.IsDBNull(5) ? null : rows.GetString(5), rows.IsDBNull(6) ? null : rows.GetInt32(6));
    }
}
