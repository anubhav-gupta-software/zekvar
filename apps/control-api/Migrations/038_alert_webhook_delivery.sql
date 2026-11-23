CREATE TABLE alert_webhook_deliveries (
    organization_id uuid NOT NULL,
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    alert_id uuid NOT NULL,
    route_fingerprint text NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 6),
    available_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    lease_id uuid,
    lease_until timestamptz,
    last_attempt_at timestamptz,
    sent_at timestamptz,
    failure_code text CHECK (failure_code IN ('http_status', 'network_error', 'request_timeout', 'delivery_unconfirmed', 'recovery_cancelled')),
    last_http_status integer CHECK (last_http_status BETWEEN 200 AND 599),
    PRIMARY KEY (organization_id, id),
    UNIQUE (organization_id, alert_id),
    FOREIGN KEY (organization_id, alert_id) REFERENCES security_alert_windows (organization_id, id) ON DELETE CASCADE,
    CHECK ((status = 'sent') = (sent_at IS NOT NULL)),
    CHECK ((lease_id IS NULL) = (lease_until IS NULL)),
    CHECK (status = 'pending' OR lease_id IS NULL)
);
CREATE INDEX alert_webhook_deliveries_due ON alert_webhook_deliveries (available_at, id) WHERE status = 'pending';
