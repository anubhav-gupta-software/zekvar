-- Device-manager enrollment keys: one scoped, expiring, revocable key that many Chrome profiles redeem.
CREATE TABLE enrollment_keys (
    organization_id uuid NOT NULL REFERENCES organizations(id),
    id uuid NOT NULL,
    label text NOT NULL CHECK (char_length(label) BETWEEN 2 AND 64),
    token_hash text NOT NULL UNIQUE,
    policy_group_id uuid,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
    max_redemptions integer CHECK (max_redemptions BETWEEN 1 AND 100000),
    redeemed integer NOT NULL DEFAULT 0 CHECK (redeemed >= 0 AND (max_redemptions IS NULL OR redeemed <= max_redemptions)),
    last_redeemed_at timestamptz,
    rejected integer NOT NULL DEFAULT 0 CHECK (rejected >= 0),
    last_rejected_at timestamptz,
    revoked_at timestamptz,
    rotated_from uuid,
    attempt_window_started_at timestamptz,
    attempt_window_count integer NOT NULL DEFAULT 0 CHECK (attempt_window_count >= 0),
    PRIMARY KEY (organization_id, id),
    FOREIGN KEY (organization_id, policy_group_id) REFERENCES policy_groups (organization_id, id),
    FOREIGN KEY (organization_id, rotated_from) REFERENCES enrollment_keys (organization_id, id)
);
CREATE INDEX enrollment_keys_by_organization ON enrollment_keys (organization_id, created_at DESC, id DESC);

-- One row per profile nonce. The primary key makes a retried redemption reuse its installation and seat.
CREATE TABLE enrollment_key_redemptions (
    organization_id uuid NOT NULL,
    key_id uuid NOT NULL,
    nonce_hash text NOT NULL,
    installation_id uuid NOT NULL UNIQUE,
    redeemed_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (organization_id, key_id, nonce_hash),
    FOREIGN KEY (organization_id, key_id) REFERENCES enrollment_keys (organization_id, id),
    FOREIGN KEY (organization_id, installation_id) REFERENCES installations (organization_id, id)
);
CREATE INDEX enrollment_key_redemptions_by_key ON enrollment_key_redemptions (organization_id, key_id, installation_id);

ALTER TABLE control_audit ADD COLUMN enrollment_key_change jsonb CHECK (jsonb_typeof(enrollment_key_change) = 'object'),
    ADD CONSTRAINT control_audit_enrollment_key_check CHECK (
        (action NOT IN ('enrollment_key_issued', 'enrollment_key_revoked') OR enrollment_key_change IS NOT NULL) AND
        (enrollment_key_change IS NULL OR action IN ('enrollment_key_issued', 'enrollment_key_revoked', 'browser_enrolled'))),
    DROP CONSTRAINT control_audit_action_check,
    ADD CONSTRAINT control_audit_action_check CHECK (action IN ('policy_published', 'policy_restored', 'grant_issued',
        'browser_enrolled', 'browser_revoked', 'app_classified', 'retention_changed', 'retention_cleanup',
        'policy_group_created', 'policy_group_assigned', 'access_issued', 'access_revoked', 'control_sso_signed_in',
        'policy_review_setting_changed', 'policy_review_requested', 'policy_review_decided', 'enrollment_batch_issued',
        'enrollment_batch_cancelled', 'event_triage_changed', 'incident_case_changed', 'security_alert_settings_changed',
        'security_alert_acknowledged', 'event_feed_key_issued', 'event_feed_key_revoked', 'browser_fleet_changed', 'policy_template_changed',
        'rollout_plan_changed', 'enrollment_key_issued', 'enrollment_key_revoked'));
