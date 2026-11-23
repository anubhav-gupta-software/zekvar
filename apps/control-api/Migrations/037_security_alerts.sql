CREATE TABLE security_alert_settings (
    organization_id uuid PRIMARY KEY REFERENCES organizations(id),
    enabled boolean NOT NULL DEFAULT false,
    threshold integer NOT NULL DEFAULT 5 CHECK (threshold BETWEEN 2 AND 100),
    revision integer NOT NULL DEFAULT 0 CHECK (revision >= 0)
);

CREATE TABLE security_alert_windows (
    organization_id uuid NOT NULL REFERENCES organizations(id),
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    setting_revision integer NOT NULL CHECK (setting_revision >= 1),
    app_id text NOT NULL CHECK (app_id IN ('chatgpt', 'gemini', 'claude')),
    rollout_group_id uuid,
    rollout_attributed boolean NOT NULL,
    window_start timestamptz NOT NULL,
    first_received_at timestamptz NOT NULL,
    threshold integer NOT NULL CHECK (threshold BETWEEN 2 AND 100),
    block_count bigint NOT NULL DEFAULT 1 CHECK (block_count >= 1),
    triggered_at timestamptz,
    acknowledged_at timestamptz,
    PRIMARY KEY (organization_id, id),
    UNIQUE NULLS NOT DISTINCT (organization_id, setting_revision, app_id, rollout_group_id, rollout_attributed, window_start),
    FOREIGN KEY (organization_id, rollout_group_id) REFERENCES policy_groups (organization_id, id),
    CHECK (rollout_attributed OR rollout_group_id IS NULL),
    CHECK ((triggered_at IS NOT NULL) = (block_count >= threshold)),
    CHECK (acknowledged_at IS NULL OR triggered_at IS NOT NULL)
);
CREATE INDEX security_alert_inbox ON security_alert_windows (organization_id, triggered_at DESC, id DESC) WHERE triggered_at IS NOT NULL;
CREATE INDEX security_alert_expiry ON security_alert_windows (first_received_at, organization_id);
CREATE INDEX security_alert_incomplete ON security_alert_windows (window_start, organization_id) WHERE triggered_at IS NULL;

CREATE TABLE security_alert_events (
    organization_id uuid NOT NULL,
    alert_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    event_id uuid NOT NULL,
    PRIMARY KEY (installation_id, event_id),
    FOREIGN KEY (organization_id, installation_id) REFERENCES installations (organization_id, id),
    FOREIGN KEY (installation_id, event_id) REFERENCES security_events (installation_id, event_id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, alert_id) REFERENCES security_alert_windows (organization_id, id) ON DELETE CASCADE
);
CREATE INDEX security_alert_event_members ON security_alert_events (organization_id, alert_id);

ALTER TABLE control_audit ADD COLUMN security_alert_change jsonb CHECK (jsonb_typeof(security_alert_change) = 'object'),
    ADD CHECK ((action IN ('security_alert_settings_changed', 'security_alert_acknowledged')) = (security_alert_change IS NOT NULL)),
    DROP CONSTRAINT control_audit_action_check,
    ADD CONSTRAINT control_audit_action_check CHECK (action IN ('policy_published', 'policy_restored', 'grant_issued',
        'browser_enrolled', 'browser_revoked', 'app_classified', 'retention_changed', 'retention_cleanup',
        'policy_group_created', 'policy_group_assigned', 'access_issued', 'access_revoked', 'control_sso_signed_in',
        'policy_review_setting_changed', 'policy_review_requested', 'policy_review_decided', 'enrollment_batch_issued',
        'enrollment_batch_cancelled', 'event_triage_changed', 'incident_case_changed', 'security_alert_settings_changed',
        'security_alert_acknowledged'));
