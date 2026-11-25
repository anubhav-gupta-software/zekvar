CREATE TABLE rollout_plans (
    organization_id uuid NOT NULL REFERENCES organizations(id),
    id uuid NOT NULL,
    name text NOT NULL CHECK (char_length(name) BETWEEN 2 AND 64),
    source_version integer NOT NULL,
    status text NOT NULL CHECK (status IN ('pending_review', 'running', 'paused', 'completed', 'rolled_back',
        'cancelled', 'rejected', 'withdrawn')),
    stage_count integer NOT NULL CHECK (stage_count BETWEEN 1 AND 5),
    current_stage integer NOT NULL DEFAULT 0 CHECK (current_stage >= 0),
    revision integer NOT NULL DEFAULT 1 CHECK (revision >= 1),
    requires_review boolean NOT NULL,
    created_by uuid,
    approved_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL DEFAULT now() + interval '24 hours',
    decided_at timestamptz,
    evaluated_at timestamptz,
    pause_reason text CHECK (pause_reason IN ('paused_by_administrator', 'acknowledgment_below_threshold',
        'composer_readiness_incomplete', 'no_active_browsers', 'block_events_exceeded', 'warn_override_rate_exceeded',
        'target_changed', 'approver_inactive', 'review_mode_changed')),
    gate jsonb CHECK (jsonb_typeof(gate) = 'object'),
    finished_at timestamptz,
    PRIMARY KEY (organization_id, id),
    FOREIGN KEY (organization_id, source_version) REFERENCES policy_versions(organization_id, version),
    FOREIGN KEY (organization_id, created_by) REFERENCES control_access(organization_id, id),
    FOREIGN KEY (organization_id, approved_by) REFERENCES control_access(organization_id, id),
    CHECK (current_stage < stage_count),
    CHECK ((status = 'paused') = (pause_reason IS NOT NULL)),
    CHECK (NOT requires_review OR created_by IS NOT NULL),
    CHECK (status NOT IN ('running', 'completed') OR NOT requires_review OR approved_by IS NOT NULL),
    CHECK ((status = 'pending_review') = (decided_at IS NULL))
);
CREATE INDEX rollout_plans_by_organization ON rollout_plans (organization_id, created_at DESC, id DESC);
CREATE INDEX rollout_plans_running ON rollout_plans (evaluated_at NULLS FIRST, organization_id) WHERE status = 'running';

CREATE TABLE rollout_stages (
    organization_id uuid NOT NULL,
    plan_id uuid NOT NULL,
    position integer NOT NULL CHECK (position BETWEEN 0 AND 4),
    group_id uuid,
    min_soak_seconds integer NOT NULL CHECK (min_soak_seconds BETWEEN 0 AND 604800),
    min_acknowledged_percent integer NOT NULL CHECK (min_acknowledged_percent BETWEEN 0 AND 100),
    require_composer_ready text[] NOT NULL DEFAULT '{}'
        CHECK (require_composer_ready <@ ARRAY['chatgpt', 'claude', 'gemini']::text[]),
    max_block_events integer CHECK (max_block_events BETWEEN 0 AND 100000),
    max_warn_override_percent integer CHECK (max_warn_override_percent BETWEEN 0 AND 100),
    prior_version integer,
    published_version integer,
    published_at timestamptz,
    rollback_version integer,
    rollback_outcome text CHECK (rollback_outcome IN ('restored', 'changed')),
    PRIMARY KEY (organization_id, plan_id, position),
    UNIQUE NULLS NOT DISTINCT (organization_id, plan_id, group_id),
    FOREIGN KEY (organization_id, plan_id) REFERENCES rollout_plans(organization_id, id),
    FOREIGN KEY (organization_id, group_id) REFERENCES policy_groups(organization_id, id),
    FOREIGN KEY (organization_id, prior_version) REFERENCES policy_versions(organization_id, version),
    FOREIGN KEY (organization_id, published_version) REFERENCES policy_versions(organization_id, version),
    FOREIGN KEY (organization_id, rollback_version) REFERENCES policy_versions(organization_id, version),
    CHECK ((published_version IS NULL) = (published_at IS NULL) AND (published_version IS NULL) = (prior_version IS NULL)),
    CHECK (rollback_version IS NULL OR rollback_outcome = 'restored'),
    CHECK (rollback_outcome IS NULL OR published_version IS NOT NULL)
);
-- Each policy version is published by at most one rollout stage.
CREATE UNIQUE INDEX rollout_stage_publication ON rollout_stages (organization_id, published_version) WHERE published_version IS NOT NULL;

ALTER TABLE control_audit ADD COLUMN rollout_change jsonb CHECK (jsonb_typeof(rollout_change) = 'object'),
    DROP CONSTRAINT control_audit_action_check,
    ADD CONSTRAINT control_audit_action_check CHECK (action IN ('policy_published', 'policy_restored', 'grant_issued',
        'browser_enrolled', 'browser_revoked', 'app_classified', 'retention_changed', 'retention_cleanup',
        'policy_group_created', 'policy_group_assigned', 'access_issued', 'access_revoked', 'control_sso_signed_in',
        'policy_review_setting_changed', 'policy_review_requested', 'policy_review_decided', 'enrollment_batch_issued',
        'enrollment_batch_cancelled', 'event_triage_changed', 'incident_case_changed', 'security_alert_settings_changed',
        'security_alert_acknowledged', 'event_feed_key_issued', 'event_feed_key_revoked', 'browser_fleet_changed', 'policy_template_changed',
        'rollout_plan_changed')),
    ADD CONSTRAINT control_audit_rollout_record_check CHECK (
        (action <> 'rollout_plan_changed' OR rollout_change IS NOT NULL) AND
        (rollout_change IS NULL OR action IN ('rollout_plan_changed', 'policy_published', 'policy_restored')));
