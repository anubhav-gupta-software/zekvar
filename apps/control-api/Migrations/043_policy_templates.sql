CREATE TABLE policy_templates (
    organization_id uuid NOT NULL REFERENCES organizations(id),
    id uuid NOT NULL,
    name text NOT NULL CHECK (char_length(name) BETWEEN 2 AND 64),
    current_revision integer NOT NULL DEFAULT 1 CHECK (current_revision > 0),
    archived_at timestamptz,
    PRIMARY KEY (organization_id, id)
);
CREATE UNIQUE INDEX policy_templates_active_name ON policy_templates (organization_id, lower(name)) WHERE archived_at IS NULL;

CREATE TABLE policy_template_revisions (
    organization_id uuid NOT NULL,
    template_id uuid NOT NULL,
    revision integer NOT NULL CHECK (revision > 0),
    source_version integer NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, template_id, revision),
    FOREIGN KEY (organization_id, template_id) REFERENCES policy_templates (organization_id, id),
    FOREIGN KEY (organization_id, source_version) REFERENCES policy_versions (organization_id, version)
);

ALTER TABLE control_audit ADD COLUMN template_change jsonb CHECK (jsonb_typeof(template_change) = 'object'),
    ADD CONSTRAINT control_audit_template_record_check CHECK ((action = 'policy_template_changed') = (template_change IS NOT NULL)),
    DROP CONSTRAINT control_audit_action_check,
    ADD CONSTRAINT control_audit_action_check CHECK (action IN ('policy_published', 'policy_restored', 'grant_issued',
        'browser_enrolled', 'browser_revoked', 'app_classified', 'retention_changed', 'retention_cleanup',
        'policy_group_created', 'policy_group_assigned', 'access_issued', 'access_revoked', 'control_sso_signed_in',
        'policy_review_setting_changed', 'policy_review_requested', 'policy_review_decided', 'enrollment_batch_issued',
        'enrollment_batch_cancelled', 'event_triage_changed', 'incident_case_changed', 'security_alert_settings_changed',
        'security_alert_acknowledged', 'event_feed_key_issued', 'event_feed_key_revoked', 'browser_fleet_changed', 'policy_template_changed'));
