CREATE INDEX installations_active_fleet_page ON installations (organization_id, enrolled_at DESC, id DESC) WHERE revoked_at IS NULL;

ALTER TABLE control_audit ADD COLUMN fleet_change jsonb CHECK (jsonb_typeof(fleet_change) = 'object'),
    ADD COLUMN fleet_request_hash text,
    ADD CONSTRAINT control_audit_fleet_receipt_check CHECK (
        (action = 'browser_fleet_changed') = (fleet_change IS NOT NULL) AND (fleet_change IS NULL) = (fleet_request_hash IS NULL)
    ),
    DROP CONSTRAINT control_audit_action_check,
    ADD CONSTRAINT control_audit_action_check CHECK (action IN ('policy_published', 'policy_restored', 'grant_issued',
        'browser_enrolled', 'browser_revoked', 'app_classified', 'retention_changed', 'retention_cleanup',
        'policy_group_created', 'policy_group_assigned', 'access_issued', 'access_revoked', 'control_sso_signed_in',
        'policy_review_setting_changed', 'policy_review_requested', 'policy_review_decided', 'enrollment_batch_issued',
        'enrollment_batch_cancelled', 'event_triage_changed', 'incident_case_changed', 'security_alert_settings_changed',
        'security_alert_acknowledged', 'event_feed_key_issued', 'event_feed_key_revoked', 'browser_fleet_changed'));
CREATE UNIQUE INDEX control_audit_fleet_request ON control_audit (organization_id, (fleet_change->>'batchId')) WHERE action = 'browser_fleet_changed';
