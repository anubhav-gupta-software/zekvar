CREATE TABLE event_triage (
    organization_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    event_id uuid NOT NULL,
    revision integer NOT NULL CHECK (revision > 0),
    status text NOT NULL CHECK (status IN ('needs_review', 'investigating', 'resolved')),
    disposition text CHECK (disposition IN ('confirmed_violation', 'false_positive', 'expected_activity', 'insufficient_evidence')),
    assignee_id uuid,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (installation_id, event_id),
    FOREIGN KEY (organization_id, installation_id) REFERENCES installations (organization_id, id),
    FOREIGN KEY (installation_id, event_id) REFERENCES security_events (installation_id, event_id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, assignee_id) REFERENCES control_access (organization_id, id),
    CHECK ((status = 'resolved') = (disposition IS NOT NULL))
);
CREATE INDEX event_triage_queue ON event_triage (organization_id, status, assignee_id);
CREATE INDEX event_triage_assignee ON event_triage (organization_id, assignee_id) WHERE assignee_id IS NOT NULL;

ALTER TABLE control_audit ADD COLUMN event_triage_change jsonb CHECK (jsonb_typeof(event_triage_change) = 'object'),
    ADD CHECK ((action = 'event_triage_changed') = (event_triage_change IS NOT NULL)),
    DROP CONSTRAINT control_audit_action_check,
    ADD CONSTRAINT control_audit_action_check CHECK (action IN ('policy_published', 'policy_restored', 'grant_issued',
        'browser_enrolled', 'browser_revoked', 'app_classified', 'retention_changed', 'retention_cleanup',
        'policy_group_created', 'policy_group_assigned', 'access_issued', 'access_revoked', 'control_sso_signed_in',
        'policy_review_setting_changed', 'policy_review_requested', 'policy_review_decided', 'enrollment_batch_issued',
        'enrollment_batch_cancelled', 'event_triage_changed'));
CREATE INDEX event_triage_timeline ON control_audit (organization_id, (event_triage_change->>'installationId'),
    (event_triage_change->>'eventId'), occurred_at DESC, id DESC) WHERE action = 'event_triage_changed';
