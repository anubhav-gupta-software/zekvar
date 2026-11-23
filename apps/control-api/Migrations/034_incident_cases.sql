CREATE TABLE incident_cases (
    organization_id uuid NOT NULL REFERENCES organizations(id),
    id uuid NOT NULL,
    category text NOT NULL CHECK (category IN ('suspected_data_exposure', 'repeated_policy_blocks', 'unexpected_ai_use', 'other')),
    creation_fingerprint text NOT NULL,
    revision integer NOT NULL DEFAULT 1 CHECK (revision >= 1),
    status text NOT NULL DEFAULT 'needs_review' CHECK (status IN ('needs_review', 'investigating', 'resolved')),
    disposition text CHECK (disposition IN ('confirmed_violation', 'false_positive', 'expected_activity', 'insufficient_evidence')),
    assignee_id uuid,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (organization_id, id),
    FOREIGN KEY (organization_id, assignee_id) REFERENCES control_access (organization_id, id),
    CHECK ((status = 'resolved') = (disposition IS NOT NULL))
);
CREATE INDEX incident_cases_recent ON incident_cases (organization_id, created_at DESC, id DESC);
CREATE INDEX incident_cases_resolved ON incident_cases (organization_id, updated_at) WHERE status = 'resolved';

CREATE TABLE incident_case_events (
    organization_id uuid NOT NULL,
    case_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    event_id uuid NOT NULL,
    PRIMARY KEY (installation_id, event_id),
    FOREIGN KEY (organization_id, case_id) REFERENCES incident_cases (organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, installation_id) REFERENCES installations (organization_id, id),
    FOREIGN KEY (installation_id, event_id) REFERENCES security_events (installation_id, event_id) ON DELETE CASCADE
);
CREATE INDEX incident_case_events_by_case ON incident_case_events (organization_id, case_id);

ALTER TABLE control_audit ADD COLUMN incident_case_change jsonb CHECK (jsonb_typeof(incident_case_change) = 'object'),
    ADD CHECK ((action = 'incident_case_changed') = (incident_case_change IS NOT NULL)),
    DROP CONSTRAINT control_audit_action_check,
    ADD CONSTRAINT control_audit_action_check CHECK (action IN ('policy_published', 'policy_restored', 'grant_issued',
        'browser_enrolled', 'browser_revoked', 'app_classified', 'retention_changed', 'retention_cleanup',
        'policy_group_created', 'policy_group_assigned', 'access_issued', 'access_revoked', 'control_sso_signed_in',
        'policy_review_setting_changed', 'policy_review_requested', 'policy_review_decided', 'enrollment_batch_issued',
        'enrollment_batch_cancelled', 'event_triage_changed', 'incident_case_changed'));
CREATE INDEX incident_case_timeline ON control_audit (organization_id, (incident_case_change->>'caseId'), occurred_at DESC, id DESC)
    WHERE action = 'incident_case_changed';
