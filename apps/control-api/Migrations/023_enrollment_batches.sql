CREATE TABLE enrollment_batches (
    organization_id uuid NOT NULL REFERENCES organizations(id),
    id uuid NOT NULL,
    policy_group_id uuid,
    size integer NOT NULL CHECK (size BETWEEN 1 AND 25),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    cancelled_at timestamptz,
    PRIMARY KEY (organization_id, id),
    FOREIGN KEY (organization_id, policy_group_id) REFERENCES policy_groups (organization_id, id)
);
CREATE INDEX enrollment_batches_by_organization ON enrollment_batches (organization_id, created_at DESC, id);

ALTER TABLE enrollment_grants ADD COLUMN batch_id uuid,
    ADD FOREIGN KEY (organization_id, batch_id) REFERENCES enrollment_batches (organization_id, id);
CREATE INDEX enrollment_grants_by_batch ON enrollment_grants (organization_id, batch_id) WHERE batch_id IS NOT NULL;

ALTER TABLE control_audit ADD COLUMN enrollment_batch_change jsonb CHECK (jsonb_typeof(enrollment_batch_change) = 'object'),
    DROP CONSTRAINT control_audit_action_check,
    ADD CONSTRAINT control_audit_action_check CHECK (action IN ('policy_published', 'policy_restored', 'grant_issued',
        'browser_enrolled', 'browser_revoked', 'app_classified', 'retention_changed', 'retention_cleanup',
        'policy_group_created', 'policy_group_assigned', 'access_issued', 'access_revoked', 'control_sso_signed_in',
        'policy_review_setting_changed', 'policy_review_requested', 'policy_review_decided', 'enrollment_batch_issued', 'enrollment_batch_cancelled'));
