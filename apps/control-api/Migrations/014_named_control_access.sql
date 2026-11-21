CREATE TABLE control_access (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id),
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 2 AND 64),
    role text NOT NULL CHECK (role IN ('administrator', 'auditor')),
    token_hash text UNIQUE,
    issued_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL CHECK (expires_at > issued_at),
    revoked_at timestamptz,
    CHECK ((revoked_at IS NULL) = (token_hash IS NOT NULL)),
    UNIQUE (organization_id, id)
);

CREATE INDEX control_access_by_organization ON control_access (organization_id, issued_at DESC, id DESC);

ALTER TABLE control_audit DROP CONSTRAINT control_audit_action_check,
    ADD CONSTRAINT control_audit_action_check CHECK (action IN ('policy_published', 'policy_restored', 'grant_issued',
        'browser_enrolled', 'browser_revoked', 'app_classified', 'retention_changed', 'retention_cleanup',
        'policy_group_created', 'policy_group_assigned', 'access_issued', 'access_revoked')),
    ADD COLUMN actor_access_id uuid,
    ADD COLUMN subject_access_id uuid,
    ADD FOREIGN KEY (organization_id, actor_access_id) REFERENCES control_access(organization_id, id),
    ADD FOREIGN KEY (organization_id, subject_access_id) REFERENCES control_access(organization_id, id),
    ADD CHECK ((action IN ('access_issued', 'access_revoked')) = (subject_access_id IS NOT NULL));
