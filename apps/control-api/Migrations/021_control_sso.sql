ALTER TABLE control_access
    DROP CONSTRAINT control_access_check1,
    ALTER COLUMN expires_at DROP NOT NULL,
    ADD COLUMN oidc_issuer text,
    ADD COLUMN oidc_subject text,
    ADD CONSTRAINT control_access_type_check CHECK (
        (oidc_issuer IS NULL AND oidc_subject IS NULL AND expires_at IS NOT NULL
            AND (revoked_at IS NULL) = (token_hash IS NOT NULL))
        OR (oidc_issuer IS NOT NULL AND oidc_subject IS NOT NULL AND expires_at IS NULL AND token_hash IS NULL));

CREATE UNIQUE INDEX control_access_live_oidc_subject ON control_access (organization_id, oidc_issuer, oidc_subject)
    WHERE revoked_at IS NULL AND oidc_subject IS NOT NULL;

CREATE TABLE control_sso_sessions (
    token_hash text PRIMARY KEY,
    access_id uuid NOT NULL REFERENCES control_access(id),
    bridge_hash text NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX control_sso_sessions_by_expiry ON control_sso_sessions (expires_at);
CREATE INDEX control_sso_sessions_by_access ON control_sso_sessions (access_id);

ALTER TABLE control_audit DROP CONSTRAINT control_audit_action_check,
    ADD CONSTRAINT control_audit_action_check CHECK (action IN ('policy_published', 'policy_restored', 'grant_issued',
        'browser_enrolled', 'browser_revoked', 'app_classified', 'retention_changed', 'retention_cleanup',
        'policy_group_created', 'policy_group_assigned', 'access_issued', 'access_revoked', 'control_sso_signed_in',
        'policy_review_setting_changed', 'policy_review_requested', 'policy_review_decided'));
