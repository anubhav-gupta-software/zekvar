CREATE TABLE control_audit (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id),
    occurred_at timestamptz NOT NULL DEFAULT now(),
    action text NOT NULL CHECK (action IN ('policy_published', 'policy_restored', 'grant_issued',
        'browser_enrolled', 'browser_revoked', 'app_classified')),
    policy_version integer,
    restored_from integer,
    installation_id uuid,
    app_id text CHECK (app_id IN ('chatgpt', 'claude', 'gemini')),
    classification text CHECK (classification IN ('unreviewed', 'approved', 'unapproved')),
    FOREIGN KEY (organization_id, policy_version) REFERENCES policy_versions(organization_id, version),
    FOREIGN KEY (organization_id, restored_from) REFERENCES policy_versions(organization_id, version),
    FOREIGN KEY (organization_id, installation_id) REFERENCES installations(organization_id, id),
    CHECK ((action IN ('policy_published', 'policy_restored')) = (policy_version IS NOT NULL)),
    CHECK ((action = 'policy_restored') = (restored_from IS NOT NULL)),
    CHECK ((action IN ('browser_enrolled', 'browser_revoked')) = (installation_id IS NOT NULL)),
    CHECK ((action = 'app_classified') = (app_id IS NOT NULL) AND (app_id IS NULL) = (classification IS NULL))
);

CREATE INDEX control_audit_by_organization ON control_audit (organization_id, occurred_at DESC, id DESC);

INSERT INTO control_audit (organization_id, occurred_at, action, policy_version, restored_from)
SELECT a.organization_id, p.published_at,
    CASE WHEN a.restored_from IS NULL THEN 'policy_published' ELSE 'policy_restored' END, a.version, a.restored_from
FROM policy_audit a JOIN policy_versions p USING (organization_id, version);

INSERT INTO control_audit (organization_id, occurred_at, action, installation_id)
SELECT organization_id, enrolled_at, 'browser_enrolled', id FROM installations
UNION ALL
SELECT organization_id, revoked_at, 'browser_revoked', id FROM installations WHERE revoked_at IS NOT NULL;
