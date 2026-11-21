ALTER TABLE organizations ADD COLUMN require_policy_review boolean NOT NULL DEFAULT false;

CREATE TABLE policy_reviews (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id),
    requested_by uuid NOT NULL,
    decided_by uuid,
    requested_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL DEFAULT now() + interval '24 hours',
    decided_at timestamptz,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'withdrawn', 'stale', 'cancelled')),
    operation text NOT NULL CHECK (operation IN ('publish', 'restore', 'promote')),
    group_id uuid,
    source_group_id uuid,
    source_version integer,
    base_version integer NOT NULL,
    published_version integer,
    snapshots jsonb NOT NULL CHECK (jsonb_typeof(snapshots) = 'object'),
    FOREIGN KEY (organization_id, group_id) REFERENCES policy_groups(organization_id, id),
    FOREIGN KEY (organization_id, source_group_id) REFERENCES policy_groups(organization_id, id),
    FOREIGN KEY (organization_id, source_version) REFERENCES policy_versions(organization_id, version),
    FOREIGN KEY (organization_id, base_version) REFERENCES policy_versions(organization_id, version),
    FOREIGN KEY (organization_id, published_version) REFERENCES policy_versions(organization_id, version),
    FOREIGN KEY (organization_id, requested_by) REFERENCES control_access(organization_id, id),
    FOREIGN KEY (organization_id, decided_by) REFERENCES control_access(organization_id, id),
    CHECK ((operation = 'promote') = (source_group_id IS NOT NULL) AND
        (operation <> 'publish') = (source_version IS NOT NULL)),
    CHECK ((status = 'approved') = (published_version IS NOT NULL)),
    CHECK ((status = 'pending') = (decided_at IS NULL))
);

CREATE INDEX policy_reviews_by_organization ON policy_reviews (organization_id, requested_at DESC, id DESC);

ALTER TABLE control_audit DROP CONSTRAINT control_audit_action_check,
    ADD CONSTRAINT control_audit_action_check CHECK (action IN ('policy_published', 'policy_restored', 'grant_issued',
        'browser_enrolled', 'browser_revoked', 'app_classified', 'retention_changed', 'retention_cleanup',
        'policy_group_created', 'policy_group_assigned', 'access_issued', 'access_revoked',
        'policy_review_setting_changed', 'policy_review_requested', 'policy_review_decided')),
    ADD COLUMN review_change jsonb CHECK (jsonb_typeof(review_change) = 'object');
