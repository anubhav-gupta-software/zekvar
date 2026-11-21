ALTER TABLE organizations ADD COLUMN policy_sequence integer;
UPDATE organizations SET policy_sequence = policy_version;
ALTER TABLE organizations ALTER COLUMN policy_sequence SET NOT NULL,
    ALTER COLUMN policy_sequence SET DEFAULT 1,
    ADD CONSTRAINT organizations_policy_sequence_check CHECK (policy_sequence >= policy_version);

CREATE TABLE policy_groups (
    organization_id uuid NOT NULL REFERENCES organizations(id),
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    name text NOT NULL CHECK (char_length(name) BETWEEN 2 AND 64),
    policy_version integer,
    PRIMARY KEY (organization_id, id),
    FOREIGN KEY (organization_id, policy_version) REFERENCES policy_versions(organization_id, version)
);
CREATE UNIQUE INDEX policy_groups_name ON policy_groups (organization_id, lower(name));

ALTER TABLE policy_versions ADD COLUMN policy_group_id uuid,
    ADD FOREIGN KEY (organization_id, policy_group_id) REFERENCES policy_groups(organization_id, id);
CREATE INDEX policy_versions_by_group ON policy_versions (organization_id, policy_group_id, version);

ALTER TABLE installations ADD COLUMN policy_group_id uuid,
    ADD COLUMN assignment_version integer NOT NULL DEFAULT 0 CHECK (assignment_version >= 0),
    ADD COLUMN assignment_aware boolean NOT NULL DEFAULT false,
    ADD FOREIGN KEY (organization_id, policy_group_id) REFERENCES policy_groups(organization_id, id);

CREATE TABLE policy_deliveries (
    organization_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    assignment_version integer NOT NULL CHECK (assignment_version > 0),
    policy_version integer NOT NULL,
    PRIMARY KEY (installation_id, assignment_version, policy_version),
    FOREIGN KEY (organization_id, installation_id) REFERENCES installations(organization_id, id),
    FOREIGN KEY (organization_id, policy_version) REFERENCES policy_versions(organization_id, version)
);

ALTER TABLE control_audit DROP CONSTRAINT control_audit_action_check,
    ADD CONSTRAINT control_audit_action_check CHECK (action IN ('policy_published', 'policy_restored', 'grant_issued',
        'browser_enrolled', 'browser_revoked', 'app_classified', 'retention_changed', 'retention_cleanup',
        'policy_group_created', 'policy_group_assigned')),
    ADD COLUMN group_change jsonb CHECK (jsonb_typeof(group_change) = 'object');
