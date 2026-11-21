CREATE TABLE organizations (
    id uuid PRIMARY KEY,
    slug text NOT NULL UNIQUE,
    policy_version integer NOT NULL DEFAULT 1 CHECK (policy_version > 0)
);

CREATE TABLE admin_memberships (
    organization_id uuid PRIMARY KEY REFERENCES organizations(id),
    token_hash text NOT NULL UNIQUE
);

CREATE TABLE enrollment_grants (
    token_hash text PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id),
    expires_at timestamptz NOT NULL,
    redeemed_at timestamptz
);

CREATE TABLE policy_versions (
    organization_id uuid NOT NULL REFERENCES organizations(id),
    version integer NOT NULL CHECK (version > 0),
    mode text NOT NULL CHECK (mode IN ('monitor', 'warn', 'block')),
    published_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, version)
);

CREATE TABLE installations (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id),
    token_hash text NOT NULL UNIQUE,
    enrolled_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    applied_policy_version integer,
    revoked_at timestamptz,
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, applied_policy_version) REFERENCES policy_versions(organization_id, version)
);

CREATE TABLE security_events (
    organization_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    event_id uuid NOT NULL,
    occurred_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    policy_version integer NOT NULL,
    decision text NOT NULL CHECK (decision IN ('monitor', 'warn', 'block', 'warn_override')),
    PRIMARY KEY (installation_id, event_id),
    FOREIGN KEY (organization_id, installation_id) REFERENCES installations(organization_id, id),
    FOREIGN KEY (organization_id, policy_version) REFERENCES policy_versions(organization_id, version)
);

CREATE INDEX events_by_organization_recency ON security_events (organization_id, received_at DESC, event_id);

CREATE TABLE policy_audit (
    organization_id uuid NOT NULL,
    version integer NOT NULL,
    restored_from integer,
    PRIMARY KEY (organization_id, version),
    FOREIGN KEY (organization_id, version) REFERENCES policy_versions(organization_id, version),
    FOREIGN KEY (organization_id, restored_from) REFERENCES policy_versions(organization_id, version)
);
