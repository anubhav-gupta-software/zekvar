ALTER TABLE policy_versions ADD COLUMN extension_inventory_enabled boolean NOT NULL DEFAULT false;

CREATE TABLE extension_inventory_snapshots (
    installation_id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    policy_version integer NOT NULL,
    assignment_version integer NOT NULL CHECK (assignment_version >= 0),
    captured_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    status text NOT NULL CHECK (status IN ('reported', 'permission_required', 'unavailable')),
    entries jsonb NOT NULL CHECK (jsonb_typeof(entries) = 'array' AND jsonb_array_length(entries) <= 100),
    omitted integer NOT NULL CHECK (omitted >= 0),
    CHECK (status = 'reported' OR (entries = '[]'::jsonb AND omitted = 0)),
    FOREIGN KEY (organization_id, installation_id) REFERENCES installations(organization_id, id),
    FOREIGN KEY (organization_id, policy_version) REFERENCES policy_versions(organization_id, version)
);
