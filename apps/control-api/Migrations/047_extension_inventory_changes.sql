CREATE TABLE extension_inventory_change_batches (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    assignment_version integer NOT NULL CHECK (assignment_version >= 0),
    policy_version integer NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    changes jsonb NOT NULL CHECK (jsonb_typeof(changes) = 'array' AND jsonb_array_length(changes) BETWEEN 1 AND 200),
    FOREIGN KEY (organization_id, installation_id) REFERENCES installations(organization_id, id),
    FOREIGN KEY (organization_id, policy_version) REFERENCES policy_versions(organization_id, version)
);

CREATE INDEX extension_inventory_changes_by_browser ON extension_inventory_change_batches (installation_id, id DESC);
CREATE INDEX extension_inventory_changes_by_expiry ON extension_inventory_change_batches (received_at);
