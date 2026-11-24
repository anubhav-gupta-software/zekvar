CREATE TABLE prompt_exception_requests (
    organization_id uuid NOT NULL,
    id uuid PRIMARY KEY,
    installation_id uuid NOT NULL,
    event_id uuid NOT NULL,
    requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'declined', 'exception_available')),
    decided_at timestamptz,
    decided_by uuid,
    published_version integer,
    UNIQUE (installation_id, event_id),
    FOREIGN KEY (organization_id, installation_id) REFERENCES installations (organization_id, id),
    FOREIGN KEY (installation_id, event_id) REFERENCES security_events (installation_id, event_id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, decided_by) REFERENCES control_access (organization_id, id),
    FOREIGN KEY (organization_id, published_version) REFERENCES policy_versions (organization_id, version),
    CHECK ((status = 'pending') = (decided_at IS NULL)),
    CHECK ((status = 'exception_available') = (published_version IS NOT NULL)),
    CHECK (decided_at IS NOT NULL OR decided_by IS NULL)
);
CREATE INDEX prompt_exception_requests_inbox ON prompt_exception_requests (organization_id, status, requested_at, id);
