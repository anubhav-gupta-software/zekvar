CREATE TABLE composer_observations (
    organization_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    app_id text NOT NULL CHECK (app_id IN ('chatgpt', 'claude', 'gemini')),
    policy_version integer NOT NULL CHECK (policy_version > 0),
    assignment_version integer NOT NULL CHECK (assignment_version >= 0),
    coverage text NOT NULL CHECK (coverage IN ('ready', 'unsupported')),
    checked_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (installation_id, app_id),
    FOREIGN KEY (organization_id, installation_id) REFERENCES installations(organization_id, id) ON DELETE CASCADE
);
