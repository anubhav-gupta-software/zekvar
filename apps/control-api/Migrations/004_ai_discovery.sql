ALTER TABLE policy_versions ADD COLUMN discovery_enabled boolean NOT NULL DEFAULT false;

CREATE TABLE ai_app_observations (
    organization_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    app_id text NOT NULL CHECK (app_id IN ('chatgpt', 'claude', 'gemini')),
    observed_at timestamptz NOT NULL,
    PRIMARY KEY (organization_id, app_id, installation_id),
    FOREIGN KEY (organization_id, installation_id) REFERENCES installations(organization_id, id)
);

CREATE TABLE ai_app_classifications (
    organization_id uuid NOT NULL REFERENCES organizations(id),
    app_id text NOT NULL CHECK (app_id IN ('chatgpt', 'claude', 'gemini')),
    status text NOT NULL CHECK (status IN ('unreviewed', 'approved', 'unapproved')),
    PRIMARY KEY (organization_id, app_id)
);
