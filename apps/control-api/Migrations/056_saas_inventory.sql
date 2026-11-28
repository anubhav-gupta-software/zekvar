ALTER TABLE policy_versions ADD COLUMN saas_discovery_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE policy_deliveries ADD COLUMN saas_discovery boolean NOT NULL DEFAULT false;

-- One row per browser and catalog app. Only UTC days are stored, never URLs, paths, or titles.
CREATE TABLE saas_app_observations (
    organization_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    app_id text NOT NULL CHECK (app_id ~ '^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$'),
    first_seen_day date NOT NULL,
    last_seen_day date NOT NULL CHECK (last_seen_day >= first_seen_day),
    PRIMARY KEY (organization_id, app_id, installation_id),
    FOREIGN KEY (organization_id, installation_id) REFERENCES installations(organization_id, id)
);
CREATE INDEX saas_app_observations_last_seen ON saas_app_observations (organization_id, last_seen_day);

CREATE TABLE saas_app_classifications (
    organization_id uuid NOT NULL REFERENCES organizations(id),
    app_id text NOT NULL CHECK (app_id ~ '^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$'),
    status text NOT NULL CHECK (status IN ('unclassified', 'under_review', 'sanctioned', 'unsanctioned')),
    PRIMARY KEY (organization_id, app_id)
);

ALTER TABLE control_audit ADD COLUMN saas_classification jsonb CHECK (jsonb_typeof(saas_classification) = 'object');

-- Extend the current action list rather than restating it, so migrations that add actions in any order keep theirs.
DO $$
DECLARE
    actions text[];
BEGIN
    -- PostgreSQL prints an IN list as ARRAY['a'::text, ...] and an array literal as '{a,b}'::text[]; read both forms.
    SELECT array_agg(DISTINCT value ORDER BY value) INTO actions FROM (
        SELECT m[1] AS value FROM pg_constraint c,
            regexp_matches(pg_get_constraintdef(c.oid), '''([a-z_]+)''::text', 'g') AS m
        WHERE c.conrelid = 'control_audit'::regclass AND c.conname = 'control_audit_action_check'
        UNION SELECT unnest(string_to_array(m[1], ',')) FROM pg_constraint c,
            regexp_matches(pg_get_constraintdef(c.oid), '''\{([a-z_,]+)\}''', 'g') AS m
        WHERE c.conrelid = 'control_audit'::regclass AND c.conname = 'control_audit_action_check'
        UNION SELECT unnest(ARRAY['saas_app_classified'])
    ) listed;
    EXECUTE format('ALTER TABLE control_audit DROP CONSTRAINT IF EXISTS control_audit_action_check, '
        'ADD CONSTRAINT control_audit_action_check CHECK (action = ANY (%L::text[]))', actions);
END;
$$;

ALTER TABLE control_audit ADD CONSTRAINT control_audit_saas_record_check
    CHECK ((action = 'saas_app_classified') = (saas_classification IS NOT NULL));
