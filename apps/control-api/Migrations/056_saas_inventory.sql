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

-- Extend the existing action list in place so actions added by other migrations are preserved.
DO $$
DECLARE definition text;
BEGIN
    SELECT pg_get_constraintdef(oid) INTO definition FROM pg_constraint
    WHERE conrelid = 'control_audit'::regclass AND conname = 'control_audit_action_check';
    IF position('saas_app_classified' IN definition) = 0 THEN
        EXECUTE 'ALTER TABLE control_audit DROP CONSTRAINT control_audit_action_check, ADD CONSTRAINT control_audit_action_check '
            || replace(definition, 'ARRAY[', 'ARRAY[''saas_app_classified''::text, ');
    END IF;
END $$;

ALTER TABLE control_audit ADD CONSTRAINT control_audit_saas_record_check
    CHECK ((action = 'saas_app_classified') = (saas_classification IS NOT NULL));
