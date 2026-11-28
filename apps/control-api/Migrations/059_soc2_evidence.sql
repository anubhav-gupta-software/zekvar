-- Statements are repeatable so schema rollback tests can reapply this migration.
-- Actor columns have no foreign keys: access evidence outlives credential rows and schema rebuilds.
-- Credential last use for access reviews. Updates are throttled to one write per credential per minute.
ALTER TABLE admin_memberships ADD COLUMN IF NOT EXISTS last_used_at timestamptz;
ALTER TABLE control_access ADD COLUMN IF NOT EXISTS last_used_at timestamptz;
ALTER TABLE event_feed_keys ADD COLUMN IF NOT EXISTS last_used_at timestamptz;

-- Read-access audit. Exports get one row each; views and SIEM feed reads are rolled up per actor or key per UTC hour.
-- Rows hold the actor, resource, filters, and counts only, never exported content.
CREATE TABLE IF NOT EXISTS control_access_log (
    organization_id uuid NOT NULL REFERENCES organizations(id),
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    occurred_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    last_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    action text NOT NULL CHECK (action IN ('data_exported', 'data_viewed', 'event_feed_read')),
    resource text NOT NULL CHECK (resource IN ('security_events', 'incident_case', 'audit_log', 'event_feed', 'composer_readiness',
        'ai_enforcement', 'extension_inventory', 'access_review', 'evidence_pack', 'saas_inventory', 'organization_export')),
    actor_access_id uuid,
    event_feed_key_id uuid,
    scope jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(scope) = 'object'),
    records bigint NOT NULL DEFAULT 0 CHECK (records >= 0),
    requests integer NOT NULL DEFAULT 1 CHECK (requests >= 1),
    completed boolean NOT NULL DEFAULT true,
    rollup_key text,
    PRIMARY KEY (organization_id, id),
    CHECK ((action = 'event_feed_read') = (event_feed_key_id IS NOT NULL)),
    CHECK ((action = 'data_exported') = (rollup_key IS NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS control_access_log_rollup ON control_access_log (organization_id, rollup_key) WHERE rollup_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS control_access_log_history ON control_access_log (organization_id, occurred_at DESC, id DESC);

-- Owner attestations: quarterly access reviews and backup or restore drills.
CREATE TABLE IF NOT EXISTS control_attestations (
    organization_id uuid NOT NULL REFERENCES organizations(id),
    id uuid NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    kind text NOT NULL CHECK (kind IN ('access_review', 'backup_drill', 'restore_drill')),
    actor_access_id uuid,
    details jsonb NOT NULL CHECK (jsonb_typeof(details) = 'object'),
    PRIMARY KEY (organization_id, id)
);
CREATE INDEX IF NOT EXISTS control_attestations_history ON control_attestations (organization_id, occurred_at DESC, id DESC);

-- Confidential detection terms can be stored sealed: the array is emptied and a "sealed" envelope holds it.
ALTER TABLE policy_versions DROP CONSTRAINT IF EXISTS policy_versions_classification_protection_check,
    ADD CONSTRAINT policy_versions_classification_protection_check CHECK (
        jsonb_typeof(classification_protection) = 'object'
        AND classification_protection ?& ARRAY['mode', 'terms']
        AND jsonb_typeof(classification_protection->'mode') = 'string'
        AND classification_protection->>'mode' IN ('off', 'monitor', 'warn', 'block')
        AND jsonb_typeof(classification_protection->'terms') = 'array'
        AND CASE WHEN classification_protection ? 'sealed'
            THEN jsonb_typeof(classification_protection->'sealed') = 'string' AND jsonb_array_length(classification_protection->'terms') = 0
            ELSE jsonb_array_length(classification_protection->'terms') BETWEEN
                CASE WHEN classification_protection->>'mode' = 'off' THEN 0 ELSE 1 END AND 16 END),
    DROP CONSTRAINT IF EXISTS policy_versions_identifier_protection_check,
    ADD CONSTRAINT policy_versions_identifier_protection_check CHECK (
        jsonb_typeof(identifier_protection) = 'object'
        AND identifier_protection ?& ARRAY['mode', 'formats']
        AND jsonb_typeof(identifier_protection->'mode') = 'string'
        AND identifier_protection->>'mode' IN ('off', 'monitor', 'warn', 'block')
        AND jsonb_typeof(identifier_protection->'formats') = 'array'
        AND CASE WHEN identifier_protection ? 'sealed'
            THEN jsonb_typeof(identifier_protection->'sealed') = 'string' AND jsonb_array_length(identifier_protection->'formats') = 0
            ELSE jsonb_array_length(identifier_protection->'formats') BETWEEN
                CASE WHEN identifier_protection->>'mode' = 'off' THEN 0 ELSE 1 END AND 16 END);
