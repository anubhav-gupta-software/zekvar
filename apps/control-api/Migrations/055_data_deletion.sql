-- Self-service deletion: installation erasure, policy history purge, organization offboarding and export.
-- Every statement is idempotent so a test or recovery that re-applies earlier migrations can re-apply this one.

-- Operator ledger for organization deletion. It has no foreign key to organizations because it outlives the tenant:
-- after completion it keeps only the organization ID, hashes used to refuse an accidental reseed, and the signed receipt.
CREATE TABLE IF NOT EXISTS organization_deletions (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    slug_hash text NOT NULL CHECK (slug_hash ~ '^[a-f0-9]{64}$'),
    owner_token_hash text NOT NULL CHECK (owner_token_hash ~ '^[a-f0-9]{64}$'),
    receipt_token_hash text NOT NULL CHECK (receipt_token_hash ~ '^[a-f0-9]{64}$'),
    status text NOT NULL CHECK (status IN ('pending', 'deleting', 'completed', 'cancelled')),
    requested_at timestamptz NOT NULL DEFAULT now(),
    purge_after timestamptz NOT NULL,
    cancelled_at timestamptz,
    started_at timestamptz,
    completed_at timestamptz,
    deleted_rows jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(deleted_rows) = 'object'),
    batches integer NOT NULL DEFAULT 0 CHECK (batches >= 0),
    last_error text CHECK (last_error ~ '^[a-z_]{1,64}$'),
    receipt text,
    receipt_signature text CHECK (receipt_signature ~ '^[a-f0-9]{64}$'),
    CHECK ((status = 'cancelled') = (cancelled_at IS NOT NULL)),
    CHECK ((status IN ('deleting', 'completed')) = (started_at IS NOT NULL)),
    CHECK ((status = 'completed') = (completed_at IS NOT NULL)),
    CHECK ((status = 'completed') = (receipt IS NOT NULL) AND (receipt IS NULL) = (receipt_signature IS NULL)),
    CHECK (purge_after > requested_at)
);
CREATE UNIQUE INDEX IF NOT EXISTS organization_deletions_active ON organization_deletions (organization_id)
    WHERE status IN ('pending', 'deleting');
CREATE INDEX IF NOT EXISTS organization_deletions_due ON organization_deletions (purge_after) WHERE status IN ('pending', 'deleting');
CREATE INDEX IF NOT EXISTS organization_deletions_by_organization ON organization_deletions (organization_id, requested_at DESC);

-- True while an organization is in its deletion grace period or being deleted. Credentials and background work check it.
CREATE OR REPLACE FUNCTION organization_offboarding(org uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT EXISTS (SELECT 1 FROM organization_deletions WHERE organization_id = org AND status IN ('pending', 'deleting'))
$$;

-- Historical records keep the number of a purged policy version or a deleted installation instead of blocking erasure.
ALTER TABLE control_audit DROP CONSTRAINT IF EXISTS control_audit_organization_id_installation_id_fkey,
    DROP CONSTRAINT IF EXISTS control_audit_organization_id_policy_version_fkey,
    DROP CONSTRAINT IF EXISTS control_audit_organization_id_restored_from_fkey;
ALTER TABLE policy_audit DROP CONSTRAINT IF EXISTS policy_audit_organization_id_restored_from_fkey;
ALTER TABLE policy_reviews DROP CONSTRAINT IF EXISTS policy_reviews_organization_id_source_version_fkey,
    DROP CONSTRAINT IF EXISTS policy_reviews_organization_id_base_version_fkey,
    DROP CONSTRAINT IF EXISTS policy_reviews_organization_id_published_version_fkey;
ALTER TABLE rollout_plans DROP CONSTRAINT IF EXISTS rollout_plans_organization_id_source_version_fkey;
ALTER TABLE rollout_stages DROP CONSTRAINT IF EXISTS rollout_stages_organization_id_prior_version_fkey,
    DROP CONSTRAINT IF EXISTS rollout_stages_organization_id_published_version_fkey,
    DROP CONSTRAINT IF EXISTS rollout_stages_organization_id_rollback_version_fkey;

-- Policy history purge checks retained references per version, and removing a version checks these foreign keys.
CREATE INDEX IF NOT EXISTS security_events_by_policy_version ON security_events (organization_id, policy_version);
CREATE INDEX IF NOT EXISTS policy_deliveries_by_policy_version ON policy_deliveries (organization_id, policy_version);

ALTER TABLE control_audit ADD COLUMN IF NOT EXISTS data_deletion jsonb;
ALTER TABLE control_audit DROP CONSTRAINT IF EXISTS control_audit_data_deletion_check,
    ADD CONSTRAINT control_audit_data_deletion_check CHECK (jsonb_typeof(data_deletion) = 'object'),
    DROP CONSTRAINT IF EXISTS control_audit_data_deletion_record_check,
    ADD CONSTRAINT control_audit_data_deletion_record_check CHECK ((action IN ('installation_deleted', 'policy_history_purged',
        'organization_deletion_requested', 'organization_deletion_cancelled', 'organization_exported')) = (data_deletion IS NOT NULL));

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
        UNION SELECT unnest(ARRAY['installation_deleted', 'policy_history_purged', 'organization_deletion_requested',
            'organization_deletion_cancelled', 'organization_exported'])
    ) listed;
    EXECUTE format('ALTER TABLE control_audit DROP CONSTRAINT IF EXISTS control_audit_action_check, '
        'ADD CONSTRAINT control_audit_action_check CHECK (action = ANY (%L::text[]))', actions);
END;
$$;
