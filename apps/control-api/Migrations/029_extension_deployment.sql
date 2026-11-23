ALTER TABLE policy_versions ADD COLUMN extension_deployment jsonb NOT NULL DEFAULT '{"unlisted":"preserve","rules":[]}'::jsonb,
    ADD CHECK (jsonb_typeof(extension_deployment) = 'object');
