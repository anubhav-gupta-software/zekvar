ALTER TABLE policy_deliveries ADD COLUMN preset_discovery boolean NOT NULL DEFAULT false;
ALTER TABLE policy_versions ADD COLUMN preset_discovery_enabled boolean NOT NULL DEFAULT false;

ALTER TABLE ai_app_observations DROP CONSTRAINT ai_app_observations_app_id_check,
    ADD CONSTRAINT ai_app_observations_app_id_check CHECK (
        app_id IN ('chatgpt', 'claude', 'gemini', 'copilot', 'perplexity', 'grok', 'meta-ai', 'deepseek') OR app_id ~ '^saas:[a-f0-9]{64}$'
    );

ALTER TABLE ai_app_classifications DROP CONSTRAINT ai_app_classifications_app_id_check,
    ADD CONSTRAINT ai_app_classifications_app_id_check CHECK (
        app_id IN ('chatgpt', 'claude', 'gemini', 'copilot', 'perplexity', 'grok', 'meta-ai', 'deepseek') OR app_id ~ '^saas:[a-f0-9]{64}$'
    );

ALTER TABLE control_audit DROP CONSTRAINT control_audit_app_id_check,
    ADD CONSTRAINT control_audit_app_id_check CHECK (
        app_id IN ('chatgpt', 'claude', 'gemini', 'copilot', 'perplexity', 'grok', 'meta-ai', 'deepseek') OR app_id ~ '^saas:[a-f0-9]{64}$'
    );
