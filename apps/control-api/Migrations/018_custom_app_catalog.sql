ALTER TABLE policy_versions ADD COLUMN custom_apps jsonb NOT NULL DEFAULT '[]'
    CHECK (jsonb_typeof(custom_apps) = 'array' AND jsonb_array_length(custom_apps) <= 25);

ALTER TABLE ai_app_observations DROP CONSTRAINT ai_app_observations_app_id_check,
    ADD CONSTRAINT ai_app_observations_app_id_check
        CHECK (app_id IN ('chatgpt', 'claude', 'gemini') OR app_id ~ '^saas:[a-f0-9]{64}$');

ALTER TABLE ai_app_classifications DROP CONSTRAINT ai_app_classifications_app_id_check,
    ADD CONSTRAINT ai_app_classifications_app_id_check
        CHECK (app_id IN ('chatgpt', 'claude', 'gemini') OR app_id ~ '^saas:[a-f0-9]{64}$');

ALTER TABLE control_audit DROP CONSTRAINT control_audit_app_id_check,
    ADD CONSTRAINT control_audit_app_id_check
        CHECK (app_id IN ('chatgpt', 'claude', 'gemini') OR app_id ~ '^saas:[a-f0-9]{64}$');
