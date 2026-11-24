ALTER TABLE policy_versions ADD COLUMN prompt_app_modes jsonb NOT NULL DEFAULT '{}'::jsonb
    CHECK (jsonb_typeof(prompt_app_modes) = 'object');
ALTER TABLE policy_deliveries ADD COLUMN prompt_app_modes boolean NOT NULL DEFAULT false;
