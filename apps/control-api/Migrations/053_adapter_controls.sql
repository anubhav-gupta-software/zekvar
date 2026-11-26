ALTER TABLE policy_versions ADD COLUMN adapter_controls jsonb NOT NULL DEFAULT '{}'::jsonb
    CHECK (jsonb_typeof(adapter_controls) = 'object');
ALTER TABLE policy_deliveries ADD COLUMN adapter_controls boolean NOT NULL DEFAULT false;
ALTER TABLE composer_observations DROP CONSTRAINT composer_observations_coverage_check,
    ADD CONSTRAINT composer_observations_coverage_check CHECK (coverage IN ('ready', 'unsupported', 'disabled'));
ALTER TABLE installations
    DROP CONSTRAINT installations_chatgpt_coverage_check,
    ADD CONSTRAINT installations_chatgpt_coverage_check CHECK (chatgpt_coverage IN ('ready', 'unsupported', 'disabled')),
    DROP CONSTRAINT installations_gemini_coverage_check,
    ADD CONSTRAINT installations_gemini_coverage_check CHECK (gemini_coverage IN ('ready', 'unsupported', 'disabled')),
    DROP CONSTRAINT installations_claude_coverage_check,
    ADD CONSTRAINT installations_claude_coverage_check CHECK (claude_coverage IN ('ready', 'unsupported', 'disabled'));
