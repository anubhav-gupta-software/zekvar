ALTER TABLE policy_versions ADD COLUMN claude_prompt_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE policy_deliveries ADD COLUMN claude_prompt boolean NOT NULL DEFAULT false;

ALTER TABLE installations
    ADD COLUMN claude_coverage text CHECK (claude_coverage IN ('ready', 'unsupported')),
    ADD COLUMN claude_checked_at timestamptz,
    ADD COLUMN claude_coverage_version integer CHECK (claude_coverage_version > 0);

ALTER TABLE security_events DROP CONSTRAINT security_events_app_id_check,
    ADD CONSTRAINT security_events_app_id_check CHECK (app_id IN ('local-prompt-fixture', 'chatgpt', 'claude', 'gemini'));
