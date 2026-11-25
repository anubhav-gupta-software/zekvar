ALTER TABLE policy_versions
    ADD COLUMN claude_upload_mode text NOT NULL DEFAULT 'off' CHECK (claude_upload_mode IN ('off', 'monitor', 'block')),
    ADD COLUMN claude_upload_types text[] NOT NULL DEFAULT '{}' CHECK (cardinality(claude_upload_types) <= 25),
    ADD COLUMN claude_file_content_mode text NOT NULL DEFAULT 'off' CHECK (claude_file_content_mode IN ('off', 'monitor', 'block'));

ALTER TABLE policy_deliveries ADD COLUMN claude_files boolean NOT NULL DEFAULT false;

ALTER TABLE security_events DROP CONSTRAINT security_events_upload_method_check,
    ADD CONSTRAINT security_events_upload_method_check CHECK (
        (upload_method IS NULL AND rule_id NOT IN ('ai-file-upload', 'file-inspection-unavailable')) OR
        (upload_method IS NOT NULL AND upload_method IN ('picker', 'drop', 'paste') AND app_id IN ('chatgpt', 'gemini', 'claude') AND
            (decision = 'block' OR (decision = 'monitor' AND rule_id <> 'file-inspection-unavailable'))));
