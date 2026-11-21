ALTER TABLE policy_versions
    ADD COLUMN chatgpt_upload_mode text NOT NULL DEFAULT 'off' CHECK (chatgpt_upload_mode IN ('off', 'monitor', 'block')),
    ADD COLUMN gemini_upload_mode text NOT NULL DEFAULT 'off' CHECK (gemini_upload_mode IN ('off', 'monitor', 'block'));

ALTER TABLE security_events
    DROP CONSTRAINT security_events_rule_id_check,
    ADD CONSTRAINT security_events_rule_id_check CHECK (rule_id IN
        ('fixture-secret', 'github-classic-pat', 'payment-card-number', 'ai-file-upload')),
    ADD COLUMN upload_method text,
    ADD CONSTRAINT security_events_upload_method_check CHECK (
        (rule_id = 'ai-file-upload') = (upload_method IS NOT NULL) AND
        (upload_method IS NULL OR (upload_method IN ('picker', 'drop', 'paste') AND app_id IN ('chatgpt', 'gemini')
            AND decision IN ('monitor', 'block'))));
