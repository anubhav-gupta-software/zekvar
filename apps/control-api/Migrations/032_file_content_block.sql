ALTER TABLE policy_versions ADD COLUMN chatgpt_file_content_block boolean NOT NULL DEFAULT false,
    ADD COLUMN gemini_file_content_block boolean NOT NULL DEFAULT false,
    ADD CHECK (NOT chatgpt_file_content_block OR chatgpt_file_inspection),
    ADD CHECK (NOT gemini_file_content_block OR gemini_file_inspection);

ALTER TABLE policy_deliveries ADD COLUMN file_content_block boolean NOT NULL DEFAULT false;

ALTER TABLE security_events DROP CONSTRAINT security_events_rule_id_check,
    ADD CONSTRAINT security_events_rule_id_check CHECK (rule_id IN
        ('fixture-secret', 'github-classic-pat', 'payment-card-number', 'ai-file-upload', 'pem-private-key', 'file-inspection-unavailable')),
    DROP CONSTRAINT security_events_upload_method_check,
    ADD CONSTRAINT security_events_upload_method_check CHECK (
        (upload_method IS NULL AND rule_id NOT IN ('ai-file-upload', 'file-inspection-unavailable')) OR
        (upload_method IS NOT NULL AND upload_method IN ('picker', 'drop', 'paste') AND app_id IN ('chatgpt', 'gemini') AND
            (decision = 'block' OR (decision = 'monitor' AND rule_id <> 'file-inspection-unavailable'))));
