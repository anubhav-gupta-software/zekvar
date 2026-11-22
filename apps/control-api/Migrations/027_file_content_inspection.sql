ALTER TABLE policy_versions ADD COLUMN chatgpt_file_inspection boolean NOT NULL DEFAULT false,
    ADD COLUMN gemini_file_inspection boolean NOT NULL DEFAULT false;

ALTER TABLE policy_deliveries ADD COLUMN file_inspection boolean NOT NULL DEFAULT false;

ALTER TABLE security_events DROP CONSTRAINT security_events_upload_method_check,
    ADD CONSTRAINT security_events_upload_method_check CHECK (
        (upload_method IS NULL AND rule_id <> 'ai-file-upload') OR
        (upload_method IS NOT NULL AND upload_method IN ('picker', 'drop', 'paste') AND app_id IN ('chatgpt', 'gemini') AND
            (decision = 'monitor' OR (rule_id = 'ai-file-upload' AND decision = 'block'))));
