ALTER TABLE security_events DROP CONSTRAINT security_events_app_id_check,
    ADD CONSTRAINT security_events_app_id_check CHECK (app_id IN ('local-prompt-fixture', 'chatgpt', 'gemini'));

ALTER TABLE installations
    ADD COLUMN gemini_coverage text CHECK (gemini_coverage IN ('ready', 'unsupported')),
    ADD COLUMN gemini_checked_at timestamptz;
