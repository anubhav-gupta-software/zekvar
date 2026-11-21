ALTER TABLE security_events
    ADD COLUMN app_id text NOT NULL DEFAULT 'local-prompt-fixture'
        CHECK (app_id IN ('local-prompt-fixture', 'chatgpt'));

ALTER TABLE installations
    ADD COLUMN chatgpt_coverage text CHECK (chatgpt_coverage IN ('ready', 'unsupported')),
    ADD COLUMN chatgpt_checked_at timestamptz;
