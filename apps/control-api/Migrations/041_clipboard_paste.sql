ALTER TABLE policy_versions ADD COLUMN clipboard_mode text NOT NULL DEFAULT 'off'
    CHECK (clipboard_mode IN ('off', 'monitor', 'block'));
ALTER TABLE policy_deliveries ADD COLUMN clipboard_paste boolean NOT NULL DEFAULT false;
ALTER TABLE security_events ADD COLUMN clipboard_paste boolean NOT NULL DEFAULT false,
    ADD CHECK (NOT clipboard_paste OR (upload_method IS NULL AND app_id IN ('chatgpt', 'gemini', 'claude') AND decision IN ('monitor', 'block'))),
    DROP CONSTRAINT security_events_rule_id_check,
    ADD CONSTRAINT security_events_rule_id_check CHECK (rule_id IN (
        'fixture-secret', 'github-classic-pat', 'payment-card-number', 'ai-file-upload', 'pem-private-key',
        'file-inspection-unavailable', 'organization-identifier', 'us-social-security-number', 'clipboard-inspection-unavailable'
    )),
    ADD CHECK (rule_id <> 'clipboard-inspection-unavailable' OR clipboard_paste AND decision = 'block');
