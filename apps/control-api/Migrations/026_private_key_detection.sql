ALTER TABLE policy_versions ADD COLUMN private_key_mode text NOT NULL DEFAULT 'off'
    CHECK (private_key_mode IN ('off', 'monitor', 'warn', 'block')),
    DROP CONSTRAINT policy_versions_prompt_exceptions_check,
    ADD CONSTRAINT policy_versions_prompt_exceptions_check
        CHECK (jsonb_typeof(prompt_exceptions) = 'array' AND jsonb_array_length(prompt_exceptions) <= 12);

ALTER TABLE policy_deliveries ADD COLUMN private_key boolean NOT NULL DEFAULT false;

ALTER TABLE security_events DROP CONSTRAINT security_events_rule_id_check,
    ADD CONSTRAINT security_events_rule_id_check CHECK (rule_id IN
        ('fixture-secret', 'github-classic-pat', 'payment-card-number', 'ai-file-upload', 'pem-private-key'));
