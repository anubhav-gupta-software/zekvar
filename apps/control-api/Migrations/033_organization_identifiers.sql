ALTER TABLE policy_versions ADD COLUMN identifier_protection jsonb NOT NULL DEFAULT '{"mode":"off","formats":[]}'::jsonb,
    ADD CONSTRAINT policy_versions_identifier_protection_check CHECK (
        jsonb_typeof(identifier_protection) = 'object'
        AND identifier_protection ?& ARRAY['mode', 'formats']
        AND jsonb_typeof(identifier_protection->'mode') = 'string'
        AND identifier_protection->>'mode' IN ('off', 'monitor', 'warn', 'block')
        AND jsonb_typeof(identifier_protection->'formats') = 'array'
        AND jsonb_array_length(identifier_protection->'formats') BETWEEN
            CASE WHEN identifier_protection->>'mode' = 'off' THEN 0 ELSE 1 END AND 16),
    DROP CONSTRAINT policy_versions_prompt_exceptions_check,
    ADD CONSTRAINT policy_versions_prompt_exceptions_check CHECK (
        jsonb_typeof(prompt_exceptions) = 'array' AND jsonb_array_length(prompt_exceptions) <= 15);

ALTER TABLE policy_deliveries ADD COLUMN identifiers boolean NOT NULL DEFAULT false;

ALTER TABLE security_events DROP CONSTRAINT security_events_rule_id_check,
    ADD CONSTRAINT security_events_rule_id_check CHECK (rule_id IN
        ('fixture-secret', 'github-classic-pat', 'payment-card-number', 'ai-file-upload', 'pem-private-key',
         'file-inspection-unavailable', 'organization-identifier'));
