ALTER TABLE policy_versions
    ADD COLUMN cloud_credential_mode text NOT NULL DEFAULT 'off'
        CHECK (cloud_credential_mode IN ('off', 'monitor', 'warn', 'block')),
    ADD COLUMN classification_protection jsonb NOT NULL DEFAULT '{"mode":"off","terms":[]}'::jsonb,
    ADD CONSTRAINT policy_versions_classification_protection_check CHECK (
        jsonb_typeof(classification_protection) = 'object'
        AND classification_protection ?& ARRAY['mode', 'terms']
        AND jsonb_typeof(classification_protection->'mode') = 'string'
        AND classification_protection->>'mode' IN ('off', 'monitor', 'warn', 'block')
        AND jsonb_typeof(classification_protection->'terms') = 'array'
        AND jsonb_array_length(classification_protection->'terms') BETWEEN
            CASE WHEN classification_protection->>'mode' = 'off' THEN 0 ELSE 1 END AND 16);

ALTER TABLE policy_deliveries ADD COLUMN detection_rules boolean NOT NULL DEFAULT false;

ALTER TABLE security_events DROP CONSTRAINT security_events_rule_id_check,
    ADD CONSTRAINT security_events_rule_id_check CHECK (rule_id IN (
        'fixture-secret', 'github-classic-pat', 'payment-card-number', 'ai-file-upload', 'pem-private-key',
        'file-inspection-unavailable', 'organization-identifier', 'us-social-security-number', 'clipboard-inspection-unavailable',
        'github-app-or-fine-grained-token', 'aws-access-key-id', 'slack-token', 'stripe-live-secret-key', 'google-api-key',
        'openai-api-key', 'anthropic-api-key', 'organization-classification-rule'
    ));
