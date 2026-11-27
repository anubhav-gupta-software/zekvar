-- Health identifiers: one versioned mode for NPI, DEA, and MBI checks plus organization-defined medical record number formats.
-- Formats reuse the organization identifier prefix-and-digit shape. Events keep only the rule ID and category.
ALTER TABLE policy_versions
    ADD COLUMN health_protection jsonb NOT NULL DEFAULT '{"mode":"off","recordFormats":[]}'::jsonb,
    ADD CONSTRAINT policy_versions_health_protection_check CHECK (
        jsonb_typeof(health_protection) = 'object'
        AND health_protection ?& ARRAY['mode', 'recordFormats']
        AND jsonb_typeof(health_protection->'mode') = 'string'
        AND health_protection->>'mode' IN ('off', 'monitor', 'warn', 'block')
        AND jsonb_typeof(health_protection->'recordFormats') = 'array'
        AND jsonb_array_length(health_protection->'recordFormats') <= 16);

ALTER TABLE policy_deliveries ADD COLUMN health_identifiers boolean NOT NULL DEFAULT false;

ALTER TABLE security_events DROP CONSTRAINT security_events_rule_id_check,
    ADD CONSTRAINT security_events_rule_id_check CHECK (rule_id IN (
        'fixture-secret', 'github-classic-pat', 'payment-card-number', 'ai-file-upload', 'pem-private-key',
        'file-inspection-unavailable', 'organization-identifier', 'us-social-security-number', 'clipboard-inspection-unavailable',
        'github-app-or-fine-grained-token', 'aws-access-key-id', 'slack-token', 'stripe-live-secret-key', 'google-api-key',
        'openai-api-key', 'anthropic-api-key', 'organization-classification-rule', 'us-national-provider-identifier',
        'dea-registration-number', 'medicare-beneficiary-identifier', 'medical-record-number'
    ));
