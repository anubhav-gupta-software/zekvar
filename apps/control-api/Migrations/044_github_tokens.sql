ALTER TABLE policy_versions ADD COLUMN github_token_mode text NOT NULL DEFAULT 'off'
    CHECK (github_token_mode IN ('off', 'monitor', 'warn', 'block')),
    DROP CONSTRAINT policy_versions_prompt_exceptions_check,
    ADD CONSTRAINT policy_versions_prompt_exceptions_check CHECK (
        jsonb_typeof(prompt_exceptions) = 'array' AND jsonb_array_length(prompt_exceptions) <= 21
    );

ALTER TABLE policy_deliveries ADD COLUMN github_token boolean NOT NULL DEFAULT false;

ALTER TABLE security_events DROP CONSTRAINT security_events_rule_id_check,
    ADD CONSTRAINT security_events_rule_id_check CHECK (rule_id IN (
        'fixture-secret', 'github-classic-pat', 'payment-card-number', 'ai-file-upload', 'pem-private-key',
        'file-inspection-unavailable', 'organization-identifier', 'us-social-security-number', 'clipboard-inspection-unavailable',
        'github-app-or-fine-grained-token'
    ));
