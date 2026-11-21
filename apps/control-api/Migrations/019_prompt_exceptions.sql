ALTER TABLE policy_versions ADD COLUMN prompt_exceptions jsonb NOT NULL DEFAULT '[]'
    CHECK (jsonb_typeof(prompt_exceptions) = 'array' AND jsonb_array_length(prompt_exceptions) <= 6);

ALTER TABLE policy_deliveries ADD COLUMN exception_scope boolean NOT NULL DEFAULT false,
    DROP CONSTRAINT policy_deliveries_assignment_version_check,
    ADD CONSTRAINT policy_deliveries_assignment_version_check CHECK (assignment_version >= 0);

ALTER TABLE security_events DROP CONSTRAINT security_events_decision_check,
    ADD CONSTRAINT security_events_decision_check
        CHECK (decision IN ('monitor', 'warn', 'block', 'warn_override', 'exception_applied'));
