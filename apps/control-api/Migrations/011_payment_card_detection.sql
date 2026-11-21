ALTER TABLE policy_versions ADD COLUMN payment_card_mode text NOT NULL DEFAULT 'off'
    CHECK (payment_card_mode IN ('off', 'monitor', 'warn', 'block'));

ALTER TABLE security_events DROP CONSTRAINT security_events_rule_id_check,
    ADD CONSTRAINT security_events_rule_id_check CHECK (rule_id IN ('fixture-secret', 'github-classic-pat', 'payment-card-number'));
