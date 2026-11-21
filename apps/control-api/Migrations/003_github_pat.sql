ALTER TABLE policy_versions ADD COLUMN github_pat_mode text NOT NULL DEFAULT 'off'
    CHECK (github_pat_mode IN ('off', 'monitor', 'warn', 'block'));

ALTER TABLE security_events ADD COLUMN rule_id text NOT NULL DEFAULT 'fixture-secret'
    CHECK (rule_id IN ('fixture-secret', 'github-classic-pat'));
