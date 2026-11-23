ALTER TABLE policy_versions ADD COLUMN blocked_ai_app_hosts text[] NOT NULL DEFAULT '{}',
    ADD CHECK (cardinality(allowed_domains) + cardinality(blocked_domains) + cardinality(allowed_paths) +
        cardinality(blocked_paths) + cardinality(blocked_ai_app_hosts) <= 50);
ALTER TABLE policy_deliveries ADD COLUMN ai_app_access boolean NOT NULL DEFAULT false;
