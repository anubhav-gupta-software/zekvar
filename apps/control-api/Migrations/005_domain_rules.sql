ALTER TABLE policy_versions
    ADD COLUMN allowed_domains text[] NOT NULL DEFAULT '{}',
    ADD COLUMN blocked_domains text[] NOT NULL DEFAULT '{}',
    ADD CONSTRAINT policy_domain_rules CHECK (
        cardinality(allowed_domains) + cardinality(blocked_domains) <= 50
        AND NOT (allowed_domains && blocked_domains)
    );
