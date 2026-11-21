ALTER TABLE policy_versions
    ADD COLUMN allowed_paths text[] NOT NULL DEFAULT '{}',
    ADD COLUMN blocked_paths text[] NOT NULL DEFAULT '{}',
    ADD CONSTRAINT navigation_rule_limit CHECK (
        cardinality(allowed_domains) + cardinality(blocked_domains) +
        cardinality(allowed_paths) + cardinality(blocked_paths) <= 50
    ),
    ADD CONSTRAINT distinct_path_actions CHECK (NOT (allowed_paths && blocked_paths));
