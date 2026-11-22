CREATE INDEX ai_events_by_organization_time ON security_events (organization_id, occurred_at)
    INCLUDE (received_at, app_id, rule_id, decision) WHERE app_id <> 'local-prompt-fixture';
