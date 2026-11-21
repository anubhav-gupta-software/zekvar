DROP INDEX events_by_organization_recency;
CREATE INDEX events_by_organization_recency ON security_events (organization_id, received_at DESC, event_id DESC, installation_id DESC);
