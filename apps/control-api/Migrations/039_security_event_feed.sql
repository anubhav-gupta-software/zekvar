CREATE TABLE organization_event_streams (
    organization_id uuid PRIMARY KEY REFERENCES organizations(id),
    stream_id uuid NOT NULL DEFAULT gen_random_uuid(),
    last_sequence bigint NOT NULL DEFAULT 0 CHECK (last_sequence >= 0)
);

ALTER TABLE security_events ADD COLUMN stream_sequence bigint;

WITH ordered AS (
    SELECT installation_id, event_id,
        row_number() OVER (PARTITION BY organization_id ORDER BY received_at, event_id, installation_id) AS sequence
    FROM security_events
)
UPDATE security_events e SET stream_sequence = ordered.sequence
FROM ordered WHERE e.installation_id = ordered.installation_id AND e.event_id = ordered.event_id;

INSERT INTO organization_event_streams (organization_id, last_sequence)
SELECT o.id, COALESCE(max(e.stream_sequence), 0)
FROM organizations o LEFT JOIN security_events e ON e.organization_id = o.id
GROUP BY o.id;

ALTER TABLE security_events ALTER COLUMN stream_sequence SET NOT NULL,
    ADD CHECK (stream_sequence > 0);
CREATE UNIQUE INDEX security_events_feed_order ON security_events (organization_id, stream_sequence);

-- Hold the per-organization counter lock until commit so a later cursor cannot skip a writer still in flight.
CREATE FUNCTION assign_security_event_sequence() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, public AS $$
BEGIN
    INSERT INTO organization_event_streams (organization_id, last_sequence)
    VALUES (NEW.organization_id, 1)
    ON CONFLICT (organization_id) DO UPDATE SET last_sequence = organization_event_streams.last_sequence + 1
    RETURNING last_sequence INTO NEW.stream_sequence;
    RETURN NEW;
END;
$$;
CREATE TRIGGER security_event_feed_sequence BEFORE INSERT ON security_events
FOR EACH ROW EXECUTE FUNCTION assign_security_event_sequence();

CREATE TABLE event_feed_keys (
    organization_id uuid NOT NULL REFERENCES organizations(id),
    id uuid NOT NULL,
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 2 AND 64),
    token_hash text UNIQUE,
    issued_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    expires_at timestamptz NOT NULL CHECK (expires_at > issued_at),
    revoked_at timestamptz,
    PRIMARY KEY (organization_id, id),
    CHECK ((revoked_at IS NULL) = (token_hash IS NOT NULL))
);
CREATE INDEX event_feed_keys_by_organization ON event_feed_keys (organization_id, issued_at DESC, id DESC);

ALTER TABLE control_audit ADD COLUMN event_feed_key_change jsonb CHECK (jsonb_typeof(event_feed_key_change) = 'object'),
    ADD CHECK ((action IN ('event_feed_key_issued', 'event_feed_key_revoked')) = (event_feed_key_change IS NOT NULL)),
    DROP CONSTRAINT control_audit_action_check,
    ADD CONSTRAINT control_audit_action_check CHECK (action IN ('policy_published', 'policy_restored', 'grant_issued',
        'browser_enrolled', 'browser_revoked', 'app_classified', 'retention_changed', 'retention_cleanup',
        'policy_group_created', 'policy_group_assigned', 'access_issued', 'access_revoked', 'control_sso_signed_in',
        'policy_review_setting_changed', 'policy_review_requested', 'policy_review_decided', 'enrollment_batch_issued',
        'enrollment_batch_cancelled', 'event_triage_changed', 'incident_case_changed', 'security_alert_settings_changed',
        'security_alert_acknowledged', 'event_feed_key_issued', 'event_feed_key_revoked'));
