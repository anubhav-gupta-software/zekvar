CREATE TABLE organization_retention (
    organization_id uuid PRIMARY KEY REFERENCES organizations(id),
    event_days integer CHECK (event_days BETWEEN 1 AND 3650),
    observation_days integer CHECK (observation_days BETWEEN 1 AND 3650),
    audit_days integer CHECK (audit_days BETWEEN 1 AND 3650),
    event_floor timestamptz,
    observation_floor timestamptz,
    audit_floor timestamptz
);

CREATE VIEW retention_cutoffs AS
SELECT organization_id,
    GREATEST(event_floor, now() - event_days * interval '24 hours') AS event_cutoff,
    GREATEST(observation_floor, now() - observation_days * interval '24 hours') AS observation_cutoff,
    GREATEST(audit_floor, now() - audit_days * interval '24 hours') AS audit_cutoff
FROM organization_retention;

CREATE INDEX security_events_by_expiration ON security_events (organization_id, LEAST(occurred_at, received_at));
CREATE INDEX ai_app_observations_by_expiration ON ai_app_observations (organization_id, observed_at);

ALTER TABLE control_audit DROP CONSTRAINT control_audit_action_check,
    ADD CONSTRAINT control_audit_action_check CHECK (action IN ('policy_published', 'policy_restored', 'grant_issued',
        'browser_enrolled', 'browser_revoked', 'app_classified', 'retention_changed', 'retention_cleanup')),
    ADD COLUMN retention jsonb CHECK (jsonb_typeof(retention) = 'object'),
    ADD COLUMN cleanup jsonb CHECK (jsonb_typeof(cleanup) = 'object'),
    ADD CONSTRAINT control_audit_lifecycle_payload_check CHECK ((retention IS NOT NULL) = (action = 'retention_changed')
        AND (cleanup IS NOT NULL) = (action = 'retention_cleanup'));
