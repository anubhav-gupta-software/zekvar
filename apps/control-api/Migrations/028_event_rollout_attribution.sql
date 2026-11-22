ALTER TABLE policy_deliveries ADD COLUMN rollout_group_id uuid,
    ADD COLUMN rollout_attributed boolean NOT NULL DEFAULT false,
    ADD CHECK (rollout_attributed OR rollout_group_id IS NULL),
    ADD FOREIGN KEY (organization_id, rollout_group_id) REFERENCES policy_groups(organization_id, id);

-- A group-specific policy identifies its group. A baseline policy may be inherited.
UPDATE policy_deliveries d
SET rollout_attributed = true,
    rollout_group_id = CASE WHEN p.policy_group_id IS NOT NULL THEN p.policy_group_id
        WHEN d.assignment_version = 0 OR d.exception_scope THEN NULL ELSE i.policy_group_id END
FROM installations i, policy_versions p
WHERE i.organization_id = d.organization_id AND i.id = d.installation_id
    AND p.organization_id = d.organization_id AND p.version = d.policy_version
    AND (p.policy_group_id IS NOT NULL OR d.assignment_version = 0 OR d.exception_scope
        OR d.assignment_version = i.assignment_version);

ALTER TABLE security_events ADD COLUMN rollout_group_id uuid,
    ADD COLUMN rollout_attributed boolean NOT NULL DEFAULT false,
    ADD CHECK (rollout_attributed OR rollout_group_id IS NULL),
    ADD FOREIGN KEY (organization_id, rollout_group_id) REFERENCES policy_groups(organization_id, id);

-- Earlier events did not retain their assignment version. Keep uncertain rows unattributed.
UPDATE security_events e
SET rollout_attributed = true, rollout_group_id = p.policy_group_id
FROM installations i, policy_versions p
WHERE i.organization_id = e.organization_id AND i.id = e.installation_id
    AND p.organization_id = e.organization_id AND p.version = e.policy_version
    AND (p.policy_group_id IS NOT NULL OR i.assignment_version = 0);

CREATE INDEX events_by_recorded_rollout ON security_events
    (organization_id, rollout_attributed, rollout_group_id, received_at DESC, event_id DESC, installation_id DESC);
