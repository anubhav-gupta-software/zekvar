CREATE TABLE extension_access_alert_settings (
    organization_id uuid PRIMARY KEY REFERENCES organizations(id),
    enabled boolean NOT NULL DEFAULT false,
    revision integer NOT NULL DEFAULT 0 CHECK (revision >= 0)
);

ALTER TABLE extension_inventory_change_batches
    ADD COLUMN alert_id uuid,
    ADD COLUMN alert_acknowledged_at timestamptz,
    ADD CHECK (alert_acknowledged_at IS NULL OR alert_id IS NOT NULL);

CREATE UNIQUE INDEX extension_access_alert_identity ON extension_inventory_change_batches (organization_id, alert_id)
    WHERE alert_id IS NOT NULL;
CREATE INDEX extension_access_alert_inbox ON extension_inventory_change_batches (organization_id, received_at DESC, alert_id DESC)
    WHERE alert_id IS NOT NULL;
