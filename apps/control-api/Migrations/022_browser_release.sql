ALTER TABLE installations
    ADD COLUMN extension_version text,
    ADD COLUMN extension_version_reported_at timestamptz,
    ADD CONSTRAINT installations_extension_report_check CHECK (
        (extension_version IS NULL AND extension_version_reported_at IS NULL) OR
        (extension_version IS NOT NULL AND extension_version_reported_at IS NOT NULL AND
            extension_version ~ '^(0|[1-9][0-9]{0,4})(\.(0|[1-9][0-9]{0,4})){0,3}$')
    );
