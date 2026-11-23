ALTER TABLE policy_versions ADD COLUMN browser_hardening jsonb NOT NULL DEFAULT
    '{"safeBrowsing":"preserve","downloads":"preserve","lockSafeBrowsingWarnings":false,"disableGuest":false,
      "disableIncognito":false,"disablePasswordSaving":false,"disableSync":false}'::jsonb,
    ADD CHECK (jsonb_typeof(browser_hardening) = 'object');
