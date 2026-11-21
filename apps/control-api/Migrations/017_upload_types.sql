ALTER TABLE policy_versions
    ADD COLUMN chatgpt_upload_types text[] NOT NULL DEFAULT '{}' CHECK (cardinality(chatgpt_upload_types) <= 25),
    ADD COLUMN gemini_upload_types text[] NOT NULL DEFAULT '{}' CHECK (cardinality(gemini_upload_types) <= 25);
