-- SOC 2 evidence is append-only. Access-log rows may only advance their rollup counters (records, requests, last_at) or finish an export
-- (completed); attestations never change. Deletion needs a transaction-local flag that only the retention job (after the 400-day floor)
-- and the organization deletion job set, the same pattern as zekvar.billing_purge.
CREATE OR REPLACE FUNCTION control_access_log_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    counters text[] := ARRAY['records', 'requests', 'last_at', 'completed'];
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF current_setting('zekvar.evidence_purge', true) = 'on' THEN RETURN OLD; END IF;
        RAISE EXCEPTION 'SOC 2 evidence cannot be deleted' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF (to_jsonb(NEW) - counters) IS NOT DISTINCT FROM (to_jsonb(OLD) - counters)
        AND NEW.requests >= OLD.requests AND NEW.records >= OLD.records AND NEW.last_at >= OLD.last_at
        AND (NEW.completed OR NOT OLD.completed) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'SOC 2 evidence cannot be changed' USING ERRCODE = 'integrity_constraint_violation';
END $$;

CREATE OR REPLACE FUNCTION control_attestations_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF current_setting('zekvar.evidence_purge', true) = 'on' THEN RETURN OLD; END IF;
        RAISE EXCEPTION 'SOC 2 evidence cannot be deleted' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RAISE EXCEPTION 'SOC 2 evidence cannot be changed' USING ERRCODE = 'integrity_constraint_violation';
END $$;

DROP TRIGGER IF EXISTS control_access_log_append_only ON control_access_log;
CREATE TRIGGER control_access_log_append_only BEFORE UPDATE OR DELETE ON control_access_log
    FOR EACH ROW EXECUTE FUNCTION control_access_log_append_only();
DROP TRIGGER IF EXISTS control_attestations_append_only ON control_attestations;
CREATE TRIGGER control_attestations_append_only BEFORE UPDATE OR DELETE ON control_attestations
    FOR EACH ROW EXECUTE FUNCTION control_attestations_append_only();
