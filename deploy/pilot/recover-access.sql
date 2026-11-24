-- The restored snapshot may predate access changes. Require fresh enrollment and delegated access.
-- Control seeds owner credentials from the recovery deployment configuration at startup.
DELETE FROM public.admin_memberships;

UPDATE public.enrollment_grants SET expires_at = CURRENT_TIMESTAMP
WHERE redeemed_at IS NULL AND expires_at > CURRENT_TIMESTAMP;

DO $$
BEGIN
    IF to_regclass('public.enrollment_batches') IS NOT NULL THEN
        UPDATE public.enrollment_batches SET cancelled_at = CURRENT_TIMESTAMP
        WHERE cancelled_at IS NULL AND expires_at > CURRENT_TIMESTAMP AND EXISTS (
            SELECT 1 FROM public.enrollment_grants g WHERE g.organization_id = enrollment_batches.organization_id
                AND g.batch_id = enrollment_batches.id AND g.redeemed_at IS NULL);
    END IF;
END;
$$;

WITH revoked AS (
    UPDATE public.control_access SET revoked_at = CURRENT_TIMESTAMP, token_hash = NULL
    WHERE revoked_at IS NULL RETURNING organization_id, id, revoked_at
)
INSERT INTO public.control_audit (organization_id, occurred_at, action, subject_access_id)
SELECT organization_id, revoked_at, 'access_revoked', id FROM revoked;

DO $$
BEGIN
    IF to_regclass('public.control_sso_sessions') IS NOT NULL THEN
        DELETE FROM public.control_sso_sessions;
    END IF;
END;
$$;

WITH revoked AS (
    UPDATE public.installations SET revoked_at = CURRENT_TIMESTAMP
    WHERE revoked_at IS NULL RETURNING organization_id, id, revoked_at
)
INSERT INTO public.control_audit (organization_id, occurred_at, action, installation_id)
SELECT organization_id, revoked_at, 'browser_revoked', id FROM revoked;

DO $$
BEGIN
    -- Every restored installation is revoked. Fresh enrollment starts with no inventory evidence.
    IF to_regclass('public.extension_inventory_change_batches') IS NOT NULL THEN
        DELETE FROM public.extension_inventory_change_batches;
    END IF;
    IF to_regclass('public.extension_inventory_snapshots') IS NOT NULL THEN
        DELETE FROM public.extension_inventory_snapshots;
    END IF;
    IF to_regclass('public.composer_observations') IS NOT NULL THEN
        DELETE FROM public.composer_observations;
    END IF;
END;
$$;

WITH cancelled AS (
    UPDATE public.policy_reviews SET status = 'cancelled', decided_at = CURRENT_TIMESTAMP
    WHERE status = 'pending' RETURNING organization_id, id, operation, group_id, base_version
)
INSERT INTO public.control_audit (organization_id, action, review_change)
SELECT organization_id, 'policy_review_decided', jsonb_build_object(
    'reviewId', id, 'operation', operation, 'status', 'cancelled', 'groupId', group_id, 'baseVersion', base_version
) FROM cancelled;

DO $$
BEGIN
    IF to_regclass('public.alert_webhook_deliveries') IS NOT NULL THEN
        UPDATE public.alert_webhook_deliveries
            SET status = 'failed', failure_code = 'recovery_cancelled', lease_id = NULL, lease_until = NULL
        WHERE status = 'pending';
    END IF;
END;
$$;

DO $$
BEGIN
    IF to_regclass('public.event_feed_keys') IS NOT NULL THEN
        WITH revoked AS (
            UPDATE public.event_feed_keys SET revoked_at = CURRENT_TIMESTAMP, token_hash = NULL
            WHERE revoked_at IS NULL RETURNING organization_id, id, display_name, revoked_at
        )
        INSERT INTO public.control_audit (organization_id, occurred_at, action, event_feed_key_change)
        SELECT organization_id, revoked_at, 'event_feed_key_revoked', jsonb_build_object('keyId', id, 'name', display_name) FROM revoked;
        UPDATE public.organization_event_streams SET stream_id = gen_random_uuid();
    END IF;
END;
$$;

COMMIT;
