-- The billing contact email on quotes and invoices is sealed with the organization's data key (Control__DataKeys), so the stored
-- value is an envelope that is longer than an address. Quote and invoice contents stay immutable: the invoice trigger permits a
-- change to billing_email only inside a transaction that sets zekvar.billing_reseal, which Control does at startup solely to seal
-- plaintext rows and to re-seal rows under a retired key. Every other column remains protected in that same transaction.
ALTER TABLE billing_quotes DROP CONSTRAINT billing_quotes_billing_email_check;
ALTER TABLE billing_quotes ADD CONSTRAINT billing_quotes_billing_email_check CHECK (char_length(billing_email) BETWEEN 3 AND 600);

CREATE OR REPLACE FUNCTION billing_invoice_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    mutable text[] := ARRAY['payment_status', 'paid_at', 'payment_reference', 'provider_status', 'provider_invoice_id',
        'provider_progress', 'provider_attempts', 'provider_error', 'provider_lease_until'];
BEGIN
    IF TG_OP = 'DELETE' THEN
        -- Organization deletion may set this for its own transaction; nothing else removes an issued document.
        IF current_setting('zekvar.billing_purge', true) = 'on' THEN RETURN OLD; END IF;
        RAISE EXCEPTION 'issued billing documents cannot be deleted' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    -- Re-sealing replaces the stored form of the contact email only; it never changes any other field.
    IF current_setting('zekvar.billing_reseal', true) = 'on' THEN mutable := array_append(mutable, 'billing_email'); END IF;
    IF (to_jsonb(NEW) - mutable) IS DISTINCT FROM (to_jsonb(OLD) - mutable) THEN
        RAISE EXCEPTION 'issued billing documents are immutable' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.payment_status IN ('paid', 'credited') AND NEW.payment_status IS DISTINCT FROM OLD.payment_status THEN
        RAISE EXCEPTION 'a settled invoice cannot change payment status' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END $$;
