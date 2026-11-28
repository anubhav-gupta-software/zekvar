-- Provider-neutral billing: seat metering, quotes, subscriptions, invoices, credit notes, and payment provider state.

-- One row per installation per UTC day on which the installation authenticated with an unrevoked credential.
CREATE TABLE billing_seat_days (
    organization_id uuid NOT NULL REFERENCES organizations(id),
    usage_date date NOT NULL,
    installation_id uuid NOT NULL,
    PRIMARY KEY (organization_id, usage_date, installation_id),
    FOREIGN KEY (organization_id, installation_id) REFERENCES installations(organization_id, id)
);

-- Frozen daily counts. A row is written once, after its UTC day has ended, and is never changed.
CREATE TABLE billing_usage_snapshots (
    organization_id uuid NOT NULL REFERENCES organizations(id),
    usage_date date NOT NULL,
    active_seats integer NOT NULL CHECK (active_seats >= 0),
    enrolled_seats integer NOT NULL CHECK (enrolled_seats >= 0),
    frozen_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, usage_date)
);

CREATE TABLE billing_quotes (
    organization_id uuid NOT NULL REFERENCES organizations(id),
    id uuid NOT NULL,
    request_id uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('open', 'accepted', 'withdrawn')),
    plan_id text NOT NULL,
    plan_name text NOT NULL,
    term text NOT NULL CHECK (term IN ('monthly', 'annual')),
    committed_seats integer NOT NULL CHECK (committed_seats BETWEEN 1 AND 1000000),
    currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    minor_unit_digits integer NOT NULL CHECK (minor_unit_digits BETWEEN 0 AND 3),
    tier_mode text NOT NULL CHECK (tier_mode IN ('volume', 'graduated')),
    tiers jsonb NOT NULL CHECK (jsonb_typeof(tiers) = 'array'),
    price_book_version text NOT NULL,
    tax_basis_points integer NOT NULL CHECK (tax_basis_points BETWEEN 0 AND 10000),
    tax_label text NOT NULL,
    lines jsonb NOT NULL CHECK (jsonb_typeof(lines) = 'array'),
    subtotal bigint NOT NULL,
    tax_amount bigint NOT NULL,
    total bigint NOT NULL,
    customer_name text NOT NULL CHECK (char_length(customer_name) BETWEEN 2 AND 120),
    billing_email text NOT NULL CHECK (char_length(billing_email) BETWEEN 3 AND 254),
    base_subscription_id uuid,
    base_subscription_revision integer,
    -- Named Control access IDs, kept without a foreign key so credential history changes never block billing records.
    created_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    decided_at timestamptz,
    decided_by uuid,
    PRIMARY KEY (organization_id, id),
    UNIQUE (organization_id, request_id),
    CHECK ((status = 'open') = (decided_at IS NULL)),
    CHECK ((base_subscription_id IS NULL) = (base_subscription_revision IS NULL))
);
CREATE INDEX billing_quotes_by_organization ON billing_quotes (organization_id, created_at DESC, id DESC);

CREATE TABLE billing_subscriptions (
    organization_id uuid NOT NULL REFERENCES organizations(id),
    id uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('active')),
    revision integer NOT NULL DEFAULT 1 CHECK (revision >= 1),
    started_on date NOT NULL,
    -- Number of monthly usage periods that have been closed and invoiced.
    closed_periods integer NOT NULL DEFAULT 0 CHECK (closed_periods >= 0),
    quote_id uuid NOT NULL,
    pending_quote_id uuid,
    pending_effective_on date,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, id),
    FOREIGN KEY (organization_id, quote_id) REFERENCES billing_quotes(organization_id, id),
    FOREIGN KEY (organization_id, pending_quote_id) REFERENCES billing_quotes(organization_id, id),
    CHECK ((pending_quote_id IS NULL) = (pending_effective_on IS NULL))
);
CREATE UNIQUE INDEX billing_one_active_subscription ON billing_subscriptions (organization_id) WHERE status = 'active';

-- Gap-free document numbering per issuer and document kind. A number is taken in the same transaction that writes the document.
CREATE TABLE billing_document_counters (
    issuer_id text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('invoice', 'credit_note')),
    last_sequence bigint NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    PRIMARY KEY (issuer_id, kind)
);

CREATE TABLE billing_invoices (
    organization_id uuid NOT NULL REFERENCES organizations(id),
    id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('invoice', 'credit_note')),
    issuer_id text NOT NULL,
    sequence bigint NOT NULL CHECK (sequence >= 1),
    number text NOT NULL,
    subscription_id uuid NOT NULL,
    related_invoice_id uuid,
    reason text NOT NULL CHECK (reason IN ('subscription_start', 'period', 'amendment', 'correction')),
    period_key text NOT NULL,
    request_id uuid,
    period_start date,
    period_end date,
    issued_at timestamptz NOT NULL DEFAULT now(),
    due_on date,
    currency text NOT NULL,
    minor_unit_digits integer NOT NULL,
    lines jsonb NOT NULL CHECK (jsonb_typeof(lines) = 'array'),
    usage jsonb CHECK (jsonb_typeof(usage) = 'object'),
    subtotal bigint NOT NULL,
    tax_basis_points integer NOT NULL,
    tax_label text NOT NULL,
    tax_amount bigint NOT NULL,
    total bigint NOT NULL CHECK (total >= 0),
    issuer_name text NOT NULL,
    issuer_address text NOT NULL,
    customer_name text NOT NULL,
    billing_email text NOT NULL,
    plan_name text NOT NULL,
    term text NOT NULL,
    note text,
    provider text NOT NULL CHECK (provider IN ('manual', 'stripe')),
    -- Mutable collection state. Every other column is protected by billing_invoice_immutable.
    payment_status text NOT NULL CHECK (payment_status IN ('open', 'paid', 'credited', 'issued')),
    paid_at timestamptz,
    payment_reference text,
    provider_status text NOT NULL CHECK (provider_status IN ('not_applicable', 'pending', 'submitted', 'failed')),
    provider_invoice_id text,
    provider_progress integer NOT NULL DEFAULT 0,
    provider_attempts integer NOT NULL DEFAULT 0,
    provider_error text,
    provider_lease_until timestamptz,
    PRIMARY KEY (organization_id, id),
    UNIQUE (issuer_id, kind, sequence),
    UNIQUE (issuer_id, number),
    UNIQUE (organization_id, subscription_id, period_key),
    UNIQUE (organization_id, request_id),
    FOREIGN KEY (organization_id, subscription_id) REFERENCES billing_subscriptions(organization_id, id),
    FOREIGN KEY (organization_id, related_invoice_id) REFERENCES billing_invoices(organization_id, id),
    CHECK ((kind = 'credit_note') = (related_invoice_id IS NOT NULL)),
    CHECK ((kind = 'credit_note') = (payment_status = 'issued')),
    CHECK ((payment_status = 'paid') = (paid_at IS NOT NULL))
);
CREATE INDEX billing_invoices_by_organization ON billing_invoices (organization_id, issued_at DESC, id DESC);
CREATE INDEX billing_invoices_pending_provider ON billing_invoices (provider_lease_until NULLS FIRST) WHERE provider_status = 'pending';
CREATE UNIQUE INDEX billing_invoices_provider_id ON billing_invoices (provider, provider_invoice_id) WHERE provider_invoice_id IS NOT NULL;

CREATE FUNCTION billing_invoice_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    mutable text[] := ARRAY['payment_status', 'paid_at', 'payment_reference', 'provider_status', 'provider_invoice_id',
        'provider_progress', 'provider_attempts', 'provider_error', 'provider_lease_until'];
BEGIN
    IF TG_OP = 'DELETE' THEN
        -- Organization deletion may set this for its own transaction; nothing else removes an issued document.
        IF current_setting('zekvar.billing_purge', true) = 'on' THEN RETURN OLD; END IF;
        RAISE EXCEPTION 'issued billing documents cannot be deleted' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF (to_jsonb(NEW) - mutable) IS DISTINCT FROM (to_jsonb(OLD) - mutable) THEN
        RAISE EXCEPTION 'issued billing documents are immutable' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.payment_status IN ('paid', 'credited') AND NEW.payment_status IS DISTINCT FROM OLD.payment_status THEN
        RAISE EXCEPTION 'a settled invoice cannot change payment status' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER billing_invoice_immutable BEFORE UPDATE OR DELETE ON billing_invoices
    FOR EACH ROW EXECUTE FUNCTION billing_invoice_immutable();

CREATE FUNCTION billing_snapshot_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND current_setting('zekvar.billing_purge', true) = 'on' THEN RETURN OLD; END IF;
    RAISE EXCEPTION 'frozen usage snapshots are immutable' USING ERRCODE = 'integrity_constraint_violation';
END $$;
CREATE TRIGGER billing_snapshot_immutable BEFORE UPDATE OR DELETE ON billing_usage_snapshots
    FOR EACH ROW EXECUTE FUNCTION billing_snapshot_immutable();

CREATE TABLE billing_provider_customers (
    organization_id uuid NOT NULL REFERENCES organizations(id),
    provider text NOT NULL CHECK (provider IN ('stripe')),
    customer_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, provider)
);

-- Verified provider webhook events, kept so a replayed delivery has no effect.
CREATE TABLE billing_provider_events (
    provider text NOT NULL CHECK (provider IN ('stripe')),
    event_id text NOT NULL,
    event_type text NOT NULL,
    organization_id uuid REFERENCES organizations(id),
    invoice_id uuid,
    outcome text NOT NULL CHECK (outcome IN ('applied', 'ignored')),
    received_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, event_id)
);
CREATE INDEX billing_provider_events_by_organization ON billing_provider_events (organization_id) WHERE organization_id IS NOT NULL;

ALTER TABLE control_audit ADD COLUMN billing_change jsonb CHECK (jsonb_typeof(billing_change) = 'object');
-- Control extends the audit action list with billing_changed at every startup (ControlStore.EnsureBillingAuditAction),
-- so an older migration that redefines the list cannot drop it.
ALTER TABLE control_audit ADD CONSTRAINT control_audit_billing_record_check
    CHECK ((action = 'billing_changed') = (billing_change IS NOT NULL));
