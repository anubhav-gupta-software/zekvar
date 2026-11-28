using System.Text.Json;
using Npgsql;

namespace Control;

// Provider-neutral billing. Seat metering rule (proposed, needs founder sign-off):
// a browser installation is an active seat on a UTC day when its credential is unrevoked at the end of that day and it
// checked in with Control on that day or any of the previous six days. Billable seats for a monthly usage period are the
// highest daily active count in the period. Daily counts are frozen once the day has ended, so a period can be reconciled
// after security event retention has deleted the underlying events.
internal sealed partial class ControlStore
{
    public BillingSettings Billing { get; init; } = new();
    public IPaymentCollector Collector { get; init; } = new ManualCollector();

    private const int MaxProviderAttempts = 8;

    // Extends the audit action list in place, so it composes with any migration that also extends or redefines the list.
    private const string EnsureBillingAuditAction = """
        DO $$
        DECLARE
            definition text;
            actions text[];
        BEGIN
            SELECT pg_get_constraintdef(oid) INTO definition FROM pg_constraint
            WHERE conrelid = 'control_audit'::regclass AND conname = 'control_audit_action_check';
            IF definition IS NOT NULL AND position('billing_changed' IN definition) = 0 THEN
                SELECT array_agg(DISTINCT value ORDER BY value) INTO actions FROM (
                    SELECT m[1] AS value FROM regexp_matches(definition, '''([a-z_]+)''::text', 'g') AS m
                    UNION SELECT unnest(string_to_array(m[1], ',')) FROM regexp_matches(definition, '''\{([a-z_,]+)\}''', 'g') AS m
                    UNION SELECT 'billing_changed'
                ) listed;
                EXECUTE format('ALTER TABLE control_audit DROP CONSTRAINT control_audit_action_check, '
                    'ADD CONSTRAINT control_audit_action_check CHECK (action = ANY (%L::text[]))', actions);
            END IF;
        END $$;
        """;
    private const int SeatDayRetentionDays = 400;
    // Days freeze ten minutes after UTC midnight so a check-in committing at the boundary is never missed.
    private const string GraceToday = "((now() - interval '10 minutes') AT TIME ZONE 'UTC')::date";
    private const string ActiveSeatsOn = """
        (SELECT count(DISTINCT s.installation_id)::integer FROM billing_seat_days s
         JOIN installations i ON i.organization_id = s.organization_id AND i.id = s.installation_id
         WHERE s.organization_id = $1 AND s.usage_date BETWEEN day - 6 AND day
            AND (i.revoked_at IS NULL OR i.revoked_at >= (day + 1)::timestamp AT TIME ZONE 'UTC'))
        """;
    private const string EnrolledSeatsOn = """
        (SELECT count(*)::integer FROM installations i WHERE i.organization_id = $1
            AND i.enrolled_at < (day + 1)::timestamp AT TIME ZONE 'UTC'
            AND (i.revoked_at IS NULL OR i.revoked_at >= (day + 1)::timestamp AT TIME ZONE 'UTC'))
        """;

    private sealed record QuoteRow(Guid Id, string Status, string PlanId, string PlanName, string Term, int Seats, string Currency, int Digits,
        string TierMode, BillingTier[] Tiers, string PriceBookVersion, int TaxBasisPoints, string TaxLabel, BillingLine[] Lines, long Subtotal,
        long TaxAmount, long Total, string CustomerName, string BillingEmail, Guid? BaseSubscriptionId, int? BaseRevision, DateTime CreatedAt,
        DateTime ExpiresAt, DateTime? DecidedAt, bool Expired)
    {
        public BillingQuote View() => new(Id, Status == "open" && Expired ? "expired" : Status, PlanId, PlanName, Term, Seats, Currency, Digits,
            TierMode, PriceBookVersion, Lines, Subtotal, TaxBasisPoints, TaxLabel, TaxAmount, Total, CustomerName, BillingEmail,
            BaseSubscriptionId is not null, CreatedAt, ExpiresAt, DecidedAt);
    }

    // The billing contact email on quotes and invoices is sealed with the organization's data key when one is configured.
    // A sealed value is an envelope without an at sign, so it cannot be mistaken for a plaintext address.
    private const string BillingEmailField = "billing_documents.billing_email";

    private string SealBillingEmail(Guid organizationId, string email) =>
        protection.Enabled ? protection.Seal(email, organizationId, BillingEmailField) : email;

    private string OpenBillingEmail(Guid organizationId, string stored) =>
        stored.StartsWith("zk1:", StringComparison.Ordinal) && !stored.Contains('@') ? protection.Open(stored, organizationId, BillingEmailField) : stored;

    private sealed record SubscriptionRow(Guid Id, int Revision, DateOnly StartedOn, int ClosedPeriods, Guid QuoteId, Guid? PendingQuoteId,
        DateOnly? PendingEffectiveOn);

    private sealed record DocumentDraft(string Kind, string Reason, string PeriodKey, Guid SubscriptionId, Guid? RelatedInvoiceId, Guid? RequestId,
        DateOnly? PeriodStart, DateOnly? PeriodEnd, IReadOnlyList<BillingLine> Lines, BillingUsagePeriod? Usage, string Currency, int Digits,
        int TaxBasisPoints, string TaxLabel, long TaxAmount, string CustomerName, string BillingEmail, string PlanName, string Term, string? Note,
        bool Automatic, Guid? ActorId);

    private const string QuoteColumns = """
        id, status, plan_id, plan_name, term, committed_seats, currency, minor_unit_digits, tier_mode, tiers::text, price_book_version,
        tax_basis_points, tax_label, lines::text, subtotal, tax_amount, total, customer_name, billing_email, base_subscription_id,
        base_subscription_revision, created_at, expires_at, decided_at, expires_at <= now()
        """;

    private QuoteRow ReadQuote(NpgsqlDataReader rows, Guid organizationId) => new(rows.GetGuid(0), rows.GetString(1), rows.GetString(2), rows.GetString(3),
        rows.GetString(4), rows.GetInt32(5), rows.GetString(6), rows.GetInt32(7), rows.GetString(8),
        JsonSerializer.Deserialize<BillingTier[]>(rows.GetString(9), JsonSerializerOptions.Web)!, rows.GetString(10), rows.GetInt32(11),
        rows.GetString(12), JsonSerializer.Deserialize<BillingLine[]>(rows.GetString(13), JsonSerializerOptions.Web)!, rows.GetInt64(14),
        rows.GetInt64(15), rows.GetInt64(16), rows.GetString(17), OpenBillingEmail(organizationId, rows.GetString(18)), rows.IsDBNull(19) ? null : rows.GetGuid(19),
        rows.IsDBNull(20) ? null : rows.GetInt32(20), rows.GetDateTime(21), rows.GetDateTime(22), rows.IsDBNull(23) ? null : rows.GetDateTime(23),
        rows.GetBoolean(24));

    private static (DateOnly Start, DateOnly End) CommitmentPeriod(DateOnly startedOn, string term, int usageIndex)
    {
        if (term == "monthly") return (BillingMath.PeriodStart(startedOn, usageIndex), BillingMath.PeriodStart(startedOn, usageIndex + 1));
        var year = usageIndex / 12;
        return (BillingMath.PeriodStart(startedOn, year * 12), BillingMath.PeriodStart(startedOn, year * 12 + 12));
    }

    private static int UsageIndex(DateOnly startedOn, DateOnly day)
    {
        var index = 0;
        while (BillingMath.PeriodStart(startedOn, index + 1) <= day) index++;
        return index;
    }

    private static string Day(DateOnly day) => day.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);

    private static IReadOnlyList<BillingLine> CommitmentLines(QuoteRow quote, DateOnly start, DateOnly end) =>
        BillingMath.Lines("commitment", $"{quote.PlanName} committed seats, {Day(start)} to {Day(end.AddDays(-1))}", quote.Tiers, quote.TierMode,
            0, quote.Seats, quote.Term, 1, 1);

    private static IReadOnlyList<BillingLine> OverageLines(QuoteRow quote, BillingUsagePeriod usage) =>
        usage.OverageSeats <= 0 ? [] : BillingMath.Lines("overage",
            $"Overage above {usage.CommittedSeats} committed seats (peak {usage.PeakSeats}), {Day(usage.PeriodStart)} to {Day(usage.PeriodEnd.AddDays(-1))}",
            quote.Tiers, quote.TierMode, usage.CommittedSeats, usage.PeakSeats, quote.Term, 1, quote.Term == "annual" ? 12 : 1, priceAt: usage.PeakSeats);

    // Called for each authenticated browser request when billing is enabled. A repeat on the same day writes nothing.
    private const string RecordSeatDay = """
        INSERT INTO billing_seat_days (organization_id, usage_date, installation_id)
        VALUES ($1, (now() AT TIME ZONE 'UTC')::date, $2) ON CONFLICT DO NOTHING
        """;

    private async Task RecordBillingSeat(Guid organizationId, Guid installationId, CancellationToken ct)
    {
        if (!Billing.Enabled) return;
        await using var command = Command(RecordSeatDay, organizationId, installationId);
        await command.ExecuteNonQueryAsync(ct);
    }

    public async Task<IReadOnlyList<Guid>> BillingOrganizations(CancellationToken ct)
    {
        if (!Billing.Enabled) return [];
        await using var command = Command("""
            SELECT o.id FROM organizations o
            WHERE NOT organization_offboarding(o.id) AND (EXISTS (SELECT 1 FROM billing_seat_days s WHERE s.organization_id = o.id)
               OR EXISTS (SELECT 1 FROM billing_subscriptions b WHERE b.organization_id = o.id AND b.status = 'active'))
            ORDER BY o.id
            """);
        var organizations = new List<Guid>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct)) organizations.Add(rows.GetGuid(0));
        return organizations;
    }

    private async Task FreezeUsage(Guid organizationId, CancellationToken ct)
    {
        await using var command = Command($"""
            WITH bounds AS (
                SELECT GREATEST(COALESCE(
                        (SELECT max(usage_date) + 1 FROM billing_usage_snapshots WHERE organization_id = $1),
                        (SELECT min(usage_date) FROM billing_seat_days WHERE organization_id = $1)),
                    {GraceToday} - {SeatDayRetentionDays}) AS first_day,
                    {GraceToday} - 1 AS last_day
            ), days AS (
                -- GREATEST ignores NULL, so an organization without check-ins or snapshots must be excluded explicitly.
                SELECT d::date AS day FROM bounds, generate_series(first_day, last_day, interval '1 day') d
                WHERE EXISTS (SELECT 1 FROM billing_seat_days WHERE organization_id = $1)
                   OR EXISTS (SELECT 1 FROM billing_usage_snapshots WHERE organization_id = $1)
            ), frozen AS (
                INSERT INTO billing_usage_snapshots (organization_id, usage_date, active_seats, enrolled_seats)
                SELECT $1, day, {ActiveSeatsOn}, {EnrolledSeatsOn} FROM days
                ON CONFLICT DO NOTHING
            )
            DELETE FROM billing_seat_days WHERE organization_id = $1 AND usage_date < {GraceToday} - {SeatDayRetentionDays}
            """, organizationId);
        await command.ExecuteNonQueryAsync(ct);
    }

    private async Task<BillingUsageDay> ProvisionalToday(NpgsqlTransaction? transaction, Guid organizationId, CancellationToken ct)
    {
        await using var command = BrowserRead(transaction, $"""
            SELECT day, {ActiveSeatsOn}, {EnrolledSeatsOn} FROM (SELECT (now() AT TIME ZONE 'UTC')::date AS day) today
            """, organizationId);
        await using var rows = await command.ExecuteReaderAsync(ct);
        await rows.ReadAsync(ct);
        return new(rows.GetFieldValue<DateOnly>(0), rows.GetInt32(1), rows.GetInt32(2), true);
    }

    private async Task<IReadOnlyList<BillingUsageDay>> UsageDays(NpgsqlTransaction? transaction, Guid organizationId, DateOnly from, DateOnly until,
        CancellationToken ct)
    {
        var days = new List<BillingUsageDay>();
        await using (var command = BrowserRead(transaction, """
            SELECT usage_date, active_seats, enrolled_seats FROM billing_usage_snapshots
            WHERE organization_id = $1 AND usage_date >= $2 AND usage_date < $3 ORDER BY usage_date
            """, organizationId, from, until))
        {
            await using var rows = await command.ExecuteReaderAsync(ct);
            while (await rows.ReadAsync(ct)) days.Add(new(rows.GetFieldValue<DateOnly>(0), rows.GetInt32(1), rows.GetInt32(2), false));
        }
        var today = await ProvisionalToday(transaction, organizationId, ct);
        if (today.Date >= from && today.Date < until && days.All(day => day.Date != today.Date)) days.Add(today);
        return days;
    }

    private async Task<BillingUsagePeriod> PeriodUsage(NpgsqlTransaction? transaction, Guid organizationId, DateOnly start, DateOnly end,
        int committed, CancellationToken ct)
    {
        var days = await UsageDays(transaction, organizationId, start, end, ct);
        var peak = days.OrderByDescending(day => day.ActiveSeats).ThenBy(day => day.Date).FirstOrDefault();
        var seats = peak?.ActiveSeats ?? 0;
        return new(start, end, seats, peak?.Date, committed, Math.Max(0, seats - committed), days.Count, BillingSettings.MeteringRule);
    }

    private async Task<DateOnly> DatabaseToday(NpgsqlTransaction transaction, bool grace, CancellationToken ct)
    {
        await using var command = BrowserRead(transaction, grace ? $"SELECT {GraceToday}" : "SELECT (now() AT TIME ZONE 'UTC')::date");
        return (DateOnly)(await command.ExecuteScalarAsync(ct))!;
    }

    private async Task<QuoteRow?> LoadQuote(NpgsqlTransaction? transaction, Guid organizationId, Guid id, CancellationToken ct, bool forUpdate = false)
    {
        await using var command = BrowserRead(transaction, $"SELECT {QuoteColumns} FROM billing_quotes WHERE organization_id = $1 AND id = $2" +
            (forUpdate ? " FOR UPDATE" : ""), organizationId, id);
        await using var rows = await command.ExecuteReaderAsync(ct);
        return await rows.ReadAsync(ct) ? ReadQuote(rows, organizationId) : null;
    }

    private async Task<SubscriptionRow?> LoadSubscription(NpgsqlTransaction? transaction, Guid organizationId, CancellationToken ct, bool forUpdate = false)
    {
        await using var command = BrowserRead(transaction, """
            SELECT id, revision, started_on, closed_periods, quote_id, pending_quote_id, pending_effective_on
            FROM billing_subscriptions WHERE organization_id = $1 AND status = 'active'
            """ + (forUpdate ? " FOR UPDATE" : ""), organizationId);
        await using var rows = await command.ExecuteReaderAsync(ct);
        return await rows.ReadAsync(ct) ? new(rows.GetGuid(0), rows.GetInt32(1), rows.GetFieldValue<DateOnly>(2), rows.GetInt32(3), rows.GetGuid(4),
            rows.IsDBNull(5) ? null : rows.GetGuid(5), rows.IsDBNull(6) ? null : rows.GetFieldValue<DateOnly>(6)) : null;
    }

    private async Task Audit(NpgsqlTransaction transaction, Guid organizationId, Guid? actorId, BillingAudit change, CancellationToken ct)
    {
        await using var command = BrowserRead(transaction, """
            INSERT INTO control_audit (organization_id, action, actor_access_id, billing_change) VALUES ($1, 'billing_changed', $2, $3::jsonb)
            """, organizationId, (object?)actorId ?? DBNull.Value, JsonSerializer.Serialize(change, JsonSerializerOptions.Web));
        await command.ExecuteNonQueryAsync(ct);
    }

    // Takes the next number for the issuer and kind inside the caller's transaction. The counter row stays locked until
    // commit, so concurrent issuers serialize and a rolled-back document returns its number: numbering stays gap-free.
    private async Task<BillingInvoiceSummary> IssueDocument(NpgsqlTransaction transaction, Guid organizationId, DocumentDraft draft, CancellationToken ct)
    {
        var subtotal = draft.Lines.Sum(line => line.Amount);
        var total = subtotal + draft.TaxAmount;
        if (subtotal < 0 || total < 0) throw new InvalidOperationException("A billing document cannot have a negative total.");
        long sequence;
        await using (var counter = BrowserRead(transaction, """
            INSERT INTO billing_document_counters (issuer_id, kind, last_sequence) VALUES ($1, $2, 1)
            ON CONFLICT (issuer_id, kind) DO UPDATE SET last_sequence = billing_document_counters.last_sequence + 1
            RETURNING last_sequence
            """, Billing.IssuerId, draft.Kind))
            sequence = (long)(await counter.ExecuteScalarAsync(ct))!;
        var prefix = draft.Kind == "invoice" ? Billing.InvoicePrefix : Billing.CreditNotePrefix;
        var number = $"{prefix}-{sequence:D6}";
        var id = Guid.NewGuid();
        var invoice = draft.Kind == "invoice";
        var providerStatus = invoice && Collector.RequiresSubmission ? "pending" : "not_applicable";
        DateTime issuedAt;
        await using (var insert = BrowserRead(transaction, """
            INSERT INTO billing_invoices (organization_id, id, kind, issuer_id, sequence, number, subscription_id, related_invoice_id, reason,
                period_key, request_id, period_start, period_end, due_on, currency, minor_unit_digits, lines, usage, subtotal, tax_basis_points,
                tax_label, tax_amount, total, issuer_name, issuer_address, customer_name, billing_email, plan_name, term, note, provider,
                payment_status, provider_status)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
                CASE WHEN $3 = 'invoice' THEN (now() AT TIME ZONE 'UTC')::date + $14 END, $15, $16, $17::jsonb, $18::jsonb, $19, $20, $21, $22, $23,
                $24, $25, $26, $27, $28, $29, $30, $31, $32, $33)
            RETURNING issued_at
            """, organizationId, id, draft.Kind, Billing.IssuerId, sequence, number, draft.SubscriptionId,
            (object?)draft.RelatedInvoiceId ?? DBNull.Value, draft.Reason, draft.PeriodKey, (object?)draft.RequestId ?? DBNull.Value,
            (object?)draft.PeriodStart ?? DBNull.Value, (object?)draft.PeriodEnd ?? DBNull.Value, Billing.PaymentTermsDays, draft.Currency, draft.Digits,
            JsonSerializer.Serialize(draft.Lines, JsonSerializerOptions.Web),
            draft.Usage is null ? DBNull.Value : JsonSerializer.Serialize(draft.Usage, JsonSerializerOptions.Web),
            subtotal, draft.TaxBasisPoints, draft.TaxLabel, draft.TaxAmount, total, Billing.IssuerName, Billing.IssuerAddress, draft.CustomerName,
            SealBillingEmail(organizationId, draft.BillingEmail), draft.PlanName, draft.Term, (object?)draft.Note ?? DBNull.Value, Billing.Provider, invoice ? "open" : "issued",
            providerStatus))
            issuedAt = (DateTime)(await insert.ExecuteScalarAsync(ct))!;
        await Audit(transaction, organizationId, draft.ActorId, new(invoice ? "invoice_issued" : "credit_note_issued", draft.Automatic,
            draft.Automatic ? "system" : draft.ActorId is null ? "operator" : "owner", InvoiceId: id, SubscriptionId: draft.SubscriptionId, Number: number, Total: total,
            Currency: draft.Currency), ct);
        return new(id, draft.Kind, number, draft.Reason, issuedAt, draft.PeriodStart, draft.PeriodEnd, draft.Currency, draft.Digits, total, 0,
            invoice ? "open" : "issued", providerStatus, draft.RelatedInvoiceId);
    }

    private DocumentDraft Draft(string reason, string periodKey, SubscriptionRow subscription, QuoteRow quote, DateOnly? start, DateOnly? end,
        IReadOnlyList<BillingLine> lines, BillingUsagePeriod? usage, bool automatic, Guid? actorId) =>
        new("invoice", reason, periodKey, subscription.Id, null, null, start, end, lines, usage, quote.Currency, quote.Digits, Billing.TaxBasisPoints,
            Billing.TaxLabel, BillingMath.Tax(lines.Sum(line => line.Amount), Billing.TaxBasisPoints), quote.CustomerName, quote.BillingEmail,
            quote.PlanName, quote.Term, null, automatic, actorId);

    // Closes every monthly usage period that has ended, oldest first, inside the caller's transaction with the subscription locked.
    // The unique period key makes a second close of the same period impossible even if locking were bypassed.
    private async Task<SubscriptionRow> CloseElapsedPeriods(NpgsqlTransaction transaction, Guid organizationId, SubscriptionRow subscription,
        CancellationToken ct)
    {
        var today = await DatabaseToday(transaction, grace: true, ct);
        for (var closed = 0; closed < 36; closed++)
        {
            var index = subscription.ClosedPeriods;
            var start = BillingMath.PeriodStart(subscription.StartedOn, index);
            var end = BillingMath.PeriodStart(subscription.StartedOn, index + 1);
            if (end > today) break;
            var quote = (await LoadQuote(transaction, organizationId, subscription.QuoteId, ct))!;
            var usage = await PeriodUsage(transaction, organizationId, start, end, quote.Seats, ct);
            var lines = new List<BillingLine>(OverageLines(quote, usage));
            var revision = subscription.Revision;
            if (subscription.PendingEffectiveOn == end && subscription.PendingQuoteId is { } pending)
            {
                quote = (await LoadQuote(transaction, organizationId, pending, ct))!;
                subscription = subscription with { QuoteId = pending, PendingQuoteId = null, PendingEffectiveOn = null };
                revision++;
            }
            DateOnly? periodStart = start, periodEnd = end;
            if (quote.Term == "monthly" || (index + 1) % 12 == 0)
            {
                var (commitmentStart, commitmentEnd) = CommitmentPeriod(subscription.StartedOn, quote.Term, index + 1);
                lines.AddRange(CommitmentLines(quote, commitmentStart, commitmentEnd));
                (periodStart, periodEnd) = (commitmentStart, commitmentEnd);
            }
            if (lines.Count > 0)
                await IssueDocument(transaction, organizationId,
                    Draft("period", $"close:{index}", subscription, quote, periodStart, periodEnd, lines, usage, automatic: true, null), ct);
            subscription = subscription with { ClosedPeriods = index + 1, Revision = revision };
            await using var update = BrowserRead(transaction, """
                UPDATE billing_subscriptions SET closed_periods = $3, quote_id = $4, pending_quote_id = $5, pending_effective_on = $6, revision = $7,
                    updated_at = now()
                WHERE organization_id = $1 AND id = $2
                """, organizationId, subscription.Id, subscription.ClosedPeriods, subscription.QuoteId,
                (object?)subscription.PendingQuoteId ?? DBNull.Value, (object?)subscription.PendingEffectiveOn ?? DBNull.Value, subscription.Revision);
            await update.ExecuteNonQueryAsync(ct);
        }
        return subscription;
    }

    public async Task EvaluateBilling(Guid organizationId, bool skipIfBusy, CancellationToken ct)
    {
        if (!Billing.Enabled) return;
        await FreezeUsage(organizationId, ct);
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        SubscriptionRow? subscription;
        try
        {
            var configured = skipIfBusy ? await SetLockTimeout(transaction, $"{(int)ReadLockTimeout.TotalMilliseconds}ms", ct) : null;
            subscription = await LoadSubscription(transaction, organizationId, ct, forUpdate: true);
            if (configured is not null) await SetLockTimeout(transaction, configured, ct);
        }
        catch (PostgresException error) when (skipIfBusy && error.SqlState == PostgresErrorCodes.LockNotAvailable)
        {
            return;
        }
        if (subscription is null) return;
        await CloseElapsedPeriods(transaction, organizationId, subscription, ct);
        await transaction.CommitAsync(ct);
    }

    public async Task<BillingResult<BillingQuote>> CreateBillingQuote(RequestIdentity identity, CreateBillingQuote request, BillingPlan plan,
        CancellationToken ct)
    {
        var org = identity.OrganizationId;
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using (var existing = BrowserRead(transaction, $"SELECT {QuoteColumns} FROM billing_quotes WHERE organization_id = $1 AND request_id = $2",
            org, request.RequestId))
        await using (var rows = await existing.ExecuteReaderAsync(ct))
            if (await rows.ReadAsync(ct)) return new(ReadQuote(rows, org).View());
        var subscription = await LoadSubscription(transaction, org, ct);
        if (subscription is not null)
        {
            var current = (await LoadQuote(transaction, org, subscription.QuoteId, ct))!;
            if (current.Term != request.Term) return new(null, "billing_term_change_unsupported");
            if (current.Currency != Billing.Currency) return new(null, "billing_currency_changed");
        }
        var term = request.Term!;
        var lines = BillingMath.Lines("commitment", $"{plan.Name} committed seats, one {(term == "annual" ? "year" : "month")}", plan.Tiers,
            Billing.TierMode, 0, request.CommittedSeats, term, 1, 1);
        var subtotal = lines.Sum(line => line.Amount);
        var tax = BillingMath.Tax(subtotal, Billing.TaxBasisPoints);
        var id = Guid.NewGuid();
        await using (var insert = BrowserRead(transaction, """
            INSERT INTO billing_quotes (organization_id, id, request_id, status, plan_id, plan_name, term, committed_seats, currency, minor_unit_digits,
                tier_mode, tiers, price_book_version, tax_basis_points, tax_label, lines, subtotal, tax_amount, total, customer_name, billing_email,
                base_subscription_id, base_subscription_revision, created_by, expires_at)
            VALUES ($1, $2, $3, 'open', $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12, $13, $14, $15::jsonb, $16, $17, $18, $19, $20, $21, $22, $23,
                now() + $24 * interval '1 day')
            ON CONFLICT (organization_id, request_id) DO NOTHING
            """, org, id, request.RequestId, plan.Id, plan.Name, term, request.CommittedSeats, Billing.Currency, Billing.MinorUnitDigits,
            Billing.TierMode, JsonSerializer.Serialize(plan.Tiers, JsonSerializerOptions.Web), Billing.PriceBookVersion, Billing.TaxBasisPoints,
            Billing.TaxLabel, JsonSerializer.Serialize(lines, JsonSerializerOptions.Web), subtotal, tax, subtotal + tax, request.CustomerName!.Trim(),
            SealBillingEmail(org, request.BillingEmail!.Trim()), (object?)subscription?.Id ?? DBNull.Value, (object?)subscription?.Revision ?? DBNull.Value,
            (object?)identity.Access?.Id ?? DBNull.Value, Billing.QuoteValidDays))
            if (await insert.ExecuteNonQueryAsync(ct) == 1)
                await Audit(transaction, org, identity.Access?.Id, new("quote_created", QuoteId: id, Total: subtotal + tax, Currency: Billing.Currency,
                    CommittedSeats: request.CommittedSeats, Term: term), ct);
        var quote = (await LoadQuote(transaction, org, id, ct))!;
        await transaction.CommitAsync(ct);
        return new(quote.View());
    }

    public async Task<BillingResult<BillingQuote>> WithdrawBillingQuote(RequestIdentity identity, Guid id, CancellationToken ct)
    {
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        var quote = await LoadQuote(transaction, identity.OrganizationId, id, ct, forUpdate: true);
        if (quote is null) return new(null, "billing_quote_unavailable");
        if (quote.Status != "open") return new(null, "billing_quote_closed");
        await using (var update = BrowserRead(transaction, """
            UPDATE billing_quotes SET status = 'withdrawn', decided_at = now(), decided_by = $3 WHERE organization_id = $1 AND id = $2
            """, identity.OrganizationId, id, (object?)identity.Access?.Id ?? DBNull.Value))
            await update.ExecuteNonQueryAsync(ct);
        await Audit(transaction, identity.OrganizationId, identity.Access?.Id, new("quote_withdrawn", QuoteId: id), ct);
        var withdrawn = (await LoadQuote(transaction, identity.OrganizationId, id, ct))!;
        await transaction.CommitAsync(ct);
        return new(withdrawn.View());
    }

    public async Task<BillingResult<BillingAcceptance>> AcceptBillingQuote(RequestIdentity identity, Guid id, CancellationToken ct)
    {
        var org = identity.OrganizationId;
        await FreezeUsage(org, ct);
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        var quote = await LoadQuote(transaction, org, id, ct, forUpdate: true);
        if (quote is null) return new(null, "billing_quote_unavailable");
        if (quote.Status != "open") return new(null, "billing_quote_closed");
        if (quote.Expired) return new(null, "billing_quote_expired");
        var subscription = await LoadSubscription(transaction, org, ct, forUpdate: true);
        var today = await DatabaseToday(transaction, grace: false, ct);
        BillingInvoiceSummary? invoice = null;
        string effective;
        DateOnly effectiveOn;
        if (quote.BaseSubscriptionId is null)
        {
            if (subscription is not null) return new(null, "billing_quote_stale");
            subscription = new(Guid.NewGuid(), 1, today, 0, quote.Id, null, null);
            await using (var insert = BrowserRead(transaction, """
                INSERT INTO billing_subscriptions (organization_id, id, status, started_on, quote_id) VALUES ($1, $2, 'active', $3, $4)
                """, org, subscription.Id, today, quote.Id))
                try
                {
                    await insert.ExecuteNonQueryAsync(ct);
                }
                catch (PostgresException error) when (error.SqlState == PostgresErrorCodes.UniqueViolation)
                {
                    // Another quote started a subscription concurrently; this one was priced without it.
                    return new(null, "billing_quote_stale");
                }
            var (start, end) = CommitmentPeriod(today, quote.Term, 0);
            invoice = await IssueDocument(transaction, org, Draft("subscription_start", "start", subscription, quote, start, end,
                CommitmentLines(quote, start, end), null, automatic: false, identity.Access?.Id), ct);
            (effective, effectiveOn) = ("immediate", today);
        }
        else
        {
            if (subscription is null || subscription.Id != quote.BaseSubscriptionId) return new(null, "billing_quote_stale");
            subscription = await CloseElapsedPeriods(transaction, org, subscription, ct);
            if (subscription.Revision != quote.BaseRevision) return new(null, "billing_quote_stale");
            var current = (await LoadQuote(transaction, org, subscription.QuoteId, ct))!;
            if (current.Term != quote.Term) return new(null, "billing_term_change_unsupported");
            if (current.Currency != quote.Currency) return new(null, "billing_currency_changed");
            var (start, end) = CommitmentPeriod(subscription.StartedOn, current.Term, UsageIndex(subscription.StartedOn, today));
            var increases = BillingMath.PeriodAmount(quote.Tiers, quote.TierMode, quote.Seats, quote.Term) >
                BillingMath.PeriodAmount(current.Tiers, current.TierMode, current.Seats, current.Term);
            if (increases)
            {
                // Credit the unused part of the current commitment and charge the new commitment for the same remaining days.
                var remaining = end.DayNumber - today.DayNumber;
                var length = end.DayNumber - start.DayNumber;
                var through = Day(end.AddDays(-1));
                var lines = BillingMath.Lines("proration_credit", $"Unused {current.PlanName} commitment of {current.Seats} seats, {Day(today)} to {through}",
                        current.Tiers, current.TierMode, 0, current.Seats, current.Term, remaining, length, negative: true)
                    .Concat(BillingMath.Lines("proration_charge", $"{quote.PlanName} commitment of {quote.Seats} seats, {Day(today)} to {through}",
                        quote.Tiers, quote.TierMode, 0, quote.Seats, quote.Term, remaining, length)).ToList();
                // Rounding each line can leave a net of zero or one minor unit below zero for a tiny increase; no invoice is issued then.
                if (lines.Sum(line => line.Amount) > 0)
                    invoice = await IssueDocument(transaction, org, Draft("amendment", $"amendment:{quote.Id:N}", subscription, quote, today, end, lines,
                        null, automatic: false, identity.Access?.Id), ct);
                subscription = subscription with { QuoteId = quote.Id, PendingQuoteId = null, PendingEffectiveOn = null, Revision = subscription.Revision + 1 };
                (effective, effectiveOn) = ("immediate", today);
            }
            else
            {
                subscription = subscription with { PendingQuoteId = quote.Id, PendingEffectiveOn = end, Revision = subscription.Revision + 1 };
                (effective, effectiveOn) = ("next_period", end);
            }
            await using var update = BrowserRead(transaction, """
                UPDATE billing_subscriptions SET quote_id = $3, pending_quote_id = $4, pending_effective_on = $5, revision = $6, updated_at = now()
                WHERE organization_id = $1 AND id = $2
                """, org, subscription.Id, subscription.QuoteId, (object?)subscription.PendingQuoteId ?? DBNull.Value,
                (object?)subscription.PendingEffectiveOn ?? DBNull.Value, subscription.Revision);
            await update.ExecuteNonQueryAsync(ct);
        }
        await using (var accept = BrowserRead(transaction, """
            UPDATE billing_quotes SET status = 'accepted', decided_at = now(), decided_by = $3 WHERE organization_id = $1 AND id = $2
            """, org, quote.Id, (object?)identity.Access?.Id ?? DBNull.Value))
            await accept.ExecuteNonQueryAsync(ct);
        await Audit(transaction, org, identity.Access?.Id, new("quote_accepted", QuoteId: quote.Id, SubscriptionId: subscription.Id,
            CommittedSeats: quote.Seats, Term: quote.Term, Effective: effective), ct);
        var view = (await SubscriptionView(transaction, org, ct))!;
        await transaction.CommitAsync(ct);
        return new(new BillingAcceptance(view, effective, effectiveOn, invoice));
    }

    private async Task<BillingSubscriptionView?> SubscriptionView(NpgsqlTransaction? transaction, Guid org, CancellationToken ct)
    {
        var subscription = await LoadSubscription(transaction, org, ct);
        if (subscription is null) return null;
        var quote = (await LoadQuote(transaction, org, subscription.QuoteId, ct))!;
        var pending = subscription.PendingQuoteId is { } pendingId ? await LoadQuote(transaction, org, pendingId, ct) : null;
        var today = DateOnly.FromDateTime(DateTime.UtcNow);
        var index = Math.Max(subscription.ClosedPeriods, UsageIndex(subscription.StartedOn, today));
        var (commitmentStart, commitmentEnd) = CommitmentPeriod(subscription.StartedOn, quote.Term, index);
        return new(subscription.Id, "active", subscription.Revision, subscription.StartedOn, quote.PlanId, quote.PlanName, quote.Term, quote.Seats,
            quote.TierMode, quote.Tiers, quote.Currency, quote.CustomerName, subscription.ClosedPeriods,
            BillingMath.PeriodStart(subscription.StartedOn, index), BillingMath.PeriodStart(subscription.StartedOn, index + 1),
            commitmentStart, commitmentEnd,
            pending is null ? null : new(pending.Id, pending.PlanName, pending.Seats, subscription.PendingEffectiveOn!.Value));
    }

    public async Task<BillingOverview> BillingOverview(RequestIdentity identity, CancellationToken ct)
    {
        var org = identity.OrganizationId;
        await EvaluateBilling(org, skipIfBusy: true, ct);
        await SubmitPendingInvoices(org, ct);
        var subscription = await LoadSubscription(null, org, ct);
        var view = await SubscriptionView(null, org, ct);
        var today = DateOnly.FromDateTime(DateTime.UtcNow);
        BillingUsagePeriod? usage;
        BillingEstimate? estimate = null;
        if (subscription is not null && view is not null)
        {
            var quote = (await LoadQuote(null, org, subscription.QuoteId, ct))!;
            usage = await PeriodUsage(null, org, view.CurrentPeriodStart, view.CurrentPeriodEnd, quote.Seats, ct);
            var lines = new List<BillingLine>(OverageLines(quote, usage));
            var index = UsageIndex(subscription.StartedOn, view.CurrentPeriodStart);
            if (subscription.PendingEffectiveOn == view.CurrentPeriodEnd && subscription.PendingQuoteId is { } pending)
                quote = (await LoadQuote(null, org, pending, ct))!;
            if (quote.Term == "monthly" || (index + 1) % 12 == 0)
            {
                var (start, end) = CommitmentPeriod(subscription.StartedOn, quote.Term, index + 1);
                lines.AddRange(CommitmentLines(quote, start, end));
            }
            var subtotal = lines.Sum(line => line.Amount);
            var tax = BillingMath.Tax(subtotal, Billing.TaxBasisPoints);
            estimate = new(view.CurrentPeriodEnd, lines, subtotal, Billing.TaxBasisPoints, tax, subtotal + tax, usage);
        }
        else usage = await PeriodUsage(null, org, today.AddDays(-29), today.AddDays(1), 0, ct);

        var quotes = new List<BillingQuote>();
        await using (var command = Command($"""
            SELECT {QuoteColumns} FROM billing_quotes WHERE organization_id = $1 ORDER BY created_at DESC, id DESC LIMIT 20
            """, org))
        await using (var rows = await command.ExecuteReaderAsync(ct))
            while (await rows.ReadAsync(ct)) quotes.Add(ReadQuote(rows, org).View());
        return new(identity.OrganizationSlug!, Billing.Provider, Billing.Currency, Billing.MinorUnitDigits, Billing.TierMode, Billing.TaxBasisPoints,
            Billing.TaxLabel, true, BillingSettings.MeteringRule, Billing.PriceBookVersion,
            Billing.Plans.Select(plan => new BillingPlanView(plan.Id, plan.Name, plan.Tiers)).ToList(), view, usage, estimate,
            await UsageDays(null, org, today.AddDays(-34), today.AddDays(1), ct), quotes, await InvoiceSummaries(org, null, ct));
    }

    public async Task<IReadOnlyList<BillingUsageDay>> BillingUsage(Guid org, DateOnly from, DateOnly until, CancellationToken ct)
    {
        await FreezeUsage(org, ct);
        return await UsageDays(null, org, from, until, ct);
    }

    private const string SummaryColumns = """
        b.id, b.kind, b.number, b.reason, b.issued_at, b.period_start, b.period_end, b.currency, b.minor_unit_digits, b.total,
        COALESCE((SELECT sum(c.total) FROM billing_invoices c WHERE c.organization_id = b.organization_id AND c.related_invoice_id = b.id), 0)::bigint,
        b.payment_status, b.provider_status, b.related_invoice_id
        """;

    private static BillingInvoiceSummary ReadSummary(NpgsqlDataReader rows) => new(rows.GetGuid(0), rows.GetString(1), rows.GetString(2),
        rows.GetString(3), rows.GetDateTime(4), rows.IsDBNull(5) ? null : rows.GetFieldValue<DateOnly>(5),
        rows.IsDBNull(6) ? null : rows.GetFieldValue<DateOnly>(6), rows.GetString(7), rows.GetInt32(8), rows.GetInt64(9), rows.GetInt64(10),
        rows.GetString(11), rows.GetString(12), rows.IsDBNull(13) ? null : rows.GetGuid(13));

    private async Task<IReadOnlyList<BillingInvoiceSummary>> InvoiceSummaries(Guid org, Guid? relatedTo, CancellationToken ct)
    {
        await using var command = Command($"""
            SELECT {SummaryColumns} FROM billing_invoices b
            WHERE b.organization_id = $1 AND ($2::uuid IS NULL OR b.related_invoice_id = $2)
            ORDER BY b.issued_at DESC, b.kind, b.sequence DESC LIMIT 100
            """, org, (object?)relatedTo ?? DBNull.Value);
        var invoices = new List<BillingInvoiceSummary>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct)) invoices.Add(ReadSummary(rows));
        return invoices;
    }

    public async Task<BillingInvoice?> BillingInvoiceDetails(Guid org, Guid id, CancellationToken ct)
    {
        BillingInvoice invoice;
        await using (var command = Command("""
            SELECT b.id, b.kind, b.number, b.reason, b.subscription_id, b.related_invoice_id, r.number, b.issued_at, b.due_on, b.period_start,
                b.period_end, b.currency, b.minor_unit_digits, b.lines::text, b.usage::text, b.subtotal, b.tax_basis_points, b.tax_label, b.tax_amount,
                b.total, COALESCE((SELECT sum(c.total) FROM billing_invoices c WHERE c.organization_id = b.organization_id AND c.related_invoice_id = b.id), 0)::bigint,
                b.issuer_name, b.issuer_address, b.customer_name, b.billing_email, b.plan_name, b.term, b.note, b.provider, b.payment_status,
                b.paid_at, b.payment_reference, b.provider_status
            FROM billing_invoices b LEFT JOIN billing_invoices r ON r.organization_id = b.organization_id AND r.id = b.related_invoice_id
            WHERE b.organization_id = $1 AND b.id = $2
            """, org, id))
        {
            await using var rows = await command.ExecuteReaderAsync(ct);
            if (!await rows.ReadAsync(ct)) return null;
            var kind = rows.GetString(1);
            var total = rows.GetInt64(19);
            var credited = rows.GetInt64(20);
            var status = rows.GetString(29);
            invoice = new(rows.GetGuid(0), kind, rows.GetString(2), rows.GetString(3), rows.GetGuid(4), rows.IsDBNull(5) ? null : rows.GetGuid(5),
                rows.IsDBNull(6) ? null : rows.GetString(6), rows.GetDateTime(7), rows.IsDBNull(8) ? null : rows.GetFieldValue<DateOnly>(8),
                rows.IsDBNull(9) ? null : rows.GetFieldValue<DateOnly>(9), rows.IsDBNull(10) ? null : rows.GetFieldValue<DateOnly>(10),
                rows.GetString(11), rows.GetInt32(12), JsonSerializer.Deserialize<BillingLine[]>(rows.GetString(13), JsonSerializerOptions.Web)!,
                rows.IsDBNull(14) ? null : JsonSerializer.Deserialize<BillingUsagePeriod>(rows.GetString(14), JsonSerializerOptions.Web),
                rows.GetInt64(15), rows.GetInt32(16), rows.GetString(17), rows.GetInt64(18), total, credited,
                kind == "invoice" && status == "open" ? total - credited : 0,
                new(rows.GetString(21), rows.GetString(22)), new(rows.GetString(23), OpenBillingEmail(org, rows.GetString(24))), rows.GetString(25), rows.GetString(26),
                rows.IsDBNull(27) ? null : rows.GetString(27), rows.GetString(28), status, rows.IsDBNull(30) ? null : rows.GetDateTime(30),
                rows.IsDBNull(31) ? null : rows.GetString(31), rows.GetString(32),
                kind == "invoice" && rows.GetString(28) == "manual" && Billing.PaymentInstructions.Length > 0 ? Billing.PaymentInstructions : null, []);
        }
        return invoice.Kind == "invoice" ? invoice with { CreditNotes = await InvoiceSummaries(org, id, ct) } : invoice;
    }

    public async Task<BillingResult<BillingInvoiceSummary>> IssueBillingCreditNote(RequestIdentity identity, Guid invoiceId, IssueCreditNote request,
        CancellationToken ct)
    {
        var org = identity.OrganizationId;
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using (var existing = BrowserRead(transaction, $"""
            SELECT {SummaryColumns} FROM billing_invoices b WHERE b.organization_id = $1 AND b.request_id = $2
            """, org, request.RequestId))
        await using (var rows = await existing.ExecuteReaderAsync(ct))
            if (await rows.ReadAsync(ct))
            {
                var previous = ReadSummary(rows);
                return previous.RelatedInvoiceId == invoiceId ? new(previous) : new(null, "billing_request_reused");
            }
        // Locking the invoice serializes credit notes against it, so the credited total can never exceed the invoice total.
        // The credited sums are read by a later statement: in READ COMMITTED a statement that waited for the lock still reads
        // subqueries from its original snapshot, which would miss a credit note committed while it waited.
        await using (var gate = BrowserRead(transaction, """
            SELECT 1 FROM billing_invoices WHERE organization_id = $1 AND id = $2 AND kind = 'invoice' FOR UPDATE
            """, org, invoiceId))
            if (await gate.ExecuteScalarAsync(ct) is null) return new(null, "billing_invoice_unavailable");
        Guid subscriptionId;
        long subtotal, total, creditedSubtotal, creditedTotal;
        int taxBasisPoints, digits;
        string number, currency, taxLabel, customer, email, plan, term, status;
        await using (var locked = BrowserRead(transaction, """
            SELECT subscription_id, subtotal, total, tax_basis_points, number, currency, minor_unit_digits, tax_label, customer_name, billing_email,
                plan_name, term, payment_status,
                COALESCE((SELECT sum(c.subtotal) FROM billing_invoices c WHERE c.organization_id = $1 AND c.related_invoice_id = $2), 0)::bigint,
                COALESCE((SELECT sum(c.total) FROM billing_invoices c WHERE c.organization_id = $1 AND c.related_invoice_id = $2), 0)::bigint
            FROM billing_invoices WHERE organization_id = $1 AND id = $2 AND kind = 'invoice'
            """, org, invoiceId))
        {
            await using var rows = await locked.ExecuteReaderAsync(ct);
            if (!await rows.ReadAsync(ct)) return new(null, "billing_invoice_unavailable");
            (subscriptionId, subtotal, total, taxBasisPoints, number, currency, digits, taxLabel, customer, email, plan, term, status) =
                (rows.GetGuid(0), rows.GetInt64(1), rows.GetInt64(2), rows.GetInt32(3), rows.GetString(4), rows.GetString(5), rows.GetInt32(6),
                    rows.GetString(7), rows.GetString(8), OpenBillingEmail(org, rows.GetString(9)), rows.GetString(10), rows.GetString(11), rows.GetString(12));
            (creditedSubtotal, creditedTotal) = (rows.GetInt64(13), rows.GetInt64(14));
        }
        var remainingSubtotal = subtotal - creditedSubtotal;
        if (request.Amount > remainingSubtotal) return new(null, "billing_credit_exceeds_invoice");
        // Tax is credited on a cumulative basis: the tax credited so far is always the invoice tax prorated to the subtotal credited so far,
        // rounded once. Partial credits therefore never over-credit tax, and crediting the whole subtotal credits exactly the invoice tax.
        var invoiceTax = total - subtotal;
        long CumulativeTax(long credited) => subtotal == 0 ? 0 : BillingMath.Round((decimal)credited * invoiceTax / subtotal);
        var tax = CumulativeTax(creditedSubtotal + request.Amount) - CumulativeTax(creditedSubtotal);
        var reason = request.Reason!.Trim();
        var line = new BillingLine("credit", $"Credit for {number}: {reason}", 1, request.Amount, 1, 1, request.Amount);
        var note = await IssueDocument(transaction, org, new("credit_note", "correction", $"credit:{request.RequestId:N}", subscriptionId, invoiceId,
            request.RequestId, null, null, [line], null, currency, digits, taxBasisPoints, taxLabel, tax, customer, email, plan, term, reason,
            false, identity.Access?.Id), ct);
        if (creditedTotal + note.Total == total && status == "open")
        {
            await using var settle = BrowserRead(transaction, """
                UPDATE billing_invoices SET payment_status = 'credited' WHERE organization_id = $1 AND id = $2
                """, org, invoiceId);
            await settle.ExecuteNonQueryAsync(ct);
        }
        await transaction.CommitAsync(ct);
        return new(note);
    }

    // The operator acts for an organization without holding one of its credentials. No access record is attached, so audit
    // entries show the operator source and no actor.
    public async Task<RequestIdentity?> OperatorIdentity(string slug, CancellationToken ct)
    {
        await using var command = Command("SELECT id FROM organizations WHERE slug = $1 AND NOT organization_offboarding(id)", slug);
        return await command.ExecuteScalarAsync(ct) is Guid id ? new(id, null, slug, null) : null;
    }

    public async Task<BillingResult<BillingInvoiceSummary>> RecordBillingPayment(RequestIdentity identity, Guid invoiceId, string reference,
        CancellationToken ct)
    {
        var org = identity.OrganizationId;
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        string? provider = null, status = null, number = null, currency = null;
        long total = 0;
        await using (var locked = BrowserRead(transaction, """
            SELECT provider, payment_status, number, currency, total FROM billing_invoices
            WHERE organization_id = $1 AND id = $2 AND kind = 'invoice' FOR UPDATE
            """, org, invoiceId))
        await using (var rows = await locked.ExecuteReaderAsync(ct))
            if (await rows.ReadAsync(ct)) (provider, status, number, currency, total) = (rows.GetString(0), rows.GetString(1), rows.GetString(2),
                rows.GetString(3), rows.GetInt64(4));
        if (provider is null) return new(null, "billing_invoice_unavailable");
        if (provider != "manual") return new(null, "billing_provider_managed");
        if (status != "open") return new(null, "billing_invoice_settled");
        await using (var update = BrowserRead(transaction, """
            UPDATE billing_invoices SET payment_status = 'paid', paid_at = now(), payment_reference = $3 WHERE organization_id = $1 AND id = $2
            """, org, invoiceId, reference))
            await update.ExecuteNonQueryAsync(ct);
        await Audit(transaction, org, identity.Access?.Id, new("payment_recorded", Source: "operator", InvoiceId: invoiceId, Number: number, Total: total,
            Currency: currency), ct);
        await transaction.CommitAsync(ct);
        return new((await InvoiceSummaries(org, null, ct)).First(invoice => invoice.Id == invoiceId));
    }

    // Applies one verified Stripe event at most once. The event row and its effect commit together, so a replay finds the
    // event and changes nothing.
    public async Task<string> ApplyStripeEvent(StripeWebhookEvent stripeEvent, CancellationToken ct)
    {
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        Guid? org = null, invoiceId = null;
        string? status = null, number = null, currency = null;
        long total = 0;
        if (stripeEvent.InvoiceId is { } providerInvoice)
        {
            await using var locked = BrowserRead(transaction, """
                SELECT organization_id, id, payment_status, number, currency, total FROM billing_invoices
                WHERE provider = 'stripe' AND provider_invoice_id = $1 AND NOT organization_offboarding(organization_id) FOR UPDATE
                """, providerInvoice);
            await using var rows = await locked.ExecuteReaderAsync(ct);
            if (await rows.ReadAsync(ct) && (stripeEvent.ControlInvoiceId is null || stripeEvent.ControlInvoiceId == rows.GetGuid(1)))
                (org, invoiceId, status, number, currency, total) = (rows.GetGuid(0), rows.GetGuid(1), rows.GetString(2), rows.GetString(3),
                    rows.GetString(4), rows.GetInt64(5));
        }
        var outcome = org is not null && (stripeEvent.Type == "invoice.paid" && status == "open" || stripeEvent.Type == "invoice.payment_failed")
            ? "applied" : "ignored";
        await using (var record = BrowserRead(transaction, """
            INSERT INTO billing_provider_events (provider, event_id, event_type, organization_id, invoice_id, outcome)
            VALUES ('stripe', $1, $2, $3, $4, $5) ON CONFLICT DO NOTHING
            """, stripeEvent.Id, stripeEvent.Type, (object?)org ?? DBNull.Value, (object?)invoiceId ?? DBNull.Value, outcome))
            if (await record.ExecuteNonQueryAsync(ct) == 0) return "duplicate";
        if (outcome == "applied")
        {
            if (stripeEvent.Type == "invoice.paid")
            {
                await using var update = BrowserRead(transaction, """
                    UPDATE billing_invoices SET payment_status = 'paid', paid_at = now(), payment_reference = $3 WHERE organization_id = $1 AND id = $2
                    """, org!.Value, invoiceId!.Value, stripeEvent.InvoiceId!);
                await update.ExecuteNonQueryAsync(ct);
            }
            await Audit(transaction, org!.Value, null, new(stripeEvent.Type == "invoice.paid" ? "payment_recorded" : "payment_failed",
                Automatic: true, Source: "stripe", InvoiceId: invoiceId, Number: number, Total: total, Currency: currency), ct);
        }
        await transaction.CommitAsync(ct);
        return outcome;
    }

    // Sends issued invoices to the configured provider outside any database transaction. A short lease keeps concurrent
    // workers from submitting the same invoice; the provider's idempotency keys cover a lease that expires mid-submission.
    public async Task SubmitPendingInvoices(Guid? organizationId, CancellationToken ct)
    {
        if (!Billing.Enabled || !Collector.RequiresSubmission) return;
        for (var sent = 0; sent < 20; sent++)
        {
            ProviderSubmission submission;
            int attempts;
            await using (var claim = Command("""
                UPDATE billing_invoices b SET provider_lease_until = now() + interval '2 minutes', provider_attempts = b.provider_attempts + 1
                WHERE (b.organization_id, b.id) = (
                    SELECT organization_id, id FROM billing_invoices
                    WHERE provider_status = 'pending' AND NOT organization_offboarding(organization_id) AND ($1::uuid IS NULL OR organization_id = $1)
                        AND (provider_lease_until IS NULL OR provider_lease_until <= now())
                    ORDER BY issued_at, id LIMIT 1 FOR UPDATE SKIP LOCKED)
                RETURNING b.organization_id, b.id, b.number, b.currency, b.lines::text, b.tax_amount, b.tax_label, b.customer_name, b.billing_email,
                    b.provider_invoice_id, b.provider_progress, b.provider_attempts, GREATEST(b.due_on - (now() AT TIME ZONE 'UTC')::date, 1),
                    (SELECT customer_id FROM billing_provider_customers c WHERE c.organization_id = b.organization_id AND c.provider = b.provider)
                """, (object?)organizationId ?? DBNull.Value))
            {
                await using var rows = await claim.ExecuteReaderAsync(ct);
                if (!await rows.ReadAsync(ct)) return;
                var items = JsonSerializer.Deserialize<BillingLine[]>(rows.GetString(4), JsonSerializerOptions.Web)!
                    .Select(line => new ProviderItem(line.Description, line.Amount)).ToList();
                if (rows.GetInt64(5) != 0) items.Add(new(rows.GetString(6), rows.GetInt64(5)));
                submission = new(rows.GetGuid(0), rows.GetGuid(1), rows.GetString(2), rows.GetString(3), items, rows.GetInt32(12), rows.GetString(7),
                    OpenBillingEmail(rows.GetGuid(0), rows.GetString(8)), rows.IsDBNull(13) ? null : rows.GetString(13), rows.IsDBNull(9) ? null : rows.GetString(9), rows.GetInt32(10));
                attempts = rows.GetInt32(11);
            }
            var result = await Collector.Submit(submission, ct);
            var status = result.Completed ? "submitted" : !result.Retryable || attempts >= MaxProviderAttempts ? "failed" : "pending";
            await using var connection = await dataSource.OpenConnectionAsync(ct);
            await using var transaction = await connection.BeginTransactionAsync(ct);
            if (result.CustomerId is { } customer)
            {
                await using var save = BrowserRead(transaction, """
                    INSERT INTO billing_provider_customers (organization_id, provider, customer_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING
                    """, submission.OrganizationId, Collector.Provider, customer);
                await save.ExecuteNonQueryAsync(ct);
            }
            await using (var update = BrowserRead(transaction, """
                UPDATE billing_invoices SET provider_status = $3, provider_invoice_id = COALESCE($4, provider_invoice_id), provider_progress = $5,
                    provider_error = $6, provider_lease_until = CASE WHEN $3 = 'pending' THEN now() + $7 * interval '1 second' END
                WHERE organization_id = $1 AND id = $2
                """, submission.OrganizationId, submission.InvoiceId, status, (object?)result.ProviderInvoiceId ?? DBNull.Value, result.Progress,
                (object?)result.Error ?? DBNull.Value, Math.Min(1 << Math.Min(attempts - 1, 9), 300)))
                await update.ExecuteNonQueryAsync(ct);
            if (status == "failed")
                await Audit(transaction, submission.OrganizationId, null, new("provider_submission_failed", Automatic: true, Source: Collector.Provider,
                    InvoiceId: submission.InvoiceId, Number: submission.Number), ct);
            await transaction.CommitAsync(ct);
        }
    }

    public async Task<BillingResult<BillingInvoiceSummary>> RetryProviderSubmission(RequestIdentity identity, Guid invoiceId, CancellationToken ct)
    {
        if (!Collector.RequiresSubmission) return new(null, "billing_provider_manual");
        await using (var command = Command("""
            WITH retried AS (
                UPDATE billing_invoices SET provider_status = 'pending', provider_attempts = 0, provider_lease_until = NULL
                WHERE organization_id = $1 AND id = $2 AND kind = 'invoice' AND provider_status = 'failed' AND provider = $3
                RETURNING organization_id, id, number
            )
            INSERT INTO control_audit (organization_id, action, actor_access_id, billing_change)
            SELECT organization_id, 'billing_changed', $4, jsonb_build_object('kind', 'provider_submission_retried', 'automatic', false,
                'source', 'owner', 'invoiceId', id, 'number', number) FROM retried
            """, identity.OrganizationId, invoiceId, Collector.Provider, (object?)identity.Access?.Id ?? DBNull.Value))
            if (await command.ExecuteNonQueryAsync(ct) == 0) return new(null, "billing_submission_not_failed");
        await SubmitPendingInvoices(identity.OrganizationId, ct);
        return new((await InvoiceSummaries(identity.OrganizationId, null, ct)).First(invoice => invoice.Id == invoiceId));
    }
}
