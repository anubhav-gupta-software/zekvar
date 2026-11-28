using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Control;

// Operator configuration under Control:Billing. Prices are integer minor units of the configured currency.
// Nothing here ships with real prices; the price book must be supplied by the operator.
internal sealed class ConfiguredBilling
{
    public bool Enabled { get; set; }
    public string? IssuerId { get; set; }
    public string? IssuerName { get; set; }
    public string? IssuerAddress { get; set; }
    public string? InvoicePrefix { get; set; }
    public string? CreditNotePrefix { get; set; }
    public string? Currency { get; set; }
    public int MinorUnitDigits { get; set; } = 2;
    public int TaxRateBasisPoints { get; set; }
    public string? TaxLabel { get; set; }
    public int PaymentTermsDays { get; set; } = 30;
    public int QuoteValidDays { get; set; } = 30;
    public string? TierMode { get; set; }
    public ConfiguredBillingPlan[]? Plans { get; set; }
    public string? PaymentProvider { get; set; }
    public string? PaymentInstructions { get; set; }
    public ConfiguredStripe? Stripe { get; set; }
    public int EvaluationSeconds { get; set; } = 300;
}

internal sealed class ConfiguredBillingPlan
{
    public string? Id { get; set; }
    public string? Name { get; set; }
    public ConfiguredBillingTier[]? Tiers { get; set; }
}

internal sealed class ConfiguredBillingTier
{
    public int? UpTo { get; set; }
    public long? MonthlyUnitAmount { get; set; }
    public long? AnnualUnitAmount { get; set; }
}

internal sealed class ConfiguredStripe
{
    public string? ApiBase { get; set; }
    public string? SecretKey { get; set; }
    public string? WebhookSecret { get; set; }
    public int WebhookToleranceSeconds { get; set; } = 300;
}

internal sealed record BillingTier(int? UpTo, long MonthlyUnitAmount, long AnnualUnitAmount);
internal sealed record BillingPlan(string Id, string Name, BillingTier[] Tiers);
internal sealed record StripeSettings(Uri ApiBase, string SecretKey, string WebhookSecret, int ToleranceSeconds);

internal sealed partial class BillingSettings
{
    public const int MaxSeats = 1_000_000;
    public const long MaxUnitAmount = 1_000_000_000;
    public const string MeteringRule = "peak_daily_active_7d";

    public bool Enabled { get; private init; }
    public string IssuerId { get; private init; } = "";
    public string IssuerName { get; private init; } = "";
    public string IssuerAddress { get; private init; } = "";
    public string InvoicePrefix { get; private init; } = "";
    public string CreditNotePrefix { get; private init; } = "";
    public string Currency { get; private init; } = "";
    public int MinorUnitDigits { get; private init; }
    public int TaxBasisPoints { get; private init; }
    public string TaxLabel { get; private init; } = "";
    public int PaymentTermsDays { get; private init; }
    public int QuoteValidDays { get; private init; }
    public string TierMode { get; private init; } = "volume";
    public IReadOnlyList<BillingPlan> Plans { get; private init; } = [];
    public string Provider { get; private init; } = "manual";
    public string PaymentInstructions { get; private init; } = "";
    public StripeSettings? Stripe { get; private init; }
    public string PriceBookVersion { get; private init; } = "";
    public TimeSpan EvaluationInterval { get; private init; } = TimeSpan.FromMinutes(5);

    public BillingPlan? Plan(string? id) => Plans.FirstOrDefault(plan => plan.Id == id);

    public static BillingSettings Read(IConfiguration configuration, bool development)
    {
        var raw = configuration.GetSection("Control:Billing").Get<ConfiguredBilling>();
        if (raw is not { Enabled: true }) return new();
        static InvalidOperationException Invalid(string detail) => new($"Invalid Control:Billing configuration: {detail}");
        if (raw.IssuerId is not { } issuerId || !Slug().IsMatch(issuerId)) throw Invalid("IssuerId must be 2 to 40 lowercase letters, digits, or hyphens.");
        if (!Text(raw.IssuerName, 2, 120)) throw Invalid("IssuerName must be 2 to 120 printable characters.");
        if (raw.IssuerAddress is not null && !Text(raw.IssuerAddress, 0, 400, multiline: true)) throw Invalid("IssuerAddress must be at most 400 characters.");
        if (raw.InvoicePrefix is not { } invoicePrefix || !Prefix().IsMatch(invoicePrefix) ||
            raw.CreditNotePrefix is not { } creditPrefix || !Prefix().IsMatch(creditPrefix) || invoicePrefix == creditPrefix)
            throw Invalid("InvoicePrefix and CreditNotePrefix must be distinct 2 to 8 uppercase letters or digits.");
        if (raw.Currency is not { } currency || !CurrencyCode().IsMatch(currency)) throw Invalid("Currency must be a three-letter uppercase code.");
        if (raw.MinorUnitDigits is < 0 or > 3) throw Invalid("MinorUnitDigits must be 0 to 3.");
        if (raw.TaxRateBasisPoints is < 0 or > 10000) throw Invalid("TaxRateBasisPoints must be 0 to 10000.");
        if (!Text(raw.TaxLabel, 1, 40)) throw Invalid("TaxLabel must be 1 to 40 printable characters.");
        if (raw.PaymentTermsDays is < 1 or > 120 || raw.QuoteValidDays is < 1 or > 90) throw Invalid("PaymentTermsDays is 1 to 120 and QuoteValidDays is 1 to 90.");
        if (raw.TierMode is not ("volume" or "graduated")) throw Invalid("TierMode must be volume or graduated.");
        if (raw.EvaluationSeconds is < 1 or > 86400) throw Invalid("EvaluationSeconds must be 1 to 86400.");
        if (raw.Plans is not { Length: >= 1 and <= 10 }) throw Invalid("Configure 1 to 10 plans.");
        var plans = new List<BillingPlan>();
        foreach (var plan in raw.Plans)
        {
            if (plan.Id is not { } id || !Slug().IsMatch(id) || plans.Any(existing => existing.Id == id) || !Text(plan.Name, 2, 80))
                throw Invalid("Each plan needs a distinct slug Id and a Name of 2 to 80 characters.");
            if (plan.Tiers is not { Length: >= 1 and <= 10 }) throw Invalid($"Plan {id} needs 1 to 10 tiers.");
            var tiers = new List<BillingTier>();
            for (var index = 0; index < plan.Tiers.Length; index++)
            {
                var tier = plan.Tiers[index];
                var last = index == plan.Tiers.Length - 1;
                if (last != (tier.UpTo is null) || tier.UpTo is { } upTo && (upTo < 1 || upTo >= MaxSeats || tiers.Count > 0 && upTo <= tiers[^1].UpTo))
                    throw Invalid($"Plan {id} tiers need ascending UpTo limits below {MaxSeats}, and only the last tier is unbounded.");
                if (tier.MonthlyUnitAmount is not (>= 0 and <= MaxUnitAmount) || tier.AnnualUnitAmount is not (>= 0 and <= MaxUnitAmount))
                    throw Invalid($"Plan {id} tiers need MonthlyUnitAmount and AnnualUnitAmount from 0 to {MaxUnitAmount} minor units.");
                tiers.Add(new(tier.UpTo, tier.MonthlyUnitAmount.Value, tier.AnnualUnitAmount.Value));
            }
            plans.Add(new(id, plan.Name!.Trim(), [.. tiers]));
        }
        var provider = raw.PaymentProvider ?? "manual";
        StripeSettings? stripe = null;
        if (provider == "stripe")
        {
            var configured = raw.Stripe ?? new ConfiguredStripe();
            var apiBase = configured.ApiBase ?? "https://api.stripe.com";
            if (!Uri.TryCreate(apiBase, UriKind.Absolute, out var uri) || uri.UserInfo != "" || uri.Query != "" || uri.Fragment != "" ||
                uri.AbsolutePath != "/" || !(uri.Scheme == Uri.UriSchemeHttps || development && uri.Scheme == Uri.UriSchemeHttp && uri.Host == "127.0.0.1"))
                throw Invalid("Stripe:ApiBase must be an HTTPS origin, or a 127.0.0.1 HTTP origin in Development.");
            if (configured.SecretKey is not { } key || !StripeKey().IsMatch(key)) throw Invalid("Stripe:SecretKey must be a Stripe secret or restricted key.");
            if (configured.WebhookSecret is not { } secret || !StripeWebhookSecret().IsMatch(secret)) throw Invalid("Stripe:WebhookSecret must be a whsec_ signing secret.");
            if (configured.WebhookToleranceSeconds is < 30 or > 900) throw Invalid("Stripe:WebhookToleranceSeconds must be 30 to 900.");
            stripe = new(uri, key, secret, configured.WebhookToleranceSeconds);
        }
        else if (provider != "manual") throw Invalid("PaymentProvider must be manual or stripe.");
        if (raw.PaymentInstructions is not null && !Text(raw.PaymentInstructions, 0, 600, multiline: true))
            throw Invalid("PaymentInstructions must be at most 600 characters.");
        var book = JsonSerializer.Serialize(new { currency, raw.MinorUnitDigits, raw.TierMode, Plans = plans }, JsonSerializerOptions.Web);
        return new BillingSettings
        {
            Enabled = true, IssuerId = issuerId, IssuerName = raw.IssuerName!.Trim(), IssuerAddress = raw.IssuerAddress?.Trim() ?? "",
            InvoicePrefix = invoicePrefix, CreditNotePrefix = creditPrefix, Currency = currency, MinorUnitDigits = raw.MinorUnitDigits,
            TaxBasisPoints = raw.TaxRateBasisPoints, TaxLabel = raw.TaxLabel!.Trim(), PaymentTermsDays = raw.PaymentTermsDays,
            QuoteValidDays = raw.QuoteValidDays, TierMode = raw.TierMode, Plans = plans, Provider = provider,
            PaymentInstructions = raw.PaymentInstructions?.Trim() ?? "", Stripe = stripe,
            EvaluationInterval = TimeSpan.FromSeconds(raw.EvaluationSeconds),
            PriceBookVersion = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(book)))[..16],
        };
    }

    public static bool Text(string? value, int min, int max, bool multiline = false) =>
        value?.Trim() is { } trimmed && trimmed.Length >= min && trimmed.Length <= max &&
        trimmed.All(character => !char.IsControl(character) || multiline && character == '\n');

    [GeneratedRegex("^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$")] private static partial Regex Slug();
    [GeneratedRegex("^[A-Z0-9]{2,8}$")] private static partial Regex Prefix();
    [GeneratedRegex("^[A-Z]{3}$")] private static partial Regex CurrencyCode();
    [GeneratedRegex("^(sk|rk)_(test|live)_[A-Za-z0-9]{8,200}$")] private static partial Regex StripeKey();
    [GeneratedRegex("^whsec_[A-Za-z0-9+/=]{8,200}$")] private static partial Regex StripeWebhookSecret();
}

// One invoice or quote line. amount = round(quantity * unitAmount * numerator / denominator), half away from zero.
internal sealed record BillingLine(string Kind, string Description, int Quantity, long UnitAmount, int Numerator, int Denominator, long Amount);

internal static class BillingMath
{
    public static long Round(decimal value) => (long)Math.Round(value, 0, MidpointRounding.AwayFromZero);

    public static long LineAmount(int quantity, long unitAmount, int numerator, int denominator) =>
        Round((decimal)quantity * unitAmount * numerator / denominator);

    public static long Tax(long subtotal, int basisPoints) => Round((decimal)subtotal * basisPoints / 10000m);

    public static long Unit(BillingTier tier, string term) => term == "annual" ? tier.AnnualUnitAmount : tier.MonthlyUnitAmount;

    public static BillingTier TierFor(BillingTier[] tiers, int seats) => tiers.First(tier => tier.UpTo is null || seats <= tier.UpTo);

    // Splits seat positions (fromExclusive, toInclusive] into priced slices.
    // Volume pricing prices every position at the tier reached by priceAt; graduated pricing prices each position at its own band.
    public static IReadOnlyList<(int From, int To, long Unit)> Slices(BillingTier[] tiers, string mode, int fromExclusive, int toInclusive,
        string term, int? priceAt = null)
    {
        if (toInclusive <= fromExclusive) return [];
        if (mode == "volume") return [(fromExclusive, toInclusive, Unit(TierFor(tiers, priceAt ?? toInclusive), term))];
        var slices = new List<(int, int, long)>();
        var lower = 0;
        foreach (var tier in tiers)
        {
            var upper = tier.UpTo ?? int.MaxValue;
            var from = Math.Max(lower, fromExclusive);
            var to = Math.Min(upper, toInclusive);
            if (to > from) slices.Add((from, to, Unit(tier, term)));
            if (upper >= toInclusive) break;
            lower = upper;
        }
        return slices;
    }

    public static IReadOnlyList<BillingLine> Lines(string kind, string label, BillingTier[] tiers, string mode, int fromExclusive, int toInclusive,
        string term, int numerator, int denominator, bool negative = false, int? priceAt = null) =>
        Slices(tiers, mode, fromExclusive, toInclusive, term, priceAt).Select(slice =>
        {
            var amount = LineAmount(slice.To - slice.From, slice.Unit, numerator, denominator);
            return new BillingLine(kind, $"{label}, seats {slice.From + 1}–{slice.To}", slice.To - slice.From, slice.Unit, numerator, denominator,
                negative ? -amount : amount);
        }).ToList();

    public static long PeriodAmount(BillingTier[] tiers, string mode, int seats, string term) =>
        Lines("commitment", "", tiers, mode, 0, seats, term, 1, 1).Sum(line => line.Amount);

    // Monthly usage periods are anchored on the subscription start date. Each is computed from the start so day clamping
    // (for example a start on the 31st) never drifts.
    public static DateOnly PeriodStart(DateOnly startedOn, int index) => startedOn.AddMonths(index);
}

internal sealed record BillingPlanView(string Id, string Name, BillingTier[] Tiers);
internal sealed record BillingQuote(Guid Id, string Status, string PlanId, string PlanName, string Term, int CommittedSeats, string Currency,
    int MinorUnitDigits, string TierMode, string PriceBookVersion, IReadOnlyList<BillingLine> Lines, long Subtotal, int TaxBasisPoints,
    string TaxLabel, long TaxAmount, long Total, string CustomerName, string BillingEmail, bool Amendment, DateTime CreatedAt,
    DateTime ExpiresAt, DateTime? DecidedAt);
internal sealed record BillingSubscriptionView(Guid Id, string Status, int Revision, DateOnly StartedOn, string PlanId, string PlanName,
    string Term, int CommittedSeats, string TierMode, BillingTier[] Tiers, string Currency, string CustomerName, int ClosedPeriods,
    DateOnly CurrentPeriodStart, DateOnly CurrentPeriodEnd, DateOnly CommitmentPeriodStart, DateOnly CommitmentPeriodEnd,
    BillingPendingChange? PendingChange);
internal sealed record BillingPendingChange(Guid QuoteId, string PlanName, int CommittedSeats, DateOnly EffectiveOn);
internal sealed record BillingUsageDay(DateOnly Date, int ActiveSeats, int EnrolledSeats, bool Provisional);
internal sealed record BillingUsagePeriod(DateOnly PeriodStart, DateOnly PeriodEnd, int PeakSeats, DateOnly? PeakDate, int CommittedSeats,
    int OverageSeats, int DaysMeasured, string Rule);
internal sealed record BillingEstimate(DateOnly IssueOn, IReadOnlyList<BillingLine> Lines, long Subtotal, int TaxBasisPoints, long TaxAmount,
    long Total, BillingUsagePeriod Usage);
internal sealed record BillingInvoiceSummary(Guid Id, string Kind, string Number, string Reason, DateTime IssuedAt, DateOnly? PeriodStart,
    DateOnly? PeriodEnd, string Currency, int MinorUnitDigits, long Total, long CreditedTotal, string PaymentStatus, string ProviderStatus,
    Guid? RelatedInvoiceId);
internal sealed record BillingInvoice(Guid Id, string Kind, string Number, string Reason, Guid SubscriptionId, Guid? RelatedInvoiceId,
    string? RelatedNumber, DateTime IssuedAt, DateOnly? DueOn, DateOnly? PeriodStart, DateOnly? PeriodEnd, string Currency, int MinorUnitDigits,
    IReadOnlyList<BillingLine> Lines, BillingUsagePeriod? Usage, long Subtotal, int TaxBasisPoints, string TaxLabel, long TaxAmount, long Total,
    long CreditedTotal, long BalanceDue, BillingParty Issuer, BillingParty Customer, string PlanName, string Term, string? Note,
    string Provider, string PaymentStatus, DateTime? PaidAt, string? PaymentReference, string ProviderStatus, string? PaymentInstructions,
    IReadOnlyList<BillingInvoiceSummary> CreditNotes);
internal sealed record BillingParty(string Name, string Detail);
internal sealed record BillingOverview(string Organization, string Provider, string Currency, int MinorUnitDigits, string TierMode,
    int TaxBasisPoints, string TaxLabel, bool TaxPlaceholder, string MeteringRule, string PriceBookVersion, IReadOnlyList<BillingPlanView> Plans,
    BillingSubscriptionView? Subscription, BillingUsagePeriod? CurrentUsage, BillingEstimate? Estimate, IReadOnlyList<BillingUsageDay> Usage,
    IReadOnlyList<BillingQuote> Quotes, IReadOnlyList<BillingInvoiceSummary> Invoices);
internal sealed record BillingResult<T>(T? Value, string? Error = null) where T : class;
internal sealed record BillingAcceptance(BillingSubscriptionView Subscription, string Effective, DateOnly EffectiveOn, BillingInvoiceSummary? Invoice);

internal sealed record CreateBillingQuote(Guid RequestId, string? PlanId, string? Term, int CommittedSeats, string? CustomerName, string? BillingEmail);
internal sealed record IssueCreditNote(Guid RequestId, long Amount, string? Reason);
internal sealed record RecordBillingPayment(string? Reference);

internal sealed record BillingAudit(string Kind, bool Automatic = false, string? Source = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] Guid? QuoteId = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] Guid? SubscriptionId = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] Guid? InvoiceId = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Number = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] long? Total = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Currency = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? CommittedSeats = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Term = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Effective = null);

internal static partial class BillingValidation
{
    public static bool Email(string? value) => value is { Length: >= 3 and <= 254 } && EmailPattern().IsMatch(value);
    [GeneratedRegex(@"^[^\s@<>""]+@[^\s@<>""]+\.[^\s@<>""]+$")] private static partial Regex EmailPattern();
}

// Payment collection is behind this interface so a provider can be chosen later. The manual provider records bank transfers
// marked by the owner; it needs no submission.
internal interface IPaymentCollector
{
    string Provider { get; }
    bool RequiresSubmission { get; }
    Task<CollectorResult> Submit(ProviderSubmission submission, CancellationToken ct);
}

internal sealed record ProviderItem(string Description, long Amount);
internal sealed record ProviderSubmission(Guid OrganizationId, Guid InvoiceId, string Number, string Currency, IReadOnlyList<ProviderItem> Items,
    int DaysUntilDue, string CustomerName, string BillingEmail, string? CustomerId, string? ProviderInvoiceId, int Progress);
internal sealed record CollectorResult(bool Completed, string? CustomerId, string? ProviderInvoiceId, int Progress, string? Error, bool Retryable);

internal sealed class ManualCollector : IPaymentCollector
{
    public string Provider => "manual";
    public bool RequiresSubmission => false;
    public Task<CollectorResult> Submit(ProviderSubmission submission, CancellationToken ct) =>
        Task.FromResult(new CollectorResult(true, null, null, submission.Progress, null, false));
}

// Stripe adapter against the documented REST API: customers, invoices, invoice items, and finalization.
// Every request carries an idempotency key derived from the Control invoice, and progress is stored after each run,
// so retries never create a second Stripe customer, invoice, or line.
internal sealed class StripeCollector(StripeSettings settings) : IPaymentCollector
{
    public const string ApiVersion = "2024-06-20";
    private readonly HttpClient client = new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false, UseCookies = false, UseProxy = false, PooledConnectionLifetime = TimeSpan.FromMinutes(5),
    }) { Timeout = TimeSpan.FromSeconds(10), BaseAddress = settings.ApiBase };

    public string Provider => "stripe";
    public bool RequiresSubmission => true;

    public async Task<CollectorResult> Submit(ProviderSubmission submission, CancellationToken ct)
    {
        var customer = submission.CustomerId;
        var invoice = submission.ProviderInvoiceId;
        var progress = submission.Progress;
        var key = submission.InvoiceId.ToString("N");
        try
        {
            if (customer is null)
            {
                var created = await Post("/v1/customers", $"zekvar-customer-{submission.OrganizationId:N}", [
                    ("name", submission.CustomerName), ("email", submission.BillingEmail),
                    ("metadata[zekvar_organization_id]", submission.OrganizationId.ToString("D"))], ct);
                customer = created.Error is null ? created.Id : null;
                if (customer is null) return new(false, null, invoice, progress, created.Error, created.Retryable);
            }
            if (invoice is null)
            {
                var created = await Post("/v1/invoices", $"zekvar-invoice-{key}", [
                    ("customer", customer), ("collection_method", "send_invoice"),
                    ("days_until_due", submission.DaysUntilDue.ToString(CultureInfo.InvariantCulture)),
                    ("currency", submission.Currency.ToLowerInvariant()), ("auto_advance", "false"),
                    ("pending_invoice_items_behavior", "exclude"), ("description", $"Zekvar {submission.Number}"),
                    ("metadata[zekvar_invoice_id]", submission.InvoiceId.ToString("D")), ("metadata[zekvar_invoice_number]", submission.Number),
                    ("metadata[zekvar_organization_id]", submission.OrganizationId.ToString("D"))], ct);
                invoice = created.Error is null ? created.Id : null;
                if (invoice is null) return new(false, customer, null, progress, created.Error, created.Retryable);
            }
            for (; progress < submission.Items.Count; progress++)
            {
                var item = submission.Items[progress];
                var created = await Post("/v1/invoiceitems", $"zekvar-invoice-{key}-item-{progress}", [
                    ("customer", customer), ("invoice", invoice), ("amount", item.Amount.ToString(CultureInfo.InvariantCulture)),
                    ("currency", submission.Currency.ToLowerInvariant()), ("description", item.Description),
                    ("metadata[zekvar_invoice_id]", submission.InvoiceId.ToString("D"))], ct);
                if (created.Error is not null) return new(false, customer, invoice, progress, created.Error, created.Retryable);
            }
            if (progress == submission.Items.Count)
            {
                var finalized = await Post($"/v1/invoices/{Uri.EscapeDataString(invoice)}/finalize", $"zekvar-invoice-{key}-finalize", [], ct);
                if (finalized.Error is not null) return new(false, customer, invoice, progress, finalized.Error, finalized.Retryable);
                progress++;
            }
            return new(true, customer, invoice, progress, null, false);
        }
        catch (Exception error) when (error is HttpRequestException or TaskCanceledException && !ct.IsCancellationRequested)
        {
            return new(false, customer, invoice, progress, "provider_unreachable", true);
        }
    }

    private async Task<(string? Id, string? Error, bool Retryable)> Post(string path, string idempotencyKey,
        IEnumerable<(string Key, string Value)> fields, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = new FormUrlEncodedContent(fields.Select(field =>
            new KeyValuePair<string, string>(field.Key, field.Value))) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", settings.SecretKey);
        request.Headers.Add("Idempotency-Key", idempotencyKey);
        request.Headers.Add("Stripe-Version", ApiVersion);
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        if (!response.IsSuccessStatusCode)
        {
            var status = (int)response.StatusCode;
            // The response body is never logged or stored; only the status class is recorded.
            return (null, $"provider_http_{status}", status is 409 or 429 || status >= 500);
        }
        await using var body = await response.Content.ReadAsStreamAsync(ct);
        using var json = await JsonDocument.ParseAsync(body, cancellationToken: ct);
        return json.RootElement.TryGetProperty("id", out var id) && id.ValueKind == JsonValueKind.String && id.GetString() is { Length: >= 3 and <= 255 } value
            ? (value, null, false) : (null, "provider_response_invalid", false);
    }
}

// Verifies a Stripe-Signature header: t=<unix seconds>,v1=<hex HMAC-SHA256 of "t.payload" keyed by the signing secret>.
internal static class StripeSignature
{
    public static string Sign(string secret, long timestamp, ReadOnlySpan<byte> payload)
    {
        var prefix = Encoding.UTF8.GetBytes($"{timestamp.ToString(CultureInfo.InvariantCulture)}.");
        var message = new byte[prefix.Length + payload.Length];
        prefix.CopyTo(message, 0);
        payload.CopyTo(message.AsSpan(prefix.Length));
        return Convert.ToHexStringLower(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), message));
    }

    public static string Verify(string? header, ReadOnlySpan<byte> payload, string secret, DateTimeOffset now, int toleranceSeconds)
    {
        if (header is not { Length: > 0 and <= 2048 }) return "signature_missing";
        long? timestamp = null;
        var signatures = new List<string>();
        foreach (var part in header.Split(','))
        {
            var separator = part.IndexOf('=');
            if (separator <= 0) continue;
            var name = part[..separator].Trim();
            var value = part[(separator + 1)..].Trim();
            if (name == "t")
            {
                if (timestamp is not null || !long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed)) return "signature_invalid";
                timestamp = parsed;
            }
            else if (name == "v1") signatures.Add(value);
        }
        if (timestamp is not { } t || signatures.Count == 0) return "signature_invalid";
        var expected = Encoding.ASCII.GetBytes(Sign(secret, t, payload));
        var matched = false;
        foreach (var signature in signatures)
            matched |= CryptographicOperations.FixedTimeEquals(expected, Encoding.ASCII.GetBytes(signature));
        if (!matched) return "signature_invalid";
        return Math.Abs(now.ToUnixTimeSeconds() - t) > toleranceSeconds ? "signature_stale" : "valid";
    }
}

internal sealed record StripeWebhookEvent(string Id, string Type, string? InvoiceId, Guid? ControlInvoiceId);

internal static class StripeWebhook
{
    public const int MaxBodySize = 256 * 1024;

    public static StripeWebhookEvent? Parse(ReadOnlySpan<byte> payload)
    {
        try
        {
            var reader = new Utf8JsonReader(payload);
            using var json = JsonDocument.ParseValue(ref reader);
            var root = json.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("id", out var id) || id.GetString() is not { Length: >= 5 and <= 255 } eventId ||
                !eventId.StartsWith("evt_", StringComparison.Ordinal) || !root.TryGetProperty("type", out var type) ||
                type.GetString() is not { Length: >= 1 and <= 128 } eventType) return null;
            string? invoice = null;
            Guid? control = null;
            if (root.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Object &&
                data.TryGetProperty("object", out var item) && item.ValueKind == JsonValueKind.Object &&
                item.TryGetProperty("object", out var kind) && kind.ValueKind == JsonValueKind.String && kind.GetString() == "invoice")
            {
                if (item.TryGetProperty("id", out var invoiceId) && invoiceId.ValueKind == JsonValueKind.String) invoice = invoiceId.GetString();
                if (item.TryGetProperty("metadata", out var metadata) && metadata.ValueKind == JsonValueKind.Object &&
                    metadata.TryGetProperty("zekvar_invoice_id", out var reference) && reference.ValueKind == JsonValueKind.String &&
                    Guid.TryParseExact(reference.GetString(), "D", out var parsed)) control = parsed;
            }
            return new(eventId, eventType, invoice is { Length: >= 3 and <= 255 } ? invoice : null, control);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}

internal sealed class BillingWorker(ControlStore store, BillingSettings settings, ILogger<BillingWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var schedule = new PeriodicTimer(settings.EvaluationInterval);
        do
        {
            try
            {
                foreach (var organizationId in await store.BillingOrganizations(stoppingToken))
                {
                    try
                    {
                        await store.EvaluateBilling(organizationId, skipIfBusy: false, stoppingToken);
                    }
                    catch (Exception error) when (!stoppingToken.IsCancellationRequested)
                    {
                        logger.LogWarning("Control could not evaluate billing for one organization. Error type {ErrorType}.", error.GetType().Name);
                    }
                }
                await store.SubmitPendingInvoices(null, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception error)
            {
                logger.LogWarning("Control billing evaluation failed with {ErrorType}. The next pass will retry.", error.GetType().Name);
            }
        } while (await schedule.WaitForNextTickAsync(stoppingToken));
    }
}
