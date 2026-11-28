using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Control;

internal sealed record OrganizationDeletionOptions(byte[]? ReceiptKey, int GraceDays, int BatchSize, TimeSpan SweepInterval, int? BackupRetentionDays)
{
    public bool Available => ReceiptKey is not null;

    public static OrganizationDeletionOptions Read(IConfiguration configuration)
    {
        var section = configuration.GetSection("Control:OrganizationDeletion");
        var key = section["ReceiptKey"];
        if (!string.IsNullOrEmpty(key) && !Tokens.IsValid(key))
            throw new InvalidOperationException("Configure the organization deletion receipt key as 32 bytes of lowercase hex.");
        var grace = section.GetValue("GraceDays", 7);
        if (grace is < 1 or > 30) throw new InvalidOperationException("Configure an organization deletion grace period from 1 to 30 days.");
        var batch = section.GetValue("BatchSize", 1000);
        if (batch is < 1 or > 10000) throw new InvalidOperationException("Configure an organization deletion batch size from 1 to 10000 rows.");
        var sweep = section.GetValue("SweepSeconds", 60);
        if (sweep is < 1 or > 3600) throw new InvalidOperationException("Configure an organization deletion sweep from 1 to 3600 seconds.");
        var backup = configuration.GetValue<int?>("Control:BackupRetentionDays");
        if (backup is < 1 or > 3650) throw new InvalidOperationException("Configure a backup retention period from 1 to 3650 days.");
        return new(string.IsNullOrEmpty(key) ? null : Convert.FromHexString(key), grace, batch, TimeSpan.FromSeconds(sweep), backup);
    }
}

// One step of organization deletion. Steps run in this order, children before the rows they reference.
// Every base table in the public schema must be listed here or in RetainedTables; startup of a deletion and the
// API suite's schema-coverage test both fail when a migration adds a table that neither list handles.
internal sealed record TenantTable(string Name, string Scope, bool Export = false, string[]? Secrets = null);

internal static class TenantTables
{
    public const string ByOrganization = "organization_id = $1";

    // BEGIN tenant deletion plan
    public static readonly TenantTable[] DeletionOrder =
    [
        new("control_sso_sessions", "access_id IN (SELECT id FROM control_access WHERE organization_id = $1)"),
        new("alert_webhook_deliveries", ByOrganization, Export: true),
        new("security_alert_events", ByOrganization, Export: true),
        new("incident_case_events", ByOrganization, Export: true),
        new("event_triage", ByOrganization, Export: true),
        new("prompt_exception_requests", ByOrganization, Export: true),
        new("security_alert_windows", ByOrganization, Export: true),
        new("incident_cases", ByOrganization, Export: true),
        new("composer_observations", ByOrganization, Export: true),
        new("saas_app_observations", ByOrganization, Export: true),
        new("control_access_log", ByOrganization, Export: true),
        new("control_attestations", ByOrganization, Export: true),
        new("enrollment_key_redemptions", ByOrganization, Export: true, Secrets: ["nonce_hash"]),
        new("ai_app_observations", ByOrganization, Export: true),
        new("extension_inventory_snapshots", ByOrganization, Export: true),
        new("extension_inventory_change_batches", ByOrganization, Export: true),
        new("policy_deliveries", ByOrganization, Export: true),
        new("security_events", ByOrganization, Export: true),
        new("control_audit", ByOrganization, Export: true),
        new("policy_audit", ByOrganization, Export: true),
        new("rollout_stages", ByOrganization, Export: true),
        new("rollout_plans", ByOrganization, Export: true),
        new("policy_reviews", ByOrganization, Export: true),
        new("policy_template_revisions", ByOrganization, Export: true),
        new("policy_templates", ByOrganization, Export: true),
        new("enrollment_grants", ByOrganization),
        new("enrollment_keys", ByOrganization, Export: true, Secrets: ["token_hash"]),
        new("enrollment_batches", ByOrganization, Export: true),
        new("installations", ByOrganization, Export: true, Secrets: ["token_hash"]),
        new("event_feed_keys", ByOrganization, Export: true, Secrets: ["token_hash"]),
        new("organization_event_streams", ByOrganization, Export: true),
        new("security_alert_settings", ByOrganization, Export: true),
        new("extension_access_alert_settings", ByOrganization, Export: true),
        new("organization_retention", ByOrganization, Export: true),
        new("ai_app_classifications", ByOrganization, Export: true),
        new("saas_app_classifications", ByOrganization, Export: true),
        new("control_access", ByOrganization, Export: true, Secrets: ["token_hash"]),
        new("policy_versions", ByOrganization, Export: true),
        new("policy_groups", ByOrganization, Export: true),
        new("admin_memberships", ByOrganization),
        new("organizations", "id = $1"),
    ];

    // Global tables and the operator's deletion ledger, which outlives the tenant by design.
    public static readonly string[] RetainedTables = ["schema_migrations", "organization_deletions"];
    // END tenant deletion plan

    public static readonly HashSet<string> Handled =
        DeletionOrder.Select(table => table.Name).Concat(RetainedTables).ToHashSet(StringComparer.Ordinal);
}

internal sealed record RequestOrganizationDeletion(string? ConfirmSlug);
internal sealed record PurgePolicyHistory([property: JsonRequired] DateTimeOffset PublishedBefore, Guid? GroupId = null, bool DryRun = false);

internal sealed record OrganizationDeletionStatus(Guid Id, string Status, DateTime RequestedAt, DateTime PurgeAfter,
    DateTime? CancelledAt, DateTime? StartedAt, DateTime? CompletedAt, long DeletedRows, int Batches,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? LastError);
internal sealed record RequestedOrganizationDeletion(OrganizationDeletionStatus Deletion, string ReceiptToken);
internal sealed record OrganizationDeletionResult(RequestedOrganizationDeletion? Requested, string? Error);

internal sealed record InstallationDeletion(Guid InstallationId, IReadOnlyDictionary<string, long> DeletedRows);
internal sealed record InstallationDeletionResult(InstallationDeletion? Deletion, string? Error);

internal sealed record PolicyPurgeKept(int Current, int OpenReview, int ActiveRollout, int RetainedEvent, int Installation, int Evidence);
internal sealed record PolicyPurge(string Scope, Guid? GroupId, DateTime PublishedBefore, bool DryRun, int[] Versions, PolicyPurgeKept Kept);

internal static class DeletionReceipts
{
    public const string Type = "zekvar.organization_deletion_receipt";

    public static string Timestamp(DateTime value) =>
        DateTime.SpecifyKind(value, DateTimeKind.Utc).ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);

    // The receipt is compact JSON with a fixed property order and ASCII-only values, so re-serializing the parsed
    // object (JSON.stringify, jq -c) reproduces the signed bytes exactly.
    public static string Build(OrganizationDeletionStatus deletion, Guid organizationId, IReadOnlyList<(string Table, long Rows)> tables,
        int? tablesChecked, long? remainingRows, int? backupRetentionDays)
    {
        using var buffer = new MemoryStream();
        using (var json = new Utf8JsonWriter(buffer))
        {
            json.WriteStartObject();
            json.WriteNumber("version", 1);
            json.WriteString("type", Type);
            json.WriteString("deletionId", deletion.Id.ToString("D"));
            json.WriteString("organizationId", organizationId.ToString("D"));
            json.WriteString("status", deletion.Status);
            json.WriteString("requestedAt", Timestamp(deletion.RequestedAt));
            json.WriteString("scheduledFor", Timestamp(deletion.PurgeAfter));
            WriteTimestamp(json, "startedAt", deletion.StartedAt);
            WriteTimestamp(json, "completedAt", deletion.CompletedAt);
            json.WriteString("rowsMeaning", deletion.Status == "completed" ? "deleted" : "held_at_issue");
            json.WriteStartArray("tables");
            foreach (var (table, rows) in tables)
            {
                json.WriteStartObject();
                json.WriteString("table", table);
                json.WriteNumber("rows", rows);
                json.WriteEndObject();
            }
            json.WriteEndArray();
            json.WriteNumber("totalRows", tables.Sum(entry => entry.Rows));
            if (tablesChecked is { } checkedTables && remainingRows is { } remaining)
            {
                json.WriteStartObject("verification");
                json.WriteString("method", "per_table_zero_count");
                json.WriteNumber("tablesChecked", checkedTables);
                json.WriteNumber("remainingRows", remaining);
                json.WriteEndObject();
            }
            else json.WriteNull("verification");
            json.WriteStartObject("backups");
            json.WriteString("notice", "deleted_data_persists_in_encrypted_backups_until_they_age_out");
            if (backupRetentionDays is { } days) json.WriteNumber("retentionDays", days);
            else json.WriteNull("retentionDays");
            json.WriteEndObject();
            json.WriteString("issuedAt", Timestamp(DateTime.UtcNow));
            json.WriteEndObject();
        }
        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    public static string Sign(byte[] key, string receipt) => Convert.ToHexStringLower(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(receipt)));

    public static string KeyId(byte[] key) => Convert.ToHexStringLower(SHA256.HashData(key))[..16];

    public static string Envelope(byte[] key, string receipt, string? signature = null)
    {
        using var buffer = new MemoryStream();
        using (var json = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = false }))
        {
            json.WriteStartObject();
            json.WritePropertyName("receipt");
            json.WriteRawValue(receipt, skipInputValidation: false);
            json.WriteStartObject("signature");
            json.WriteString("algorithm", "HMAC-SHA256");
            json.WriteString("keyId", KeyId(key));
            json.WriteString("value", signature ?? Sign(key, receipt));
            json.WriteEndObject();
            json.WriteEndObject();
        }
        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    private static void WriteTimestamp(Utf8JsonWriter json, string name, DateTime? value)
    {
        if (value is { } at) json.WriteString(name, Timestamp(at));
        else json.WriteNull(name);
    }
}

internal sealed class OrganizationDeletionSweep(ControlStore store, OrganizationDeletionOptions options, ILogger<OrganizationDeletionSweep> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var schedule = new PeriodicTimer(options.SweepInterval);
        do
        {
            try
            {
                foreach (var id in await store.DueOrganizationDeletions(stoppingToken))
                {
                    // Each batch commits on its own; a failed batch is retried on the next sweep from the recorded progress.
                    for (var batch = 0; batch < 100_000 && !stoppingToken.IsCancellationRequested; batch++)
                    {
                        var outcome = await store.RunOrganizationDeletionBatch(id, options, stoppingToken);
                        if (outcome is "completed") logger.LogInformation("Control completed one organization deletion.");
                        if (outcome is not "progress") break;
                    }
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception error)
            {
                logger.LogWarning("Control organization deletion sweep failed with {ErrorType}. The next sweep will retry.", error.GetType().Name);
            }
        } while (await schedule.WaitForNextTickAsync(stoppingToken));
    }
}
