namespace Control;

internal sealed record AuditFilters(string? Action, DateTimeOffset? Since, DateTimeOffset? Until,
    DateTimeOffset? BeforeAt, Guid? BeforeId, int Limit)
{
    public bool IsValid =>
        (Action is null or "policy_published" or "policy_restored" or "grant_issued" or "browser_enrolled" or "browser_revoked"
            or "app_classified" or "retention_changed" or "retention_cleanup") &&
        (Since is null || Until is null || Since < Until) &&
        (BeforeAt is null) == (BeforeId is null) && BeforeId != Guid.Empty && Limit is >= 1 and <= 1000;
}

internal sealed record AuditEntry(Guid Id, DateTime OccurredAt, string Action, int? PolicyVersion, int? RestoredFrom,
    Guid? InstallationId, string? AppId, string? Classification, RetentionPolicy? Retention, RetentionCleanup? Cleanup)
{
    public string Actor => Action switch
    {
        "browser_enrolled" => "browser_enrollment",
        "retention_cleanup" when Cleanup?.Source == "scheduled" => "system",
        _ => "organization_admin"
    };
}

internal sealed record AuditCursor(DateTime OccurredAt, Guid Id);
internal sealed record AuditPage(IReadOnlyList<AuditEntry> Entries, AuditCursor? Next);
