namespace Control;

internal sealed record CreateIncidentCase(Guid RequestId, string? Category, Guid InstallationId, Guid EventId)
{
    public bool IsValid() => RequestId != Guid.Empty && InstallationId != Guid.Empty && EventId != Guid.Empty &&
        Category is "suspected_data_exposure" or "repeated_policy_blocks" or "unexpected_ai_use" or "other";
}

internal sealed record SetCaseMembership(int? ExpectedRevision, Guid InstallationId, Guid EventId, bool? Linked)
{
    public bool IsValid() => ExpectedRevision is >= 1 && InstallationId != Guid.Empty && EventId != Guid.Empty && Linked.HasValue;
}

internal sealed record IncidentCaseReference(Guid Id, string Category, int Revision, string Status);
internal sealed record IncidentCase(Guid Id, string Category, DateTime CreatedAt, EventTriage Triage, int EventCount);
internal sealed record IncidentCaseCursor(DateTimeOffset CreatedAt, Guid Id);
internal sealed record IncidentCasePage(IncidentCase[] Entries, IncidentCaseCursor? Next);
internal sealed record IncidentCaseChange(Guid CaseId, string Category, int Revision, string Operation,
    EventTriageState? Before = null, EventTriageState? After = null, Guid? InstallationId = null, Guid? EventId = null);
internal sealed record IncidentCaseActivity(Guid Id, DateTime OccurredAt, AccessIdentity? ActorAccess, IncidentCaseChange Change);
internal sealed record IncidentCaseDetails(IncidentCase Case, StoredEvent[] Events, IncidentCaseActivity[] Activity);
internal sealed record IncidentCaseResult(Guid? CaseId = null, string? Error = null);
