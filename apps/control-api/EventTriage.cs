namespace Control;

internal static class TriageStatus
{
    public const string NeedsReview = "needs_review";
    public const string Investigating = "investigating";
    public const string Resolved = "resolved";

    public static bool IsValid(string? status) => status is NeedsReview or Investigating or Resolved;
}

internal sealed record SetEventTriage(int? ExpectedRevision, string? Status, string? Disposition, Guid? AssigneeId)
{
    public bool IsValid() => ExpectedRevision is >= 0 && TriageStatus.IsValid(Status) && AssigneeId != Guid.Empty &&
        (Status == TriageStatus.Resolved
            ? Disposition is "confirmed_violation" or "false_positive" or "expected_activity" or "insufficient_evidence"
            : Disposition is null);
}

internal sealed record TriageAssignee(Guid Id, string Name, bool Active);
internal sealed record EventTriage(int Revision, string Status, string? Disposition, TriageAssignee? Assignee, DateTime? UpdatedAt)
{
    public static readonly EventTriage Initial = new(0, TriageStatus.NeedsReview, null, null, null);
    public EventTriageState State() => new(Status, Disposition, Assignee?.Id);
}

internal sealed record EventTriageState(string Status, string? Disposition, Guid? AssigneeId);
internal sealed record EventTriageChange(Guid InstallationId, Guid EventId, int Revision, EventTriageState Before, EventTriageState After);
internal sealed record EventTriageActivity(Guid Id, DateTime OccurredAt, AccessIdentity? ActorAccess, EventTriageChange Change);
internal sealed record EventDetails(StoredEvent Event, EventTriageActivity[] Activity);
internal sealed record TriageResult(EventTriage? Triage = null, string? Error = null);

internal readonly record struct TriageAssigneeFilter(bool RequireUnassigned, Guid? Id)
{
    public static TriageAssigneeFilter? Parse(string? value) => value switch
    {
        null or "" => new(false, null),
        "unassigned" => new(true, null),
        _ when value.Length == 36 && Guid.TryParseExact(value, "D", out var id) && id != Guid.Empty => new(false, id),
        _ => null
    };
}
