namespace Control;

internal sealed record PolicyScope(int Version, string? Name, bool Published);
internal sealed record PolicySnapshots(Policy Before, Policy Candidate);
internal sealed record PolicyReview(Guid Id, string Status, string Operation, Guid? GroupId, string? GroupName,
    Guid? SourceGroupId, string? SourceGroupName, int? SourceVersion, DateTime RequestedAt, DateTime ExpiresAt,
    DateTime? DecidedAt, int? PublishedVersion, AccessIdentity Requester, AccessIdentity? Reviewer, PolicySnapshots Snapshots);
internal sealed record PolicyReviewQueue(bool Required, IReadOnlyList<PolicyReview> Entries);
internal sealed record SetPolicyReview(bool? Required);
internal sealed record ChoosePolicyReview(bool? Approve);
internal sealed record PolicyReviewAudit(Guid? ReviewId = null, string? Operation = null, string? Status = null, Guid? GroupId = null,
    int? BaseVersion = null, int? SourceVersion = null, int? PublishedVersion = null, bool? Required = null, int? Cancelled = null);

internal sealed record PolicyChangeResult(Policy? Policy = null, Guid? ReviewId = null, string? Error = null);
