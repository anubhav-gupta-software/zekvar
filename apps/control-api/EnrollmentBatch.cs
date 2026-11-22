namespace Control;

internal sealed record CreateEnrollmentBatch(Guid RequestId, Guid? GroupId, int Count)
{
    public bool IsValid() => RequestId != Guid.Empty && GroupId != Guid.Empty && Count is >= 1 and <= 25;
}

internal sealed record IssuedEnrollmentBatch(Guid Id, DateTime ExpiresAt, IReadOnlyList<string> Grants);
internal sealed record EnrollmentBatch(Guid Id, Guid? GroupId, string? GroupName, int Size, int Redeemed, int Available,
    DateTime CreatedAt, DateTime ExpiresAt, string Status);
internal sealed record EnrollmentBatchChange(Guid BatchId, Guid? GroupId, string? GroupName, int Count);
