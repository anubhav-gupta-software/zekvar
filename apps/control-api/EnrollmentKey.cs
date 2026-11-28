using System.Text.Json.Serialization;

namespace Control;

// A device-manager enrollment key. The prefix keeps it out of every bearer-token path, which accepts only 64 hex characters.
internal static class EnrollmentKeyToken
{
    private const string Prefix = "zke_";
    public static string Generate() => Prefix + Tokens.Generate();
    public static bool IsValid(string? value) => value is { Length: 68 } && value.StartsWith(Prefix, StringComparison.Ordinal) &&
        Tokens.IsValid(value[Prefix.Length..]);
}

// MaxRedemptions is required: a shared key without a ceiling would let anyone who reads it from chrome://policy mint installations.
internal sealed record CreateEnrollmentKey(Guid RequestId, string? Label, Guid? GroupId, int Days, int? MaxRedemptions)
{
    public const int MaxDays = 30;
    public const int RedemptionLimit = 100_000;

    public bool IsValid(out string? label)
    {
        label = Label?.Trim();
        return RequestId != Guid.Empty && GroupId != Guid.Empty && label is { Length: >= 2 and <= 64 } && !label.Any(char.IsControl) &&
            Days is >= 1 and <= MaxDays && MaxRedemptions is >= 1 and <= RedemptionLimit;
    }
}

internal sealed record RotateEnrollmentKey(Guid RequestId, int Days, int? OverlapHours)
{
    public bool IsValid() => RequestId != Guid.Empty && Days is >= 1 and <= CreateEnrollmentKey.MaxDays && OverlapHours is null or (>= 1 and <= 720);
}

internal sealed record RedeemEnrollmentKey(string? Key, string? Nonce)
{
    public bool IsValid() => EnrollmentKeyToken.IsValid(Key) && Tokens.IsValid(Nonce);
}

internal sealed record EnrollmentKey(Guid Id, string Label, Guid? GroupId, string? GroupName, DateTime CreatedAt, DateTime ExpiresAt,
    int? MaxRedemptions, int Redeemed, int ActiveInstallations, DateTime? LastRedeemedAt, int Rejected, DateTime? LastRejectedAt,
    DateTime? RevokedAt, Guid? RotatedFrom, string Status);
internal sealed record IssuedEnrollmentKey(EnrollmentKey Key, string Token);
internal sealed record EnrollmentKeyOutcome(IssuedEnrollmentKey? Issued = null, string? Error = null);

internal sealed record EnrollmentKeyChange(Guid KeyId, string Label, Guid? GroupId, string? GroupName,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] DateTime? ExpiresAt = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? MaxRedemptions = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? Redeemed = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] Guid? RotatedFrom = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] DateTime? PreviousKeyExpiresAt = null);

// Redemption outcomes. Errors other than rate limiting are final for that key and profile.
internal sealed record EnrollmentKeyRedemption(Enrollment? Enrollment = null, string? Error = null, int RetryAfterSeconds = 0);
