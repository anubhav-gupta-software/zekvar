using System.Globalization;
using System.Text.Json.Serialization;

namespace Control;

internal static class EventFeedToken
{
    private const string Prefix = "zkf_";
    public static string Generate() => Prefix + Tokens.Generate();
    public static bool IsValid(string? value) => value is { Length: 68 } && value.StartsWith(Prefix, StringComparison.Ordinal) &&
        Tokens.IsValid(value[Prefix.Length..]);
}

internal sealed record CreateEventFeedKey(Guid RequestId, string? Name, int Days);
internal sealed record EventFeedKey(Guid Id, string Name, DateTime IssuedAt, DateTime ExpiresAt, string Status);
internal sealed record IssuedEventFeedKey(EventFeedKey Key, string Token);
internal sealed record EventFeedKeyOutcome(IssuedEventFeedKey? Issued = null, string? Error = null);
internal sealed record EventFeedKeyChange(Guid KeyId, string Name,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] DateTime? ExpiresAt = null);

internal sealed record EventFeedRead(bool Authorized, EventFeedPage? Page = null);

internal readonly record struct EventFeedCursor(Guid StreamId, long Sequence)
{
    public override string ToString() => StreamId.ToString("N") + ":" + Sequence.ToString(CultureInfo.InvariantCulture);

    public static bool TryParse(string value, out EventFeedCursor cursor)
    {
        cursor = default;
        if (value.Length is < 34 or > 52 || value[32] != ':' || !Guid.TryParseExact(value.AsSpan(0, 32), "N", out var stream) ||
            stream == Guid.Empty || !long.TryParse(value.AsSpan(33), NumberStyles.None, CultureInfo.InvariantCulture, out var sequence) ||
            sequence < 0) return false;
        cursor = new(stream, sequence);
        return true;
    }
}

internal sealed record EventFeedEntry(Guid EventId, Guid InstallationId, DateTime Timestamp, DateTime ReceivedAt, int PolicyVersion,
    string AppId, string RuleId, string Decision, EventRollout Rollout,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? UploadMethod)
{
    public string DetectorCategory => FixtureContract.CategoryForRule(RuleId);
}

internal sealed record EventFeedPage(int SchemaVersion, IReadOnlyList<EventFeedEntry> Entries, string NextCursor, bool HasMore);
