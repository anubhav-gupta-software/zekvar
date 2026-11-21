using System.Security.Cryptography;
using System.Text;

namespace Control;

internal static class FixtureContract
{
    public const string AppId = "local-prompt-fixture";
    public const string ChatGpt = "chatgpt";
    public const string RuleId = "fixture-secret";
    public const string DetectorCategory = "synthetic-secret";

    public static bool IsMode(string? mode) => mode is "monitor" or "warn" or "block";

    public static bool IsEvent(PolicyEvent request) =>
        request.EventId != Guid.Empty && request.Timestamp != default && request.PolicyVersion > 0 &&
        (request.AppId is AppId or ChatGpt) && request.RuleId == RuleId && request.DetectorCategory == DetectorCategory &&
        (IsMode(request.Decision) || request.Decision == "warn_override");
}

internal static class Tokens
{
    public static string Generate() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));

    public static bool IsValid(string? value) => value is { Length: 64 } &&
        value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    public static string Hash(string token) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
}

internal sealed record DemoOrganization(string Slug, string AdminToken);
internal sealed record RequestIdentity(Guid OrganizationId, Guid? InstallationId, string? OrganizationSlug);
internal sealed record PublishPolicy(string Mode);
internal sealed record RedeemGrant(string Grant);
internal sealed record Heartbeat(int PolicyVersion, string? ChatGptCoverage = null);
internal sealed record PolicyEvent(Guid EventId, string AppId, DateTimeOffset Timestamp, string RuleId,
    string DetectorCategory, int PolicyVersion, string Decision);

internal sealed record Policy(int Version, string Mode, DateTime PublishedAt, int? RestoredFrom)
{
    public string AppId => FixtureContract.AppId;
    public string[] AppIds => [FixtureContract.AppId, FixtureContract.ChatGpt];
    public string RuleId => FixtureContract.RuleId;
    public string DetectorCategory => FixtureContract.DetectorCategory;
}

internal sealed record EnrollmentGrant(string Grant, DateTime ExpiresAt);
internal sealed record Enrollment(Guid InstallationId, string Token);
internal sealed record Installation(Guid InstallationId, DateTime EnrolledAt, DateTime LastSeenAt,
    int? AppliedPolicyVersion, DateTime? RevokedAt, string? ChatGptCoverage, DateTime? ChatGptCheckedAt);

internal sealed record StoredEvent(Guid EventId, Guid InstallationId, DateTime Timestamp, DateTime ReceivedAt,
    int PolicyVersion, string Decision, string AppId)
{
    public string RuleId => FixtureContract.RuleId;
    public string DetectorCategory => FixtureContract.DetectorCategory;
}
