using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace Control;

internal static class FixtureContract
{
    public const string AppId = "local-prompt-fixture";
    public const string ChatGpt = "chatgpt";
    public const string RuleId = "fixture-secret";
    public const string DetectorCategory = "synthetic-secret";
    public const string GitHubPatRule = "github-classic-pat";
    public const string CredentialCategory = "credential";

    public static bool IsMode(string? mode) => mode is "monitor" or "warn" or "block";

    public static bool IsEvent(PolicyEvent request) =>
        request.EventId != Guid.Empty && request.Timestamp != default && request.PolicyVersion > 0 &&
        (request.AppId is AppId or ChatGpt) &&
        ((request.RuleId == RuleId && request.DetectorCategory == DetectorCategory) ||
         (request.RuleId == GitHubPatRule && request.DetectorCategory == CredentialCategory)) &&
        (IsMode(request.Decision) || request.Decision == "warn_override");
}

internal static class DiscoveryCatalog
{
    public static readonly string[] AppIds = [FixtureContract.ChatGpt, "claude", "gemini"];

    public static bool IsApp(string? appId) => appId is not null && AppIds.Contains(appId);
    public static bool IsStatus(string? status) => status is "unreviewed" or "approved" or "unapproved";
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
internal sealed record PublishPolicy(string? Mode = null, string? GithubPatMode = null, bool? DiscoveryEnabled = null,
    DomainRules? DomainRules = null, int? ExpectedVersion = null);
internal sealed record RedeemGrant(string Grant);
internal sealed record Heartbeat(int PolicyVersion, string? ChatGptCoverage = null, bool DomainRulesApplied = false,
    int AssignmentVersion = 0);
internal sealed record PolicyEvent(Guid EventId, string AppId, DateTimeOffset Timestamp, string RuleId,
    string DetectorCategory, int PolicyVersion, string Decision, int AssignmentVersion = 0);

internal sealed record Policy(int Version, string Mode, DateTime PublishedAt, int? RestoredFrom, string GithubPatMode,
    bool DiscoveryEnabled, DomainRules DomainRules,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] int AssignmentVersion = 0)
{
    public string AppId => FixtureContract.AppId;
    public string[] AppIds => [FixtureContract.AppId, FixtureContract.ChatGpt];
    public string RuleId => FixtureContract.RuleId;
    public string DetectorCategory => FixtureContract.DetectorCategory;
}

internal sealed record AppObservation(string AppId, DateTimeOffset ObservedAt, int PolicyVersion, int AssignmentVersion = 0);
internal sealed record ClassifyApp(string Status);
internal sealed record DiscoveredApp(string AppId, string Status, long BrowsersSeen, DateTime? LastObservedAt);

internal sealed record EnrollmentGrant(string Grant, DateTime ExpiresAt);
internal sealed record Enrollment(Guid InstallationId, string Token);
internal sealed record Installation(Guid InstallationId, DateTime EnrolledAt, DateTime LastSeenAt,
    int? AppliedPolicyVersion, DateTime? RevokedAt, string? ChatGptCoverage, DateTime? ChatGptCheckedAt,
    Guid? PolicyGroupId, string? PolicyGroupName, int ExpectedPolicyVersion, bool AssignmentAware);

internal sealed record StoredEvent(Guid EventId, Guid InstallationId, DateTime Timestamp, DateTime ReceivedAt,
    int PolicyVersion, string Decision, string AppId, string RuleId)
{
    public string DetectorCategory => RuleId == FixtureContract.GitHubPatRule
        ? FixtureContract.CredentialCategory : FixtureContract.DetectorCategory;
}
