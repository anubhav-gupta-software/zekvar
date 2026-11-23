using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace Control;

internal static class FixtureContract
{
    public const string AppId = "local-prompt-fixture";
    public const string ChatGpt = "chatgpt";
    public const string Claude = "claude";
    public const string Gemini = "gemini";
    public const string RuleId = "fixture-secret";
    public const string DetectorCategory = "synthetic-secret";
    public const string GitHubPatRule = "github-classic-pat";
    public const string CredentialCategory = "credential";
    public const string PaymentCardRule = "payment-card-number";
    public const string PrivateKeyRule = "pem-private-key";
    public const string OrganizationIdentifierRule = "organization-identifier";
    public const string OrganizationIdentifierCategory = "internal-identifier";
    public const string SsnRule = "us-social-security-number";
    public const string SsnCategory = "government-identifier";
    public const string PaymentCategory = "payment-card";
    public const string UploadRule = "ai-file-upload";
    public const string FileInspectionUnavailableRule = "file-inspection-unavailable";
    public const string UploadCategory = "file-upload";
    public const string ExceptionApplied = "exception_applied";

    public static bool IsMode(string? mode) => mode is "monitor" or "warn" or "block";
    public static bool IsOptionalDetectorMode(string? mode) => mode is null or "off" || IsMode(mode);
    public static bool IsAiPromptApp(string? appId) => appId is ChatGpt or Claude or Gemini;
    public static bool IsApp(string? appId) => appId == AppId || IsAiPromptApp(appId);
    public static bool IsDecision(string? decision) => IsMode(decision) || decision is "warn_override" or ExceptionApplied;
    public static bool IsPromptRule(string? rule) => rule is RuleId or GitHubPatRule or PaymentCardRule or PrivateKeyRule or OrganizationIdentifierRule or SsnRule;

    public static bool IsEvent(PolicyEvent request) =>
        request.EventId != Guid.Empty && request.Timestamp != default && request.PolicyVersion > 0 &&
        IsApp(request.AppId) && (request.RuleId is UploadRule or FileInspectionUnavailableRule
            ? request.AppId is ChatGpt or Gemini && request.DetectorCategory == UploadCategory &&
              (request.Decision == "block" || request.RuleId == UploadRule && request.Decision == "monitor") &&
              request.UploadMethod is "picker" or "drop" or "paste"
            : (request.UploadMethod is null && IsDecision(request.Decision) ||
                (request.AppId is ChatGpt or Gemini) && (request.UploadMethod is "picker" or "drop" or "paste") && request.Decision is "monitor" or "block") &&
              (request.Decision != ExceptionApplied || request.AppId != AppId) &&
              ((request.RuleId == RuleId && request.DetectorCategory == DetectorCategory) ||
               ((request.RuleId is GitHubPatRule or PrivateKeyRule) && request.DetectorCategory == CredentialCategory) ||
               (request.RuleId == PaymentCardRule && request.DetectorCategory == PaymentCategory) ||
               (request.RuleId == OrganizationIdentifierRule && request.DetectorCategory == OrganizationIdentifierCategory) ||
               (request.RuleId == SsnRule && request.DetectorCategory == SsnCategory)));
}

internal static class DiscoveryCatalog
{
    public static readonly string[] ComposerAppIds = [FixtureContract.ChatGpt, FixtureContract.Claude, FixtureContract.Gemini];
    private static readonly Dictionary<string, (string Name, string[] Hosts)> Presets = new(StringComparer.Ordinal)
    {
        ["copilot"] = ("Microsoft Copilot", ["copilot.microsoft.com", "copilot.com"]),
        ["perplexity"] = ("Perplexity", ["perplexity.ai", "www.perplexity.ai"]),
        ["grok"] = ("Grok", ["grok.com"]),
        ["meta-ai"] = ("Meta AI", ["meta.ai", "www.meta.ai"]),
        ["deepseek"] = ("DeepSeek", ["chat.deepseek.com"]),
    };
    public static readonly string[] AppIds = [..ComposerAppIds, ..Presets.Keys];

    public static bool IsBuiltIn(string? appId) => appId is not null && AppIds.Contains(appId);
    public static string[] PresetHosts(string appId) => Presets.TryGetValue(appId, out var preset) ? preset.Hosts : [];
    public static string? PresetName(string appId) => Presets.TryGetValue(appId, out var preset) ? preset.Name : null;
    public static bool IsPresetHost(string host) => Presets.Values.Any(preset => preset.Hosts.Contains(host));
    public static bool IsApp(string? appId) => IsBuiltIn(appId) || CustomApps.IsId(appId);
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
internal sealed record RequestIdentity(Guid OrganizationId, Guid? InstallationId, string? OrganizationSlug, AccessIdentity? Access)
{
    public string? Role => Access?.Role ?? (OrganizationSlug is null ? null : AccessRoles.Owner);
}
internal sealed record PublishPolicy(string? Mode = null, string? GithubPatMode = null, bool? DiscoveryEnabled = null,
    DomainRules? DomainRules = null, int? ExpectedVersion = null, string? PaymentCardMode = null, UploadModes? UploadModes = null,
    PathRules? PathRules = null, bool? ExtensionInventoryEnabled = null, UploadTypes? UploadTypes = null,
    CustomAppSetting?[]? CustomApps = null, PromptException?[]? PromptExceptions = null, bool? ClaudePromptEnabled = null,
    string? PrivateKeyMode = null, FileInspection? FileInspection = null, ExtensionDeployment? ExtensionDeployment = null,
    string[]? BlockedAiAppHosts = null, UploadModes? FileContentModes = null, IdentifierProtection? IdentifierProtection = null,
    bool? PresetDiscoveryEnabled = null, string? SsnMode = null);
internal sealed record UploadModes(string? Chatgpt = null, string? Gemini = null)
{
    public bool HasSettings() => Chatgpt is not null || Gemini is not null;
    public bool IsValid() => (Chatgpt is null or "off" or "monitor" or "block") && (Gemini is null or "off" or "monitor" or "block");
}
internal sealed record FileInspection(bool? Chatgpt = null, bool? Gemini = null)
{
    public bool HasSettings() => Chatgpt.HasValue || Gemini.HasValue;
}
internal sealed record RedeemGrant(string Grant);
internal sealed record Heartbeat(int PolicyVersion, string? ChatGptCoverage = null, bool DomainRulesApplied = false,
    int AssignmentVersion = 0, string? GeminiCoverage = null, bool PaymentCardModeApplied = false, bool UploadControlsApplied = false,
    bool PathRulesApplied = false, bool UploadTypesApplied = false, bool CustomDiscoveryApplied = false,
    bool PromptExceptionsApplied = false, string? ClaudeCoverage = null, bool ClaudePromptApplied = false, bool PrivateKeyModeApplied = false,
    bool FileInspectionApplied = false, bool AiAppAccessApplied = false, bool FileContentBlockApplied = false, bool IdentifiersApplied = false,
    bool SsnModeApplied = false)
{
    public bool IsValid() => (ChatGptCoverage is null or "ready" or "unsupported") &&
        (GeminiCoverage is null or "ready" or "unsupported") &&
        (ClaudeCoverage is null or "ready" or "unsupported") && (!FileContentBlockApplied || FileInspectionApplied);
}
internal sealed record PolicyEvent(Guid EventId, string AppId, DateTimeOffset Timestamp, string RuleId,
    string DetectorCategory, int PolicyVersion, string Decision, int AssignmentVersion = 0, string? UploadMethod = null);

internal sealed record Policy(int Version, string Mode, DateTime PublishedAt, int? RestoredFrom, string GithubPatMode,
    bool DiscoveryEnabled, DomainRules DomainRules, string PaymentCardMode, UploadModes UploadModes, PathRules PathRules,
    bool ExtensionInventoryEnabled = false,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] UploadTypes? UploadTypes = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] CustomApp[]? CustomApps = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] PromptException[]? PromptExceptions = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] TargetedUploads? TargetedUploads = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] PromptExceptionLease? PromptExceptionLease = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] int AssignmentVersion = 0,
    bool ClaudePromptEnabled = false,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? PrivateKeyMode = "off",
    FileInspection? FileInspection = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] ExtensionDeployment? ExtensionDeployment = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string[]? BlockedAiAppHosts = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] UploadModes? FileContentModes = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] IdentifierProtection? IdentifierProtection = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] bool? PresetDiscoveryEnabled = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? SsnMode = null)
{
    public string AppId => FixtureContract.AppId;
    public string[] AppIds => ClaudePromptEnabled
        ? [FixtureContract.AppId, FixtureContract.ChatGpt, FixtureContract.Gemini, FixtureContract.Claude]
        : [FixtureContract.AppId, FixtureContract.ChatGpt, FixtureContract.Gemini];
    public string RuleId => FixtureContract.RuleId;
    public string DetectorCategory => FixtureContract.DetectorCategory;

    public UploadModes EffectiveFileContentModes() => FileContentModes ??
        new(FileInspection?.Chatgpt == true ? "monitor" : "off", FileInspection?.Gemini == true ? "monitor" : "off");

    public Policy ForBrowser(bool claudeAware, bool privateKeyAware, bool fileInspectionAware, bool aiAppAccessAware,
        bool fileBlockAware, bool identifiersAware, bool presetDiscoveryAware, bool ssnAware)
    {
        var now = DateTimeOffset.UtcNow;
        var nowMs = now.ToUnixTimeMilliseconds();
        var claudeEnabled = claudeAware && ClaudePromptEnabled;
        var content = EffectiveFileContentModes();
        var exceptions = PromptExceptions?.Where(entry => (entry.AppId != FixtureContract.Claude || claudeEnabled) &&
            (entry.RuleId != FixtureContract.PrivateKeyRule || privateKeyAware && PrivateKeyMode is "warn" or "block") &&
            (entry.RuleId != FixtureContract.OrganizationIdentifierRule || identifiersAware && IdentifierProtection?.Mode is "warn" or "block") &&
            (entry.RuleId != FixtureContract.SsnRule || ssnAware && SsnMode is "warn" or "block"))
            .Select(entry => new PromptExceptionGrant(entry.AppId, entry.RuleId, entry.ExpiresAt.ToUnixTimeMilliseconds()))
            .Where(entry => entry.ExpiresAtMs > nowMs).ToArray();
        var browser = this with
        {
            ClaudePromptEnabled = claudeEnabled,
            PrivateKeyMode = privateKeyAware ? PrivateKeyMode : "off",
            FileInspection = new(fileInspectionAware && (content.Chatgpt == "monitor" || fileBlockAware && content.Chatgpt == "block"),
                fileInspectionAware && (content.Gemini == "monitor" || fileBlockAware && content.Gemini == "block")),
            FileContentModes = fileBlockAware ? content : null,
            IdentifierProtection = identifiersAware ? IdentifierProtection : null,
            PresetDiscoveryEnabled = presetDiscoveryAware && DiscoveryEnabled ? PresetDiscoveryEnabled : null,
            SsnMode = ssnAware ? SsnMode : null,
            ExtensionDeployment = null,
            BlockedAiAppHosts = aiAppAccessAware ? BlockedAiAppHosts : null,
            PromptExceptions = PromptExceptions is { Length: > 0 } ? null : PromptExceptions,
            PromptExceptionLease = exceptions is { Length: > 0 } ? new(nowMs, exceptions) : null
        };
        var chatgpt = UploadFilter.From(UploadModes.Chatgpt, UploadTypes?.Chatgpt);
        var gemini = UploadFilter.From(UploadModes.Gemini, UploadTypes?.Gemini);
        if (chatgpt is null && gemini is null) return browser;
        // Older clients receive Off for the scoped destinations and keep their other controls.
        return browser with
        {
            UploadTypes = null,
            UploadModes = new(chatgpt is null ? UploadModes.Chatgpt : "off", gemini is null ? UploadModes.Gemini : "off"),
            TargetedUploads = new(chatgpt, gemini)
        };
    }
}

internal sealed record AppObservation(string AppId, DateTimeOffset ObservedAt, int PolicyVersion, int AssignmentVersion = 0);
internal sealed record ClassifyApp(string Status);
internal sealed record DiscoveredApp(string AppId, string Status, long BrowsersSeen, DateTime? LastObservedAt,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Host = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Name = null);

internal sealed record EnrollmentGrant(string Grant, DateTime ExpiresAt);
internal sealed record Enrollment(Guid InstallationId, string Token);
internal sealed record Installation(Guid InstallationId, DateTime EnrolledAt, DateTime LastSeenAt,
    int? AppliedPolicyVersion, DateTime? RevokedAt, string? ChatGptCoverage, DateTime? ChatGptCheckedAt,
    Guid? PolicyGroupId, string? PolicyGroupName, int ExpectedPolicyVersion, bool AssignmentAware,
    string? GeminiCoverage, DateTime? GeminiCheckedAt, bool ClaudePromptEnabled, string? ClaudeCoverage, DateTime? ClaudeCheckedAt,
    string? ExtensionVersion, DateTime? ExtensionVersionReportedAt,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] IReadOnlyDictionary<string, ComposerCheck>? ComposerReadiness = null);

internal sealed record StoredEvent(Guid EventId, Guid InstallationId, DateTime Timestamp, DateTime ReceivedAt,
    int PolicyVersion, string Decision, string AppId, string RuleId,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? UploadMethod, EventRollout Rollout,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] EventTriage? Triage)
{
    public string DetectorCategory => RuleId switch
    {
        FixtureContract.GitHubPatRule or FixtureContract.PrivateKeyRule => FixtureContract.CredentialCategory,
        FixtureContract.PaymentCardRule => FixtureContract.PaymentCategory,
        FixtureContract.OrganizationIdentifierRule => FixtureContract.OrganizationIdentifierCategory,
        FixtureContract.SsnRule => FixtureContract.SsnCategory,
        FixtureContract.UploadRule or FixtureContract.FileInspectionUnavailableRule => FixtureContract.UploadCategory,
        _ => FixtureContract.DetectorCategory
    };
}

internal sealed record EventRollout(string Kind,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] Guid? GroupId = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? GroupName = null);

internal readonly record struct EventRolloutFilter(bool? Attributed, Guid? GroupId)
{
    public static EventRolloutFilter? Parse(string? value) => value switch
    {
        null or "" => new(null, null),
        "baseline" => new(true, null),
        "unattributed" => new(false, null),
        _ when value.Length == 36 && Guid.TryParseExact(value, "D", out var id) && id != Guid.Empty => new(true, id),
        _ => null
    };
}

internal sealed record EventFilters(string? AppId, string? Decision, DateTimeOffset? Since, DateTimeOffset? Until, Guid? InstallationId,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? RolloutGroup = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? TriageStatus = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? TriageAssignee = null)
{
    public bool Valid() =>
        (AppId is null || FixtureContract.IsApp(AppId)) &&
        (Decision is null || FixtureContract.IsDecision(Decision)) &&
        (Since is null || Until is null || Since < Until) && InstallationId != Guid.Empty &&
        EventRolloutFilter.Parse(RolloutGroup) is not null && ValidTriage();

    public bool ValidTriage() => (TriageStatus is null or "" || Control.TriageStatus.IsValid(TriageStatus)) &&
        TriageAssigneeFilter.Parse(TriageAssignee) is not null;
}

internal sealed record EventCursor(DateTimeOffset ReceivedAt, Guid EventId, Guid InstallationId);
internal sealed record EventPage(IReadOnlyList<StoredEvent> Entries, EventCursor? Next);
internal sealed record EventExport(string Organization, DateTime ExportedAt, EventFilters Filters, IAsyncEnumerable<StoredEvent> Entries);
