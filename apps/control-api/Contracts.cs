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
    public const string GithubTokenRule = "github-app-or-fine-grained-token";
    public const string PaymentCategory = "payment-card";
    public const string UploadRule = "ai-file-upload";
    public const string FileInspectionUnavailableRule = "file-inspection-unavailable";
    public const string UploadCategory = "file-upload";
    public const string ExceptionApplied = "exception_applied";
    public const string ClipboardUnavailableRule = "clipboard-inspection-unavailable";
    public const string ClipboardCategory = "clipboard";
    public const string ClassificationRule = "organization-classification-rule";
    public const string ClassificationCategory = "classification";
    public static readonly string[] CloudCredentialRules =
        ["aws-access-key-id", "slack-token", "stripe-live-secret-key", "google-api-key", "openai-api-key", "anthropic-api-key"];

    public static bool IsMode(string? mode) => mode is "monitor" or "warn" or "block";
    public static bool IsOptionalDetectorMode(string? mode) => mode is null or "off" || IsMode(mode);
    public static bool IsAiPromptApp(string? appId) => appId is ChatGpt or Claude or Gemini;
    public static bool IsApp(string? appId) => appId == AppId || IsAiPromptApp(appId);
    public static bool IsDecision(string? decision) => IsMode(decision) || decision is "warn_override" or ExceptionApplied;
    public static bool IsPromptRule(string? rule) => rule is RuleId or GitHubPatRule or PaymentCardRule or PrivateKeyRule
        or OrganizationIdentifierRule or SsnRule or GithubTokenRule;
    public static bool IsCloudCredentialRule(string? rule) => rule is not null && CloudCredentialRules.Contains(rule);
    // Cloud credential and classification rules support enforcement modes but not temporary prompt exceptions.
    public static bool IsDetectionRule(string? rule) => IsPromptRule(rule) || IsCloudCredentialRule(rule) || rule == ClassificationRule;

    public static string CategoryForRule(string ruleId) => ruleId switch
    {
        GitHubPatRule or GithubTokenRule or PrivateKeyRule => CredentialCategory,
        _ when IsCloudCredentialRule(ruleId) => CredentialCategory,
        ClassificationRule => ClassificationCategory,
        PaymentCardRule => PaymentCategory,
        OrganizationIdentifierRule => OrganizationIdentifierCategory,
        SsnRule => SsnCategory,
        UploadRule or FileInspectionUnavailableRule => UploadCategory,
        ClipboardUnavailableRule => ClipboardCategory,
        _ => DetectorCategory
    };

    public static bool IsClipboardMode(string? mode) => mode is "off" or "monitor" or "block";

    public static bool IsEvent(PolicyEvent request)
    {
        if (request.EventId == Guid.Empty || request.Timestamp == default || request.PolicyVersion <= 0 || !IsApp(request.AppId)) return false;
        var promptRule = IsDetectionRule(request.RuleId) && request.DetectorCategory == CategoryForRule(request.RuleId) &&
            (request.Decision != ExceptionApplied || IsPromptRule(request.RuleId));
        if (request.ClipboardPaste)
            return IsAiPromptApp(request.AppId) && request.UploadMethod is null && request.Decision is "monitor" or "block" &&
                (promptRule || (request.RuleId == ClipboardUnavailableRule && request.DetectorCategory == ClipboardCategory && request.Decision == "block"));
        if (request.RuleId is UploadRule or FileInspectionUnavailableRule)
            return IsAiPromptApp(request.AppId) && request.DetectorCategory == UploadCategory &&
                (request.Decision == "block" || request.RuleId == UploadRule && request.Decision == "monitor") &&
                request.UploadMethod is "picker" or "drop" or "paste";
        return promptRule && (request.Decision != ExceptionApplied || request.AppId != AppId) &&
            (request.UploadMethod is null && IsDecision(request.Decision) ||
                IsAiPromptApp(request.AppId) && request.UploadMethod is "picker" or "drop" or "paste" && request.Decision is "monitor" or "block");
    }
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
    bool? PresetDiscoveryEnabled = null, string? SsnMode = null, BrowserHardening? BrowserHardening = null, string? ClipboardMode = null,
    string? GithubTokenMode = null, PromptAppModes? PromptAppModes = null, string[]? RequireComposerReady = null,
    string? CloudCredentialMode = null, ClassificationProtection? ClassificationProtection = null, AdapterControls? AdapterControls = null);
internal sealed record UploadModes(string? Chatgpt = null, string? Gemini = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Claude = null)
{
    public bool HasSettings() => Chatgpt is not null || Gemini is not null || Claude is not null;
    public bool IsValid() => Valid(Chatgpt) && Valid(Gemini) && Valid(Claude);
    private static bool Valid(string? value) => value is null or "off" or "monitor" or "block";
}
internal sealed record FileInspection(bool? Chatgpt = null, bool? Gemini = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] bool? Claude = null)
{
    public bool HasSettings() => Chatgpt.HasValue || Gemini.HasValue || Claude.HasValue;
}
internal sealed record RedeemGrant(string Grant);
internal sealed record Heartbeat(int PolicyVersion, string? ChatGptCoverage = null, bool DomainRulesApplied = false,
    int AssignmentVersion = 0, string? GeminiCoverage = null, bool PaymentCardModeApplied = false, bool UploadControlsApplied = false,
    bool PathRulesApplied = false, bool UploadTypesApplied = false, bool CustomDiscoveryApplied = false,
    bool PromptExceptionsApplied = false, string? ClaudeCoverage = null, bool ClaudePromptApplied = false, bool PrivateKeyModeApplied = false,
    bool FileInspectionApplied = false, bool AiAppAccessApplied = false, bool FileContentBlockApplied = false, bool IdentifiersApplied = false,
    bool SsnModeApplied = false, bool ClipboardModeApplied = false, bool GithubTokenModeApplied = false, bool PromptAppModesApplied = false,
    bool ClaudeFilesApplied = false, bool CloudCredentialModeApplied = false, bool ClassificationApplied = false,
    bool AdapterControlsApplied = false)
{
    // "disabled" reports that an administrator turned the adapter off; Control accepts it only for a matching policy.
    public bool IsValid() => (ChatGptCoverage is null or "ready" or "unsupported" or "disabled") &&
        (GeminiCoverage is null or "ready" or "unsupported" or "disabled") &&
        (ClaudeCoverage is null or "ready" or "unsupported" or "disabled") && (!FileContentBlockApplied || FileInspectionApplied) &&
        (!ClaudeFilesApplied || ClaudePromptApplied);
}
internal sealed record PolicyEvent(Guid EventId, string AppId, DateTimeOffset Timestamp, string RuleId,
    string DetectorCategory, int PolicyVersion, string Decision, int AssignmentVersion = 0, string? UploadMethod = null, bool ClipboardPaste = false);

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
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? SsnMode = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] BrowserHardening? BrowserHardening = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ClipboardMode = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? GithubTokenMode = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] bool? PromptExceptionRequestsAvailable = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] PromptAppModes? PromptAppModes = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? CloudCredentialMode = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] ClassificationProtection? ClassificationProtection = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AdapterControls? AdapterControls = null)
{
    public string AppId => FixtureContract.AppId;
    public string[] AppIds => ClaudePromptEnabled
        ? [FixtureContract.AppId, FixtureContract.ChatGpt, FixtureContract.Gemini, FixtureContract.Claude]
        : [FixtureContract.AppId, FixtureContract.ChatGpt, FixtureContract.Gemini];
    public string RuleId => FixtureContract.RuleId;
    public string DetectorCategory => FixtureContract.DetectorCategory;

    public UploadModes EffectiveFileContentModes() => FileContentModes ??
        new(FileInspection?.Chatgpt == true ? "monitor" : "off", FileInspection?.Gemini == true ? "monitor" : "off",
            FileInspection?.Claude == true ? "monitor" : null);

    public string? PromptModeForApp(string appId, string ruleId, bool appModesAware = true)
    {
        var mode = ruleId switch
        {
            FixtureContract.RuleId => Mode,
            FixtureContract.GitHubPatRule => GithubPatMode,
            FixtureContract.GithubTokenRule => GithubTokenMode,
            FixtureContract.PaymentCardRule => PaymentCardMode,
            FixtureContract.PrivateKeyRule => PrivateKeyMode,
            FixtureContract.OrganizationIdentifierRule => IdentifierProtection?.Mode,
            FixtureContract.SsnRule => SsnMode,
            FixtureContract.ClassificationRule => ClassificationProtection?.Mode,
            _ when FixtureContract.IsCloudCredentialRule(ruleId) => CloudCredentialMode,
            _ => null
        };
        return appModesAware && FixtureContract.IsMode(mode) ? PromptAppModes?.ForApp(appId) ?? mode : mode;
    }

    public Policy ForBrowser(bool claudeAware, bool privateKeyAware, bool fileInspectionAware, bool aiAppAccessAware,
        bool fileBlockAware, bool identifiersAware, bool presetDiscoveryAware, bool ssnAware, bool clipboardAware, bool githubTokenAware,
        bool promptAppModesAware, bool claudeFilesAware, bool detectionRulesAware, bool adapterControlsAware)
    {
        var now = DateTimeOffset.UtcNow;
        var nowMs = now.ToUnixTimeMilliseconds();
        var claudeEnabled = claudeAware && ClaudePromptEnabled;
        var content = EffectiveFileContentModes();
        var claudeFiles = claudeEnabled && claudeFilesAware;
        var exceptions = PromptExceptions?.Where(entry => (entry.AppId != FixtureContract.Claude || claudeEnabled) &&
            (entry.RuleId != FixtureContract.PrivateKeyRule || privateKeyAware) &&
            (entry.RuleId != FixtureContract.OrganizationIdentifierRule || identifiersAware) &&
            (entry.RuleId != FixtureContract.SsnRule || ssnAware) &&
            (entry.RuleId != FixtureContract.GithubTokenRule || githubTokenAware) &&
            (PromptAppModes?.ForApp(entry.AppId) is null && entry.RuleId is FixtureContract.RuleId or FixtureContract.GitHubPatRule or FixtureContract.PaymentCardRule ||
                PromptModeForApp(entry.AppId, entry.RuleId, promptAppModesAware) is "warn" or "block"))
            .Select(entry => new PromptExceptionGrant(entry.AppId, entry.RuleId, entry.ExpiresAt.ToUnixTimeMilliseconds()))
            .Where(entry => entry.ExpiresAtMs > nowMs).ToArray();
        var browser = this with
        {
            ClaudePromptEnabled = claudeEnabled,
            PrivateKeyMode = privateKeyAware ? PrivateKeyMode : "off",
            FileInspection = new(fileInspectionAware && (content.Chatgpt == "monitor" || fileBlockAware && content.Chatgpt == "block"),
                fileInspectionAware && (content.Gemini == "monitor" || fileBlockAware && content.Gemini == "block"),
                claudeFiles ? content.Claude is "monitor" or "block" : null),
            FileContentModes = fileBlockAware ? content with { Claude = claudeFiles ? content.Claude ?? "off" : null } : null,
            UploadModes = UploadModes with { Claude = claudeFiles ? UploadModes.Claude ?? "off" : null },
            UploadTypes = UploadTypes is null ? null : UploadTypes with { Claude = claudeFiles ? UploadTypes.Claude : null },
            IdentifierProtection = identifiersAware ? IdentifierProtection : null,
            PresetDiscoveryEnabled = presetDiscoveryAware && DiscoveryEnabled ? PresetDiscoveryEnabled : null,
            SsnMode = ssnAware ? SsnMode : null,
            ClipboardMode = clipboardAware ? ClipboardMode : null,
            GithubTokenMode = githubTokenAware ? GithubTokenMode : null,
            CloudCredentialMode = detectionRulesAware ? CloudCredentialMode : null,
            ClassificationProtection = detectionRulesAware ? ClassificationProtection : null,
            PromptAppModes = promptAppModesAware ? PromptAppModes : null,
            ExtensionDeployment = null,
            BrowserHardening = null,
            BlockedAiAppHosts = aiAppAccessAware ? AdapterControls.EffectiveBlockedHosts(BlockedAiAppHosts, AdapterControls) : null,
            AdapterControls = adapterControlsAware ? AdapterControls ?? new() : null,
            PromptExceptions = PromptExceptions is { Length: > 0 } ? null : PromptExceptions,
            PromptExceptionLease = exceptions is { Length: > 0 } ? new(nowMs, exceptions) : null
        };
        var chatgpt = UploadFilter.From(UploadModes.Chatgpt, UploadTypes?.Chatgpt);
        var gemini = UploadFilter.From(UploadModes.Gemini, UploadTypes?.Gemini);
        var claude = claudeFiles ? UploadFilter.From(UploadModes.Claude, UploadTypes?.Claude) : null;
        if (chatgpt is null && gemini is null && claude is null) return browser;
        // Older clients receive Off for the scoped destinations and keep their other controls.
        return browser with
        {
            UploadTypes = null,
            UploadModes = new(chatgpt is null ? UploadModes.Chatgpt : "off", gemini is null ? UploadModes.Gemini : "off",
                claude is null ? browser.UploadModes.Claude : "off"),
            TargetedUploads = new(chatgpt, gemini, claude)
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
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] EventTriage? Triage,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] bool ClipboardPaste = false)
{
    public string DetectorCategory => FixtureContract.CategoryForRule(RuleId);
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
