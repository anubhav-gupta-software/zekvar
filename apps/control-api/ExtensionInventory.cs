using System.Text.Json.Serialization;

namespace Control;

internal sealed record InventoryExtension(string Id, string Name, string Version, [property: JsonRequired] bool Enabled, string InstallType,
    string SiteAccess, string[] Permissions)
{
    private static readonly HashSet<string> ObservedPermissions = new(StringComparer.Ordinal)
    {
        "clipboardRead", "cookies", "debugger", "declarativeNetRequest", "declarativeNetRequestWithHostAccess", "downloads",
        "history", "management", "nativeMessaging", "proxy", "scripting", "tabs", "webRequest", "webRequestBlocking"
    };

    public bool IsValid() => Id is { Length: 32 } && Id.All(c => c is >= 'a' and <= 'p') &&
        Name is { Length: >= 1 and <= 100 } && Name.Trim() == Name && !Name.Any(char.IsControl) &&
        Version is { Length: >= 1 and <= 23 } && ValidVersion(Version) &&
        InstallType is "admin" or "development" or "normal" or "sideload" or "other" &&
        SiteAccess is "none" or "selected" or "all" &&
        Permissions is { Length: <= 14 } && Permissions.All(p => p is not null && ObservedPermissions.Contains(p)) &&
        Permissions.Distinct(StringComparer.Ordinal).Count() == Permissions.Length;

    private static bool ValidVersion(string version)
    {
        var parts = version.Split('.');
        return parts.Length <= 4 && parts.All(part => part.Length is >= 1 and <= 5 &&
            part.All(char.IsAsciiDigit) && ushort.TryParse(part, out _));
    }
}

internal sealed record ReportExtensionInventory(int PolicyVersion, int AssignmentVersion, DateTimeOffset CapturedAt, string Status,
    InventoryExtension[] Entries, int Omitted)
{
    public const int MaxBodySize = 128 * 1024;

    public bool IsValid(DateTimeOffset now) =>
        PolicyVersion > 0 && AssignmentVersion >= 0 && CapturedAt >= now.AddMinutes(-15) && CapturedAt <= now.AddMinutes(2) &&
        Status is "reported" or "permission_required" or "unavailable" && Entries is { Length: <= 100 } && Omitted >= 0 &&
        (Status == "reported" || Entries.Length == 0 && Omitted == 0) &&
        Entries.All(entry => entry is not null && entry.IsValid()) &&
        Entries.Select(entry => entry.Id).Distinct(StringComparer.Ordinal).Count() == Entries.Length;
}

internal sealed record InventoryExtensionState(string Version, bool Enabled, string InstallType, string SiteAccess, string[] Permissions)
{
    public static InventoryExtensionState From(InventoryExtension extension) =>
        new(extension.Version, extension.Enabled, extension.InstallType, extension.SiteAccess,
            extension.Permissions.Order(StringComparer.Ordinal).ToArray());

    public bool Matches(InventoryExtensionState other) =>
        Version == other.Version && Enabled == other.Enabled && InstallType == other.InstallType && SiteAccess == other.SiteAccess &&
        Permissions.SequenceEqual(other.Permissions);
}

internal sealed record InventoryExtensionChange(string ExtensionId, InventoryExtensionState? Before, InventoryExtensionState? After)
{
    private static readonly HashSet<string> PrivilegedPermissions = new(StringComparer.Ordinal)
        { "cookies", "debugger", "management", "nativeMessaging", "proxy" };

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool ReviewAccess => After is { Enabled: true } current && (
        Before is not { Enabled: true } prior
            ? current.SiteAccess == "all" || RiskySource(current.InstallType) || current.Permissions.Any(PrivilegedPermissions.Contains)
            : AccessRank(current.SiteAccess) > AccessRank(prior.SiteAccess) ||
                (current.InstallType != prior.InstallType && RiskySource(current.InstallType)) ||
                current.Permissions.Any(permission => PrivilegedPermissions.Contains(permission) && !prior.Permissions.Contains(permission)));

    private static bool RiskySource(string source) => source is "development" or "sideload";
    private static int AccessRank(string siteAccess) => siteAccess switch { "all" => 2, "selected" => 1, _ => 0 };

    public static InventoryExtensionChange[] Compare(InventoryExtension[] previous, ReportExtensionInventory report, bool fullSnapshot)
    {
        var before = previous.ToDictionary(extension => extension.Id, InventoryExtensionState.From, StringComparer.Ordinal);
        var after = report.Entries.ToDictionary(extension => extension.Id, InventoryExtensionState.From, StringComparer.Ordinal);
        var changes = new List<InventoryExtensionChange>();
        foreach (var id in before.Keys.Union(after.Keys).Order(StringComparer.Ordinal))
        {
            before.TryGetValue(id, out var oldState);
            after.TryGetValue(id, out var newState);
            if (oldState is not null && newState is not null ? !oldState.Matches(newState) : fullSnapshot)
                changes.Add(new(id, oldState, newState));
        }
        return changes.ToArray();
    }
}

internal sealed record InventoryChangeBatch(string Id, int PolicyVersion, DateTimeOffset ReportedAt, InventoryExtensionChange[] Changes);

internal sealed record InventoryInstallation(Guid InstallationId, string? GroupName, string Status, DateTime? ReportedAt,
    int ExtensionCount, int Omitted, InventoryExtension[]? Entries,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] InventoryChangeBatch[]? ChangeHistory = null);
