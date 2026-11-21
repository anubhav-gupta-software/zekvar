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

internal sealed record InventoryInstallation(Guid InstallationId, string? GroupName, string Status, DateTime? ReportedAt,
    int ExtensionCount, int Omitted, InventoryExtension[]? Entries);
