using System.Globalization;
using System.Text.RegularExpressions;

namespace Control;

internal sealed record BrowserReleaseCount(string Kind, string? ExtensionVersion, long Installations, long RecentReports);
internal sealed record BrowserHealthView(long ActiveInstallations, IReadOnlyList<BrowserReleaseCount> Releases,
    IReadOnlyList<Installation> Installations, BrowserComposerReadiness ComposerReadiness);

internal readonly record struct BrowserHealthFilter(bool Scoped, Guid? GroupId, string? Version)
{
    public static bool TryParse(string? group, string? version, out BrowserHealthFilter filter)
    {
        filter = default;
        Guid? groupId = null;
        var scoped = group is not (null or "");
        if (scoped && group != "baseline")
        {
            if (!Guid.TryParseExact(group, "D", out var id) || id == Guid.Empty) return false;
            groupId = id;
        }
        if (version == "") version = null;
        if (version is not (null or "unreported") && BrowserRelease.ReadVersion(version) is null) return false;
        filter = new(scoped, groupId, version);
        return true;
    }
}

internal static partial class BrowserRelease
{
    public static string? ReadVersion(string? value)
    {
        if (value is not { Length: >= 1 and <= 23 } || !VersionPattern().IsMatch(value)) return null;
        var parts = value.Split('.');
        return parts.Any(part => part != "0") &&
            parts.All(part => ushort.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out _)) ? value : null;
    }

    [GeneratedRegex(@"\A(?:0|[1-9][0-9]{0,4})(?:\.(?:0|[1-9][0-9]{0,4})){0,3}\z", RegexOptions.CultureInvariant)]
    private static partial Regex VersionPattern();
}
