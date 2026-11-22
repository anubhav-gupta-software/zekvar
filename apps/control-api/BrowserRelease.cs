using System.Globalization;
using System.Text.RegularExpressions;

namespace Control;

internal sealed record BrowserReleaseCount(string Kind, string? ExtensionVersion, long Installations, long RecentReports);

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
