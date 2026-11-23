using System.Text.RegularExpressions;

namespace Control;

internal sealed record IdentifierFormat(string? Prefix, int Digits);

internal sealed record IdentifierProtection(string? Mode, IdentifierFormat?[]? Formats)
{
    public static readonly IdentifierProtection Disabled = new("off", []);
    private static readonly Regex PrefixPattern = new(@"\A[A-Za-z][A-Za-z0-9]{1,14}[-_]\z", RegexOptions.NonBacktracking);

    public static bool TryNormalize(IdentifierProtection? submitted, out IdentifierProtection? normalized)
    {
        normalized = null;
        if (submitted is null) return true;
        if (submitted.Mode is not ("off" or "monitor" or "warn" or "block") || submitted.Formats is not { Length: <= 16 } formats ||
            (submitted.Mode != "off" && formats.Length == 0)) return false;
        var canonical = new SortedDictionary<string, IdentifierFormat>(StringComparer.Ordinal);
        foreach (var format in formats)
        {
            if (format?.Prefix?.Trim() is not { Length: >= 3 and <= 16 } prefix || !PrefixPattern.IsMatch(prefix) ||
                format.Digits is < 4 or > 12) return false;
            prefix = prefix.ToUpperInvariant();
            if (!canonical.TryAdd(prefix, new(prefix, format.Digits))) return false;
        }
        normalized = new(submitted.Mode, canonical.Values.ToArray());
        return true;
    }
}
