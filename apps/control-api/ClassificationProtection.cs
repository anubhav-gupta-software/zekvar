using System.Text.RegularExpressions;

namespace Control;

// Mirrors contracts/policy/classification.ts. Browser compiles the stored terms; Control never receives matched text.
internal sealed record ClassificationProtection(string? Mode, string?[]? Terms)
{
    public static readonly ClassificationProtection Disabled = new("off", []);
    private static readonly Regex Allowed = new(@"\A[A-Za-z0-9 \-–—_.&/:']+\z", RegexOptions.NonBacktracking);
    private static readonly Regex Spaces = new(@"[ \t]+", RegexOptions.NonBacktracking);

    public static bool TryNormalize(ClassificationProtection? submitted, out ClassificationProtection? normalized)
    {
        normalized = null;
        if (submitted is null) return true;
        if (submitted.Mode is not ("off" or "monitor" or "warn" or "block") || submitted.Terms is not { Length: <= 16 } terms ||
            (submitted.Mode != "off" && terms.Length == 0)) return false;
        var canonical = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var value in terms)
        {
            if (value is null) return false;
            var term = Spaces.Replace(value.Trim(), " ");
            if (term.Length is < 3 or > 64 || !Allowed.IsMatch(term) || term.Count(char.IsAsciiLetterOrDigit) < 3 ||
                !canonical.TryAdd(term.ToUpperInvariant(), term)) return false;
        }
        normalized = new(submitted.Mode, canonical.Values.ToArray());
        return true;
    }
}
