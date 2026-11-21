using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Control;

internal sealed record CustomAppSetting(string? Host, string? Name);
internal sealed record CustomApp(string Id, string Host, string Name);

internal static class CustomApps
{
    private const int Limit = 25;
    private static readonly HashSet<string> BuiltInHosts = new(StringComparer.Ordinal)
        { "chatgpt.com", "claude.ai", "gemini.google.com" };
    private static readonly Regex NameControl = new(@"[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    public static bool IsId(string? value) => value is { Length: 69 } && value.StartsWith("saas:", StringComparison.Ordinal) &&
        value.AsSpan(5).IndexOfAnyExcept("0123456789abcdef") == -1;

    public static bool TryNormalize(CustomAppSetting?[]? input, out CustomApp[]? catalog)
    {
        catalog = null;
        if (input is null) return true;
        if (input.Length > Limit) return false;
        var apps = new SortedDictionary<string, CustomApp>(StringComparer.Ordinal);
        foreach (var entry in input)
        {
            if (entry?.Host?.Trim() is not { } rawHost || DomainRules.NormalizeHostname(rawHost) is not { } host ||
                BuiltInHosts.Contains(host) || entry.Name?.Trim() is not { Length: >= 2 and <= 64 } name ||
                NameControl.IsMatch(name)) return false;
            var id = "saas:" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(host)));
            if (!apps.TryAdd(host, new(id, host, name))) return false;
        }
        catalog = [.. apps.Values];
        return true;
    }
}
