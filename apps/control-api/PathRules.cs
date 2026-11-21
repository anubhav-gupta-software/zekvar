using System.Text.RegularExpressions;

namespace Control;

internal sealed record PathRules(string[] Allow, string[] Block)
{
    private const int MaxPathLength = 64;
    private static readonly Regex Prefix = new(@"\A(?:/[A-Za-z0-9._~-]+)+\z",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    public static bool TryNormalize(PathRules? source, out PathRules? rules)
    {
        rules = null;
        if (source is null) return true;
        if (source.Allow is null || source.Block is null || source.Allow.Length + (long)source.Block.Length > 50 ||
            !TryNormalizeList(source.Allow, out var allow) || !TryNormalizeList(source.Block, out var block) ||
            allow.Intersect(block, StringComparer.Ordinal).Any()) return false;

        rules = new(allow, block);
        return true;
    }

    private static bool TryNormalizeList(string[] entries, out string[] paths)
    {
        paths = [];
        var normalized = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var entry in entries)
        {
            if (entry is null) return false;
            var value = entry.Trim();
            var slash = value.IndexOf('/');
            if (slash < 1 || DomainRules.NormalizeHostname(value[..slash]) is not { } host) return false;
            var path = value[slash..];
            if (path.EndsWith('/')) path = path[..^1];
            if (path.Length > MaxPathLength || !Prefix.IsMatch(path) ||
                path.Split('/').Any(segment => segment is "." or "..")) return false;
            normalized.Add(host + path);
        }
        paths = [.. normalized];
        return true;
    }
}
