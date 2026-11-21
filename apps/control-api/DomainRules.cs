using System.Text.RegularExpressions;

namespace Control;

internal sealed record DomainRules(string[] Allow, string[] Block)
{
    private static readonly Regex Hostname = new(
        @"\A(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\z",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    public static bool TryNormalize(DomainRules? source, out DomainRules? rules)
    {
        rules = null;
        if (source is null) return true;
        if (source.Allow is null || source.Block is null || source.Allow.Length + (long)source.Block.Length > 50 ||
            !TryNormalizeList(source.Allow, out var allow) || !TryNormalizeList(source.Block, out var block) ||
            allow.Intersect(block, StringComparer.Ordinal).Any()) return false;

        rules = new(allow, block);
        return true;
    }

    private static bool TryNormalizeList(string[] entries, out string[] domains)
    {
        domains = [];
        var normalized = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var entry in entries)
        {
            if (entry is null) return false;
            if (NormalizeHostname(entry.Trim()) is not { } domain) return false;
            normalized.Add(domain);
        }
        domains = [.. normalized];
        return true;
    }

    public static string? NormalizeHostname(string domain)
    {
        if (domain.EndsWith('.')) domain = domain[..^1];
        return domain.Length <= 253 && Hostname.IsMatch(domain) ? domain.ToLowerInvariant() : null;
    }
}
