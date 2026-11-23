namespace Control;

internal static class AiAppAccess
{
    private static readonly HashSet<string> ComposerHosts = new(StringComparer.Ordinal)
    {
        "chat.openai.com", "chatgpt.com", "claude.ai", "gemini.google.com"
    };

    public static bool TryNormalize(string[]? input, out string[]? hosts)
    {
        hosts = null;
        if (input is null) return true;
        if (input.Length > 50) return false;
        var selected = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var value in input)
            if (value is null || DomainRules.NormalizeHostname(value.Trim()) is not { } host || !selected.Add(host)) return false;
        hosts = [.. selected];
        return true;
    }

    public static bool InCatalog(string[]? hosts, CustomApp[]? apps) => hosts is null ||
        hosts.All(host => ComposerHosts.Contains(host) || DiscoveryCatalog.IsPresetHost(host) || (apps ?? []).Any(app => app.Host == host));
}
