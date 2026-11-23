using System.Text.Json.Serialization;

namespace Control;

internal sealed record ExtensionDeploymentRule(string Id, string Mode,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? UpdateUrl = null);

internal sealed record ExtensionDeployment(string Unlisted, ExtensionDeploymentRule[] Rules)
{
    public static readonly ExtensionDeployment Empty = new("preserve", []);

    public static bool TryNormalize(ExtensionDeployment? input, out ExtensionDeployment? normalized)
    {
        normalized = null;
        if (input is null) return true;
        if (input.Unlisted is not ("preserve" or "block") || input.Rules is not { Length: <= 100 }) return false;

        var rules = new SortedDictionary<string, ExtensionDeploymentRule>(StringComparer.Ordinal);
        foreach (var rule in input.Rules)
        {
            var id = rule?.Id?.Trim();
            if (id is not { Length: 32 } || id.Any(character => character is < 'a' or > 'p') ||
                rule?.Mode is not ("allow" or "block" or "force")) return false;
            var url = rule.UpdateUrl?.Trim();
            if (rule.Mode == "force" ? !ValidUpdateUrl(url) : url is not null) return false;
            if (!rules.TryAdd(id, new(id, rule.Mode, url))) return false;
        }
        if (rules.Values.Sum(rule => rule.UpdateUrl?.Length ?? 0) > 7_000) return false;
        normalized = new(input.Unlisted, rules.Values.ToArray());
        return true;
    }

    private static bool ValidUpdateUrl(string? value)
    {
        if (value is not { Length: > 8 and <= 512 } || !value.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
            value.Any(character => character < '!' || character > '~' || character is '\\' or '?' or '#' or '"' or '<' or '>'))
            return false;
        var authority = value[8..].Split('/', 2)[0];
        return authority.Length > 0 && !authority.Contains('@') && !authority.Contains('%') &&
            Uri.TryCreate(value, UriKind.Absolute, out var url) && url.HostNameType != UriHostNameType.Unknown;
    }
}
