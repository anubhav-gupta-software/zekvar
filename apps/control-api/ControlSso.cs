using System.Security.Cryptography;

namespace Control;

internal sealed record ControlSso(string Issuer, string OrganizationSlug, string BridgeHash, bool Legacy)
{
    public static IReadOnlyDictionary<string, ControlSso> Read(IConfiguration configuration, bool hosted, DemoOrganization[] organizations)
    {
        var section = configuration.GetSection("Control:Oidc");
        var indexed = configuration.GetSection("Control:OidcOrganizations").GetChildren().ToArray();
        var legacy = !string.IsNullOrEmpty(section["Issuer"]) || !string.IsNullOrEmpty(section["ExchangeToken"]);
        if (legacy && indexed.Length != 0) throw new InvalidOperationException("Choose either legacy OIDC settings or organization OIDC settings.");
        var entries = legacy ? new[] { section } : indexed;
        var settings = new Dictionary<string, ControlSso>(StringComparer.Ordinal);
        var bridgeHashes = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in entries)
        {
            var provider = ReadProvider(entry, hosted, organizations, legacy);
            if (!settings.TryAdd(provider.OrganizationSlug, provider) || !bridgeHashes.Add(provider.BridgeHash))
                throw new InvalidOperationException("Configure one OIDC provider and a distinct exchange token per organization.");
        }
        return settings;
    }

    private static ControlSso ReadProvider(IConfiguration section, bool hosted, DemoOrganization[] organizations, bool legacy)
    {
        var issuer = section["Issuer"];
        var token = section["ExchangeToken"];
        var organization = section["OrganizationSlug"];
        if (!hosted || issuer is not { Length: > 0 and <= 2048 } || issuer != issuer.Trim() ||
            !Uri.TryCreate(issuer, UriKind.Absolute, out var url) || url.Scheme != Uri.UriSchemeHttps ||
            url.Host.Length == 0 || url.UserInfo.Length != 0 || issuer.Contains('?') || issuer.Contains('#') ||
            !Tokens.IsValid(token) || !organizations.Any(org => org.Slug == organization) || organizations.Any(org => org.AdminToken == token))
            throw new InvalidOperationException("Configure a hosted OIDC issuer, organization, and separate exchange token.");
        return new(issuer, organization!, Tokens.Hash(token!), legacy);
    }

    public bool Authorizes(string token) => CryptographicOperations.FixedTimeEquals(
        Convert.FromHexString(BridgeHash), Convert.FromHexString(Tokens.Hash(token)));

    public static bool ValidSubject(string? subject) => subject is { Length: >= 1 and <= 255 } &&
        subject.All(character => character is >= '!' and <= '~');
}

internal sealed record AddSsoIdentity(string? Name, string? Role, string? Subject);
internal sealed record ExchangeSsoIdentity(string? Issuer, string? Subject, DateTimeOffset ExpiresAt, string? OrganizationSlug);
internal sealed record SsoSession(string Token, DateTime ExpiresAt);
