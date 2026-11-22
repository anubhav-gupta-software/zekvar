using System.Security.Cryptography;

namespace Control;

internal sealed record ControlSso(string Issuer, string OrganizationSlug, string BridgeHash)
{
    public static ControlSso? Read(IConfiguration configuration, bool hosted, DemoOrganization[] organizations)
    {
        var section = configuration.GetSection("Control:Oidc");
        var issuer = section["Issuer"];
        var token = section["ExchangeToken"];
        var organization = section["OrganizationSlug"];
        if (string.IsNullOrEmpty(issuer) && string.IsNullOrEmpty(token)) return null;
        if (!hosted || issuer is not { Length: > 0 and <= 2048 } || issuer != issuer.Trim() ||
            !Uri.TryCreate(issuer, UriKind.Absolute, out var url) || url.Scheme != Uri.UriSchemeHttps ||
            url.Host.Length == 0 || url.UserInfo.Length != 0 || issuer.Contains('?') || issuer.Contains('#') ||
            !Tokens.IsValid(token) || !organizations.Any(org => org.Slug == organization) || organizations.Any(org => org.AdminToken == token))
            throw new InvalidOperationException("Configure a hosted OIDC issuer, organization, and separate exchange token.");
        return new(issuer, organization!, Tokens.Hash(token!));
    }

    public bool Authorizes(string token) => CryptographicOperations.FixedTimeEquals(
        Convert.FromHexString(BridgeHash), Convert.FromHexString(Tokens.Hash(token)));

    public static bool ValidSubject(string? subject) => subject is { Length: >= 1 and <= 255 } &&
        subject.All(character => character is >= '!' and <= '~');
}

internal sealed record AddSsoIdentity(string? Name, string? Role, string? Subject);
internal sealed record ExchangeSsoIdentity(string? Issuer, string? Subject, DateTimeOffset ExpiresAt);
internal sealed record SsoSession(string Token, DateTime ExpiresAt);
