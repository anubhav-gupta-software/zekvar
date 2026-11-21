namespace Control;

internal static class AccessRoles
{
    public const string Owner = "owner";
    public const string Administrator = "administrator";
    public const string Auditor = "auditor";

    public static bool IsDelegated(string? role) => role is Administrator or Auditor;
}

internal sealed record IssueControlAccess(string? Name, string? Role, int Hours);
internal sealed record AccessIdentity(Guid Id, string Name, string Role);
internal sealed record ControlAccess(Guid Id, string Name, string Role, DateTime IssuedAt, DateTime ExpiresAt, string Status);
internal sealed record IssuedControlAccess(ControlAccess Access, string Token);
