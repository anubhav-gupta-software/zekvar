namespace Control;

// Mirrors contracts/policy/health-identifiers.ts. NPI, DEA, and MBI checks need no configuration. Medical record number
// formats reuse the organization identifier prefix-and-digit validation. An empty list leaves that rule inactive.
internal sealed record HealthProtection(string? Mode, IdentifierFormat?[]? RecordFormats)
{
    public static readonly HealthProtection Disabled = new("off", []);

    public static bool TryNormalize(HealthProtection? submitted, out HealthProtection? normalized)
    {
        normalized = null;
        if (submitted is null) return true;
        if (submitted.Mode is not ("off" or "monitor" or "warn" or "block") ||
            !IdentifierFormat.TryNormalize(submitted.RecordFormats, out var formats)) return false;
        normalized = new(submitted.Mode, formats);
        return true;
    }
}
