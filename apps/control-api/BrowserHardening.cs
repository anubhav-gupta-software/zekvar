namespace Control;

internal sealed record BrowserHardening(string SafeBrowsing = "preserve", string Downloads = "preserve",
    bool LockSafeBrowsingWarnings = false, bool DisableGuest = false, bool DisableIncognito = false,
    bool DisablePasswordSaving = false, bool DisableSync = false)
{
    public static readonly BrowserHardening Empty = new();

    public bool IsValid() => SafeBrowsing is "preserve" or "standard" or "enhanced" &&
        Downloads is "preserve" or "malicious" or "dangerous" or "potentially-dangerous" or "all";
}
