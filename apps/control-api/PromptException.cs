using System.Text.RegularExpressions;

namespace Control;

internal sealed record PromptException(string AppId, string RuleId, DateTimeOffset ExpiresAt, string Reason)
{
    private static readonly Regex Controls = new(@"[\u0000-\u001f\u007f-\u009f]", RegexOptions.NonBacktracking);

    public static bool TryNormalize(PromptException?[]? submitted, DateTimeOffset now, out PromptException[]? normalized)
    {
        normalized = null;
        if (submitted is null) return true;
        if (submitted.Length > 15) return false;
        var entries = new Dictionary<(string, string), PromptException>();
        foreach (var entry in submitted)
        {
            if (entry is null || !FixtureContract.IsAiPromptApp(entry.AppId) ||
                !FixtureContract.IsPromptRule(entry.RuleId) ||
                entry.ExpiresAt == default || entry.ExpiresAt > now.AddHours(24) ||
                entry.Reason?.Trim() is not { Length: >= 3 and <= 120 } reason || Controls.IsMatch(reason)) return false;
            var value = entry with { Reason = reason, ExpiresAt = entry.ExpiresAt.ToUniversalTime() };
            if (!entries.TryAdd((value.AppId, value.RuleId), value)) return false;
        }
        normalized = entries.Values.OrderBy(entry => entry.AppId, StringComparer.Ordinal)
            .ThenBy(entry => entry.RuleId, StringComparer.Ordinal).ToArray();
        return true;
    }

    public static bool IntroducesExpired(PromptException[]? candidate, PromptException[]? previous) =>
        candidate?.Any(entry => entry.ExpiresAt <= DateTimeOffset.UtcNow && !(previous?.Contains(entry) ?? false)) == true;
}

internal sealed record PromptExceptionGrant(string AppId, string RuleId, long ExpiresAtMs);
internal sealed record PromptExceptionLease(long ServerTimeMs, PromptExceptionGrant[] Grants);
