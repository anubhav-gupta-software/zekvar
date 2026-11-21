using System.Text.RegularExpressions;
using System.Text.Json.Serialization;

namespace Control;

internal sealed record UploadTypes(string[]? Chatgpt = null, string[]? Gemini = null)
{
    private static readonly Regex TypePattern = new(
        @"\A(?:\.[a-z0-9][a-z0-9_-]*(?:\.[a-z0-9][a-z0-9_-]*)*|[a-z0-9][a-z0-9.+_-]*/(?:\*|[a-z0-9][a-z0-9.+_-]*))\z",
        RegexOptions.NonBacktracking);

    public bool HasSettings() => Chatgpt is not null || Gemini is not null;

    public static bool TryNormalize(UploadTypes? input, out UploadTypes? normalized)
    {
        normalized = null;
        if (input is null) return true;
        if ((input.Chatgpt is { } chatgpt && !Valid(chatgpt)) || (input.Gemini is { } gemini && !Valid(gemini)))
            return false;
        normalized = new(Normalize(input.Chatgpt), Normalize(input.Gemini));
        return true;
    }

    private static bool Valid(string[] types) => types.Length <= 25 && types.All(type =>
        type is not null && type.Length <= 64 && TypePattern.IsMatch(type.Trim().ToLowerInvariant()));

    private static string[]? Normalize(string[]? types) =>
        types?.Select(type => type.Trim().ToLowerInvariant()).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
}

internal sealed record UploadFilter(string Mode, string[] Types)
{
    public static UploadFilter? From(string? mode, string[]? types) =>
        mode is "monitor" or "block" && types is { Length: > 0 } ? new(mode, types) : null;
}

internal sealed record TargetedUploads(
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] UploadFilter? Chatgpt,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] UploadFilter? Gemini);
