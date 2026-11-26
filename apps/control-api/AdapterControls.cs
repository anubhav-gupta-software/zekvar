using System.Text.Json.Serialization;

namespace Control;

// An administrator switch that stops Browser from intercepting one AI app adapter, or only its attachment intake.
// "open" leaves the app usable without that protection. "closed" also blocks the app's hosts through AI app access.
internal sealed record AdapterControl(string? Scope = null, string? Fallback = null)
{
    public const string Adapter = "adapter";
    public const string Attachments = "attachments";
    public const string FailClosed = "closed";

    public bool Valid() => Scope is Adapter or Attachments && Fallback is "open" or FailClosed;
}

internal sealed record AdapterControls(
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AdapterControl? Chatgpt = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AdapterControl? Gemini = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AdapterControl? Claude = null)
{
    private static readonly Dictionary<string, string[]> Hosts = new(StringComparer.Ordinal)
    {
        [FixtureContract.ChatGpt] = ["chat.openai.com", "chatgpt.com"],
        [FixtureContract.Claude] = ["claude.ai"],
        [FixtureContract.Gemini] = ["gemini.google.com"],
    };

    public bool Valid() => Chatgpt?.Valid() != false && Gemini?.Valid() != false && Claude?.Valid() != false;

    public AdapterControl? ForApp(string app) => app switch
    {
        FixtureContract.ChatGpt => Chatgpt,
        FixtureContract.Gemini => Gemini,
        FixtureContract.Claude => Claude,
        _ => null
    };

    public string[] FailClosedHosts() => Hosts.Where(entry => ForApp(entry.Key)?.Fallback == AdapterControl.FailClosed)
        .SelectMany(entry => entry.Value).ToArray();

    // Fail-closed apps reuse the AI app access host block, so every Browser that supports access blocks enforces them.
    public static string[] EffectiveBlockedHosts(string[]? explicitHosts, AdapterControls? controls) =>
        [.. new SortedSet<string>([.. explicitHosts ?? [], .. controls?.FailClosedHosts() ?? []], StringComparer.Ordinal)];
}
