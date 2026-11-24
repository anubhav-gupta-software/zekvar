using System.Text.Json.Serialization;

namespace Control;

internal sealed record PromptAppModes(
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Chatgpt = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Gemini = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Claude = null)
{
    public bool Valid() => (Chatgpt is null || FixtureContract.IsMode(Chatgpt)) &&
        (Gemini is null || FixtureContract.IsMode(Gemini)) && (Claude is null || FixtureContract.IsMode(Claude));

    public string? ForApp(string app) => app switch
    {
        FixtureContract.ChatGpt => Chatgpt,
        FixtureContract.Gemini => Gemini,
        FixtureContract.Claude => Claude,
        _ => null
    };
}
