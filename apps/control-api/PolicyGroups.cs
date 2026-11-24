using System.Text.Json.Serialization;

namespace Control;

internal sealed record CreatePolicyGroup(string Name);
internal sealed record AssignPolicyGroup([property: JsonRequired] Guid? GroupId);
internal sealed record PromotePolicyGroup(int ExpectedVersion, int? ExpectedBaselineVersion = null);
internal sealed record PolicyGroup(Guid Id, string Name, int EffectiveVersion, int? PublishedVersion, long Browsers, int BaselineVersion);
internal sealed record PolicyGroupChange(Guid? GroupId, string? GroupName, Guid? InstallationId, int? SourceVersion);
