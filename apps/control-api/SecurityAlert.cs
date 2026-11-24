using System.Text.Json.Serialization;

namespace Control;

internal sealed record SecurityAlertSettings(bool Enabled, int Threshold, int Revision)
{
    public static readonly SecurityAlertSettings Default = new(false, 5, 0);
}

internal sealed record SetSecurityAlertSettings(bool? Enabled, int Threshold, int? ExpectedRevision)
{
    public bool IsValid() => Enabled.HasValue && Threshold is >= 2 and <= 100 && ExpectedRevision is >= 0 and < int.MaxValue;
}

internal sealed record SecurityAlert(Guid Id, string AppId, EventRollout Rollout, DateTime WindowStart, DateTime WindowEnd,
    int Threshold, long BlockCount, DateTime TriggeredAt, DateTime? AcknowledgedAt);
internal sealed record SecurityAlertCursor(DateTimeOffset TriggeredAt, Guid Id);
internal sealed record SecurityAlertPage(IReadOnlyList<SecurityAlert> Entries, SecurityAlertCursor? Next);
internal sealed record SecurityAlertDetails(SecurityAlert Alert, EventPage Evidence,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AlertWebhookDelivery? Webhook = null);
internal sealed record ExtensionAccessSettings(bool Enabled, int Revision);
internal sealed record SetExtensionAccessSettings(bool? Enabled, int? ExpectedRevision)
{
    public bool IsValid() => Enabled.HasValue && ExpectedRevision is >= 0 and < int.MaxValue;
}

internal sealed record ExtensionAccessAlert(Guid Id, Guid InstallationId, string? GroupName, int PolicyVersion, int ChangeCount,
    DateTime TriggeredAt, DateTime? AcknowledgedAt);
internal sealed record ExtensionAccessAlertPage(IReadOnlyList<ExtensionAccessAlert> Entries, SecurityAlertCursor? Next);
internal sealed record ExtensionAccessAlertDetail(ExtensionAccessAlert Alert, InventoryExtensionChange[] Changes);

internal sealed record SecurityAlertChange(Guid? AlertId = null, SecurityAlertSettings? Before = null, SecurityAlertSettings? After = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] bool ExtensionAccess = false,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] ExtensionAccessSettings? ExtensionBefore = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] ExtensionAccessSettings? ExtensionAfter = null);
