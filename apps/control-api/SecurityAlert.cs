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
internal sealed record SecurityAlertDetails(SecurityAlert Alert, EventPage Evidence);
internal sealed record SecurityAlertChange(Guid? AlertId = null, SecurityAlertSettings? Before = null, SecurityAlertSettings? After = null);
