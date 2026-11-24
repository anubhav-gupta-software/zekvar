namespace Control;

internal sealed record FleetBrowser(Guid InstallationId, DateTime EnrolledAt, DateTime LastSeenAt, Guid? GroupId,
    string? GroupName, int AssignmentVersion, bool AssignmentAware, int ExpectedPolicyVersion, string? ExtensionVersion);
internal sealed record FleetCursor(DateTime EnrolledAt, Guid InstallationId);
internal sealed record FleetPage(IReadOnlyList<FleetBrowser> Entries, FleetCursor? Next);

internal sealed record FleetSelection(Guid InstallationId, int AssignmentVersion);
internal sealed record FleetRequest(Guid RequestId, string? Operation, Guid? GroupId, int? ExpectedPolicyVersion, FleetSelection?[]? Selections)
{
    public bool IsValid() => RequestId != Guid.Empty && GroupId != Guid.Empty &&
        (Operation == "assign" && ExpectedPolicyVersion is > 0 || Operation == "revoke" && GroupId is null && ExpectedPolicyVersion is null) &&
        Selections is { Length: >= 1 and <= 25 } &&
        Selections.All(row => row is { AssignmentVersion: >= 0 } && row.InstallationId != Guid.Empty) &&
        Selections.Select(row => row!.InstallationId).Distinct().Count() == Selections.Length;
}
internal sealed record FleetChange(Guid BatchId, string Operation, Guid? GroupId, string? GroupName, int? PolicyVersion,
    int SelectedCount, IReadOnlyList<Guid> ChangedInstallations);
internal sealed record FleetOutcome(FleetChange? Change = null, string? Error = null);
