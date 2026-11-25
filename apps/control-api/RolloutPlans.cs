using System.Text.Json.Serialization;

namespace Control;

internal sealed record RolloutStageRequest([property: JsonRequired] Guid? GroupId, int MinSoakSeconds, int MinAcknowledgedPercent,
    string[]? RequireComposerReady = null, int? MaxBlockEvents = null, int? MaxWarnOverridePercent = null);
internal sealed record CreateRolloutPlan(Guid RequestId, string? Name, int SourceVersion, RolloutStageRequest[]? Stages)
{
    public const int MaxStages = 5;

    public bool IsValid(out string? name)
    {
        name = Name?.Trim();
        if (RequestId == Guid.Empty || name is not { Length: >= 2 and <= 64 } || name.Any(char.IsControl) || SourceVersion < 1 ||
            Stages is not { Length: >= 1 and <= MaxStages } stages) return false;
        var scopes = stages.Select(stage => stage?.GroupId).ToArray();
        if (stages.Any(stage => stage is null) || scopes.Distinct().Count() != scopes.Length || scopes.Any(scope => scope == Guid.Empty) ||
            scopes.Take(scopes.Length - 1).Any(scope => scope is null)) return false;
        return stages.All(stage => stage.MinSoakSeconds is >= 0 and <= 604_800 && stage.MinAcknowledgedPercent is >= 0 and <= 100 &&
            stage.MaxBlockEvents is null or >= 0 and <= 100_000 && stage.MaxWarnOverridePercent is null or >= 0 and <= 100 &&
            (stage.RequireComposerReady is null || (stage.RequireComposerReady.Length <= DiscoveryCatalog.ComposerAppIds.Length &&
                stage.RequireComposerReady.Distinct(StringComparer.Ordinal).Count() == stage.RequireComposerReady.Length &&
                stage.RequireComposerReady.All(app => DiscoveryCatalog.ComposerAppIds.Contains(app)))));
    }
}

internal sealed record RolloutAcknowledgmentGate(long Active, long Acknowledged, int Threshold, bool Passed);
internal sealed record RolloutComposerGate(string AppId, long Active, long Detected, long Unsupported, bool Passed);
internal sealed record RolloutBlockGate(long Blocks, int? Threshold, bool Passed);
internal sealed record RolloutOverrideGate(long Warnings, long Overrides, int? Threshold, bool Passed);
internal sealed record RolloutGate(DateTime EvaluatedAt, int Stage, int PolicyVersion, int CurrentVersion, DateTime SoakEndsAt, bool Soaked,
    RolloutAcknowledgmentGate Acknowledgment, IReadOnlyList<RolloutComposerGate> Composers, RolloutBlockGate Blocks,
    RolloutOverrideGate Overrides, bool Passed, string? Failure);

internal sealed record RolloutStage(int Position, Guid? GroupId, string? GroupName, int MinSoakSeconds, int MinAcknowledgedPercent,
    string[] RequireComposerReady, int? MaxBlockEvents, int? MaxWarnOverridePercent, int? PriorVersion, int? PublishedVersion,
    DateTime? PublishedAt, int? RollbackVersion, string? RollbackOutcome, string State);
internal sealed record RolloutPlan(Guid Id, string Name, int SourceVersion, string Status, int CurrentStage, int Revision, bool RequiresReview,
    AccessIdentity? Creator, AccessIdentity? Approver, DateTime CreatedAt, DateTime ExpiresAt, DateTime? DecidedAt, DateTime? EvaluatedAt,
    DateTime? NextEvaluationAt, string? PauseReason, RolloutGate? Gate, DateTime? FinishedAt, IReadOnlyList<RolloutStage> Stages);

// Lifecycle and stage publications both carry this record in audit history.
internal sealed record RolloutAudit(Guid PlanId, string PlanName, string Event,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? Stage = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] Guid? GroupId = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? GroupName = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? PolicyVersion = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Reason = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] bool? Automatic = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AccessIdentity? Approver = null);

internal sealed record RolloutResult(RolloutPlan? Plan = null, string? Error = null);

internal sealed class RolloutAdvancer(ControlStore store, ILogger<RolloutAdvancer> logger, TimeSpan interval) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var schedule = new PeriodicTimer(interval);
        do
        {
            try
            {
                foreach (var (organizationId, planId) in await store.RunningRolloutPlans(stoppingToken))
                {
                    try
                    {
                        await store.EvaluateRolloutPlan(organizationId, planId, stoppingToken);
                    }
                    catch (Exception error) when (!stoppingToken.IsCancellationRequested)
                    {
                        logger.LogWarning("Control could not evaluate one rollout plan. Error type {ErrorType}.", error.GetType().Name);
                    }
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception error)
            {
                logger.LogWarning("Control rollout evaluation failed with {ErrorType}. The next pass will retry.", error.GetType().Name);
            }
        } while (await schedule.WaitForNextTickAsync(stoppingToken));
    }
}
