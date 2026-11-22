using System.Text.Json.Serialization;

namespace Control;

internal sealed record RetentionPolicy(
    [property: JsonRequired] int? SecurityEventDays,
    [property: JsonRequired] int? AiObservationDays,
    [property: JsonRequired] int? AuditDays)
{
    public bool IsValid() => ValidDays(SecurityEventDays) && ValidDays(AiObservationDays) && ValidDays(AuditDays);

    private static bool ValidDays(int? days) => days is null or >= 1 and <= 3650;
}

internal sealed record RetentionCleanup(int SecurityEvents, int AiObservations, int AuditEntries, string Source)
{
    public int Count() => SecurityEvents + AiObservations + AuditEntries;
}

internal sealed class RetentionSweep(ControlStore store, ILogger<RetentionSweep> logger, TimeSpan interval) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var schedule = new PeriodicTimer(interval);
        do
        {
            try
            {
                var failed = new HashSet<Guid>();
                bool deleted;
                do
                {
                    deleted = false;
                    foreach (var organizationId in await store.OrganizationsWithExpiredData(stoppingToken))
                    {
                        if (failed.Contains(organizationId)) continue;
                        try
                        {
                            var result = await store.CleanupRetention(organizationId, scheduled: true, stoppingToken);
                            deleted |= result.Count() > 0;
                        }
                        catch (Exception error) when (!stoppingToken.IsCancellationRequested)
                        {
                            failed.Add(organizationId);
                            logger.LogWarning("Control could not clean up one organization's expired records. Error type {ErrorType}.", error.GetType().Name);
                        }
                    }
                } while (deleted);
                await store.ExpireExtensionInventory(stoppingToken);
                await store.ExpireSsoSessions(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception error)
            {
                logger.LogWarning("Control retention sweep failed with {ErrorType}. The next sweep will retry.", error.GetType().Name);
            }
        } while (await schedule.WaitForNextTickAsync(stoppingToken));
    }
}
