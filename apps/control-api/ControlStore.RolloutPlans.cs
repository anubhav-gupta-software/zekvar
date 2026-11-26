using System.Text.Json;
using Npgsql;

namespace Control;

internal sealed partial class ControlStore
{
    public TimeSpan RolloutInterval { get; init; } = TimeSpan.FromSeconds(30);

    private sealed record LockedRollout(Guid Id, string Name, int SourceVersion, string Status, int CurrentStage, int StageCount,
        bool RequiresReview, Guid? CreatedBy, AccessIdentity? Approver, string Slug, IReadOnlyList<RolloutStage> Stages);

    public async Task<RolloutResult> CreateRolloutPlan(RequestIdentity identity, CreateRolloutPlan request, string name, CancellationToken ct)
    {
        var org = identity.OrganizationId;
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        var required = await LockPolicySettings(transaction, org, ct);
        if (required && !await NamedAdministrator(transaction, identity, ct)) return new(Error: "named_administrator_required");
        var stages = request.Stages!;
        var groups = stages.Where(stage => stage.GroupId.HasValue).Select(stage => stage.GroupId!.Value).ToArray();
        await using (var check = new NpgsqlCommand("""
            SELECT EXISTS (SELECT FROM policy_versions WHERE organization_id = $1 AND version = $2),
                (SELECT count(*) FROM policy_groups WHERE organization_id = $1 AND id = ANY($3)),
                EXISTS (SELECT FROM rollout_plans p JOIN rollout_stages s ON s.organization_id = p.organization_id AND s.plan_id = p.id
                    WHERE p.organization_id = $1 AND (p.status IN ('running', 'paused') OR (p.status = 'pending_review' AND p.expires_at > clock_timestamp()))
                        AND (s.group_id = ANY($3) OR (s.group_id IS NULL AND $4))),
                EXISTS (SELECT FROM rollout_plans WHERE organization_id = $1 AND id = $5)
            """, connection, transaction))
        {
            AddParameters(check, org, request.SourceVersion, groups, stages.Any(stage => stage.GroupId is null), request.RequestId);
            await using var rows = await check.ExecuteReaderAsync(ct);
            await rows.ReadAsync(ct);
            if (!rows.GetBoolean(0)) return new(Error: "rollout_source_unavailable");
            if (rows.GetInt64(1) != groups.Length) return new(Error: "rollout_group_unavailable");
            if (rows.GetBoolean(3)) return new(Error: "rollout_plan_exists");
            if (rows.GetBoolean(2)) return new(Error: "rollout_scope_busy");
        }

        var creator = identity.Access?.Id;
        await using (var insert = new NpgsqlCommand("""
            INSERT INTO rollout_plans (organization_id, id, name, source_version, status, stage_count, requires_review, created_by,
                approved_by, decided_at)
            VALUES ($1, $2, $3, $4, CASE WHEN $5 THEN 'pending_review' ELSE 'running' END, $6, $5, $7::uuid, CASE WHEN $5 THEN NULL ELSE $7::uuid END,
                CASE WHEN $5 THEN NULL ELSE now() END)
            """, connection, transaction))
        {
            AddParameters(insert, org, request.RequestId, name, request.SourceVersion, required, stages.Length, (object?)creator ?? DBNull.Value);
            await insert.ExecuteNonQueryAsync(ct);
        }
        for (var position = 0; position < stages.Length; position++)
        {
            var stage = stages[position];
            await using var insert = new NpgsqlCommand("""
                INSERT INTO rollout_stages (organization_id, plan_id, position, group_id, min_soak_seconds, min_acknowledged_percent,
                    require_composer_ready, max_block_events, max_warn_override_percent)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                """, connection, transaction);
            AddParameters(insert, org, request.RequestId, position, (object?)stage.GroupId ?? DBNull.Value, stage.MinSoakSeconds,
                stage.MinAcknowledgedPercent, stage.RequireComposerReady ?? [], (object?)stage.MaxBlockEvents ?? DBNull.Value,
                (object?)stage.MaxWarnOverridePercent ?? DBNull.Value);
            await insert.ExecuteNonQueryAsync(ct);
        }
        await AuditRollout(transaction, org, creator, new(request.RequestId, name, required ? "requested" : "started"), ct);
        if (!required)
        {
            var plan = (await LockRollout(transaction, org, request.RequestId, ct))!;
            await PublishRolloutStage(transaction, identity, plan, 0, automatic: false, ct);
        }
        await transaction.CommitAsync(ct);
        return new(await ReadRolloutPlan(org, request.RequestId, ct));
    }

    public async Task<RolloutResult> DecideRolloutPlan(RequestIdentity identity, Guid id, bool approve, CancellationToken ct)
    {
        if (identity.Access is not { Role: AccessRoles.Administrator } reviewer) return new(Error: "named_administrator_required");
        var org = identity.OrganizationId;
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        if (!await LockPolicySettings(transaction, org, ct)) return new(Error: "review_mode_changed");
        var plan = await LockRollout(transaction, org, id, ct);
        if (plan is null) return new(Error: "rollout_plan_unavailable");
        if (plan.Status != "pending_review") return new(Error: "rollout_plan_state");
        var creator = await ReadAccessIdentity(transaction, org, plan.CreatedBy!.Value, ct);
        var own = reviewer.Id == plan.CreatedBy;
        if (approve && (own || StringComparer.OrdinalIgnoreCase.Equals(reviewer.Name, creator?.Name))) return new(Error: "self_approval");
        if (!await ActiveAdministrator(transaction, identity, reviewer.Id, ct)) return new(Error: "named_administrator_required");

        var status = !approve ? (own ? "withdrawn" : "rejected")
            : await ActiveAdministrator(transaction, identity, plan.CreatedBy!.Value, ct) ? "running" : "cancelled";
        await using (var update = new NpgsqlCommand("""
            UPDATE rollout_plans SET status = $3, decided_at = now(), approved_by = CASE WHEN $3 = 'running' THEN $4 END,
                finished_at = CASE WHEN $3 = 'running' THEN NULL ELSE now() END, revision = revision + 1
            WHERE organization_id = $1 AND id = $2 AND status = 'pending_review' AND expires_at > clock_timestamp()
            """, connection, transaction))
        {
            AddParameters(update, org, id, status, reviewer.Id);
            if (await update.ExecuteNonQueryAsync(ct) != 1) return new(Error: "rollout_plan_state");
        }
        await AuditRollout(transaction, org, reviewer.Id, new(id, plan.Name, status switch
        {
            "running" => "approved", "cancelled" => "cancelled", _ => status
        }, Reason: status == "cancelled" ? "requester_inactive" : null), ct);
        if (status == "running")
        {
            plan = (await LockRollout(transaction, org, id, ct))!;
            await PublishRolloutStage(transaction, identity, plan, 0, automatic: false, ct);
        }
        await transaction.CommitAsync(ct);
        return status == "cancelled" ? new(Error: "rollout_plan_stale") : new(await ReadRolloutPlan(org, id, ct));
    }

    public async Task<RolloutResult> ChangeRolloutPlan(RequestIdentity identity, Guid id, string operation, CancellationToken ct)
    {
        var org = identity.OrganizationId;
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        var required = await LockPolicySettings(transaction, org, ct);
        var plan = await LockRollout(transaction, org, id, ct);
        if (plan is null) return new(Error: "rollout_plan_unavailable");
        // Pausing and cancelling stop automation, so any writer may use them. Resuming and rolling back change policy.
        if (operation is "resume" or "rollback" && required && !await NamedAdministrator(transaction, identity, ct))
            return new(Error: "named_administrator_required");
        var actor = identity.Access?.Id;
        switch (operation)
        {
            case "pause":
                if (plan.Status != "running") return new(Error: "rollout_plan_state");
                await SetRolloutStatus(transaction, org, id, "paused", "paused_by_administrator", ct);
                await AuditRollout(transaction, org, actor, new(id, plan.Name, "paused", plan.CurrentStage, Reason: "paused_by_administrator"), ct);
                break;
            case "resume":
                if (plan.Status != "paused") return new(Error: "rollout_plan_state");
                if (required && !plan.RequiresReview) return new(Error: "review_mode_changed");
                if (plan.RequiresReview && (plan.Approver is null ||
                    !await ActiveAdministrator(transaction, identity with { Access = plan.Approver }, plan.Approver.Id, ct)))
                    return new(Error: "rollout_approver_inactive");
                await SetRolloutStatus(transaction, org, id, "running", null, ct);
                await AuditRollout(transaction, org, actor, new(id, plan.Name, "resumed", plan.CurrentStage), ct);
                break;
            case "cancel":
                if (plan.Status is not ("pending_review" or "running" or "paused")) return new(Error: "rollout_plan_state");
                await SetRolloutStatus(transaction, org, id,
                    plan.Status == "pending_review" && actor is not null && actor == plan.CreatedBy ? "withdrawn" : "cancelled", null, ct);
                await AuditRollout(transaction, org, actor, new(id, plan.Name, "cancelled", plan.CurrentStage), ct);
                break;
            case "rollback":
                if (plan.Status is not ("running" or "paused" or "completed")) return new(Error: "rollout_plan_state");
                foreach (var stage in plan.Stages.Where(stage => stage.PublishedVersion.HasValue && stage.RollbackOutcome is null).Reverse())
                    await RestoreRolloutStage(transaction, identity, plan, stage, ct);
                await SetRolloutStatus(transaction, org, id, "rolled_back", null, ct);
                await AuditRollout(transaction, org, actor, new(id, plan.Name, "rolled_back", plan.CurrentStage), ct);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(operation));
        }
        await transaction.CommitAsync(ct);
        if (operation == "resume") await EvaluateRolloutPlan(org, id, ct);
        return new(await ReadRolloutPlan(org, id, ct));
    }

    public async Task<IReadOnlyList<(Guid OrganizationId, Guid PlanId)>> RunningRolloutPlans(CancellationToken ct)
    {
        await using var command = Command("""
            SELECT organization_id, id FROM rollout_plans WHERE status = 'running' ORDER BY evaluated_at NULLS FIRST LIMIT 500
            """);
        var plans = new List<(Guid, Guid)>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct)) plans.Add((rows.GetGuid(0), rows.GetGuid(1)));
        return plans;
    }

    // Every transition locks the organization's policy settings and then the plan, and rechecks state under the lock,
    // so concurrent evaluators on any API instance serialize and the later one sees the committed transition.
    // Reads pass skipIfBusy: when either lock stays held past ReadLockTimeout (another evaluator, the background service,
    // or a publish), the read rolls back without changes and returns the last committed state. The holder or the next
    // background pass performs the evaluation, so exactly-once transitions are unchanged.
    public async Task EvaluateRolloutPlan(Guid org, Guid id, CancellationToken ct, bool skipIfBusy = false)
    {
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        bool required;
        LockedRollout? plan;
        try
        {
            var configured = skipIfBusy ? await SetLockTimeout(transaction, $"{(int)ReadLockTimeout.TotalMilliseconds}ms", ct) : null;
            required = await LockPolicySettings(transaction, org, ct);
            plan = await LockRollout(transaction, org, id, ct);
            // Once both locks are held, the evaluation waits for any further locks exactly like the background service.
            if (configured is not null) await SetLockTimeout(transaction, configured, ct);
        }
        catch (PostgresException error) when (skipIfBusy && error.SqlState == PostgresErrorCodes.LockNotAvailable)
        {
            return;
        }
        if (plan is not { Status: "running" }) return;
        var stage = plan.Stages[plan.CurrentStage];
        var gate = await EvaluateRolloutGate(transaction, org, stage, ct);
        string? pause = gate.Failure is "block_events_exceeded" or "warn_override_rate_exceeded" or "target_changed" ? gate.Failure : null;
        var advance = false;
        if (pause is null && gate.Soaked)
        {
            if (!gate.Passed) pause = gate.Failure;
            else if (plan.CurrentStage + 1 < plan.StageCount)
            {
                if (required && !plan.RequiresReview) pause = "review_mode_changed";
                else if (plan.RequiresReview && !await ActiveAdministrator(transaction,
                    new(org, null, plan.Slug, plan.Approver), plan.Approver!.Id, ct)) pause = "approver_inactive";
                else advance = true;
            }
        }

        await using (var record = new NpgsqlCommand("UPDATE rollout_plans SET gate = $3::jsonb, evaluated_at = now() WHERE organization_id = $1 AND id = $2",
            connection, transaction))
        {
            AddParameters(record, org, id, JsonSerializer.Serialize(gate, JsonSerializerOptions.Web));
            await record.ExecuteNonQueryAsync(ct);
        }
        if (pause is not null)
        {
            await SetRolloutStatus(transaction, org, id, "paused", pause, ct);
            await AuditRollout(transaction, org, plan.Approver?.Id,
                new(id, plan.Name, "paused", plan.CurrentStage, Reason: pause, Automatic: true), ct);
        }
        else if (advance)
        {
            await PublishRolloutStage(transaction, new(org, null, plan.Slug, plan.Approver), plan, plan.CurrentStage + 1, automatic: true, ct);
        }
        else if (gate.Soaked && gate.Passed)
        {
            await SetRolloutStatus(transaction, org, id, "completed", null, ct);
            await AuditRollout(transaction, org, plan.Approver?.Id, new(id, plan.Name, "completed", plan.CurrentStage, Automatic: true), ct);
        }
        await transaction.CommitAsync(ct);
    }

    public async Task<IReadOnlyList<RolloutPlan>> RolloutPlans(Guid org, CancellationToken ct)
    {
        foreach (var (organizationId, planId) in await RunningRolloutPlans(org, ct))
            await EvaluateRolloutPlan(organizationId, planId, ct, skipIfBusy: true);
        return await ReadRolloutPlans(org, null, ct);
    }

    public async Task<RolloutPlan?> RolloutPlanDetails(Guid org, Guid id, CancellationToken ct)
    {
        await EvaluateRolloutPlan(org, id, ct, skipIfBusy: true);
        return await ReadRolloutPlan(org, id, ct);
    }

    private static readonly TimeSpan ReadLockTimeout = TimeSpan.FromMilliseconds(250);

    // A transaction-local setting ends with the transaction, so the pooled connection keeps its configured value afterwards.
    // Returns the value that applied before the change.
    private static async Task<string> SetLockTimeout(NpgsqlTransaction transaction, string timeout, CancellationToken ct)
    {
        string previous;
        await using (var read = new NpgsqlCommand("SELECT current_setting('lock_timeout')", transaction.Connection, transaction))
            previous = (string)(await read.ExecuteScalarAsync(ct))!;
        await using var command = new NpgsqlCommand("SELECT set_config('lock_timeout', $1, true)", transaction.Connection, transaction);
        AddParameters(command, timeout);
        await command.ExecuteNonQueryAsync(ct);
        return previous;
    }

    private async Task<IReadOnlyList<(Guid, Guid)>> RunningRolloutPlans(Guid org, CancellationToken ct)
    {
        await using var command = Command("SELECT organization_id, id FROM rollout_plans WHERE organization_id = $1 AND status = 'running'", org);
        var plans = new List<(Guid, Guid)>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct)) plans.Add((rows.GetGuid(0), rows.GetGuid(1)));
        return plans;
    }

    private async Task<RolloutGate> EvaluateRolloutGate(NpgsqlTransaction transaction, Guid org, RolloutStage stage, CancellationToken ct)
    {
        await using var clock = BrowserRead(transaction, "SELECT statement_timestamp()");
        var now = (DateTime)(await clock.ExecuteScalarAsync(ct))!;
        var version = stage.PublishedVersion!.Value;
        var current = (await ReadPolicyScope(transaction, org, stage.GroupId, ct))!.Version;
        var (readiness, _) = await BrowserComposerReadiness(org, new(stage.GroupId.HasValue, stage.GroupId, null), [], transaction, ct,
            baselineImpact: stage.GroupId is null, evaluatedAt: new DateTimeOffset(now));
        var active = readiness.ActiveInstallations;
        var acknowledged = active - readiness.Apps.First(app => app.AppId == FixtureContract.ChatGpt).Counts["policy_pending"];
        var acknowledgment = new RolloutAcknowledgmentGate(active, acknowledged, stage.MinAcknowledgedPercent,
            stage.MinAcknowledgedPercent == 0 || (active > 0 && acknowledged * 100 >= (long)stage.MinAcknowledgedPercent * active));
        var composers = stage.RequireComposerReady.Select(appId => readiness.Apps.First(app => app.AppId == appId)).Select(app =>
            new RolloutComposerGate(app.AppId, active, app.Counts["detected"], app.Counts["unsupported"], ComposerGatePassed(app, active)))
            .ToArray();

        await using var events = BrowserRead(transaction, """
            SELECT count(*) FILTER (WHERE decision = 'block'), count(*) FILTER (WHERE decision = 'warn'),
                count(*) FILTER (WHERE decision = 'warn_override')
            FROM security_events WHERE organization_id = $1 AND policy_version = $2 AND received_at >= $3
            """, org, version, stage.PublishedAt!.Value);
        long blocks, warnings, overrides;
        await using (var rows = await events.ExecuteReaderAsync(ct))
        {
            await rows.ReadAsync(ct);
            (blocks, warnings, overrides) = (rows.GetInt64(0), rows.GetInt64(1), rows.GetInt64(2));
        }
        var blockGate = new RolloutBlockGate(blocks, stage.MaxBlockEvents, stage.MaxBlockEvents is not { } maxBlocks || blocks <= maxBlocks);
        var denominator = Math.Max(warnings, overrides);
        var overrideGate = new RolloutOverrideGate(warnings, overrides, stage.MaxWarnOverridePercent,
            stage.MaxWarnOverridePercent is not { } maxRate || denominator == 0 || overrides * 100 <= maxRate * denominator);

        var soakEnds = stage.PublishedAt.Value.AddSeconds(stage.MinSoakSeconds);
        var failure = current != version ? "target_changed"
            : !blockGate.Passed ? "block_events_exceeded"
            : !overrideGate.Passed ? "warn_override_rate_exceeded"
            : !acknowledgment.Passed ? (active == 0 ? "no_active_browsers" : "acknowledgment_below_threshold")
            : composers.Any(gate => !gate.Passed) ? (active == 0 ? "no_active_browsers" : "composer_readiness_incomplete")
            : null;
        return new(now, stage.Position, version, current, soakEnds, now >= soakEnds, acknowledgment, composers, blockGate, overrideGate,
            failure is null, failure);
    }

    private static async Task PublishRolloutStage(NpgsqlTransaction transaction, RequestIdentity identity, LockedRollout plan, int position,
        bool automatic, CancellationToken ct)
    {
        var org = identity.OrganizationId;
        var stage = plan.Stages[position];
        var target = (await ReadPolicyScope(transaction, org, stage.GroupId, ct))!;
        var before = (await ReadPolicySnapshot(transaction, org, target.Version, ct))!;
        if (stage.GroupId.HasValue && !target.Published) before = before with { PromptExceptions = [] };
        // Like a template application, the reviewed snapshot keeps the destination's own temporary exceptions.
        var candidate = (await ReadPolicySnapshot(transaction, org, plan.SourceVersion, ct))! with { PromptExceptions = before.PromptExceptions };
        var published = await WritePolicy(transaction, identity, candidate, stage.GroupId, null,
            stage.GroupId is { } groupId ? new PolicyGroupChange(groupId, target.Name, null, null) : null, ct, null,
            new RolloutAudit(plan.Id, plan.Name, "stage_published", position, stage.GroupId, stage.GroupName, Automatic: automatic,
                Approver: plan.Approver));
        await using var update = new NpgsqlCommand("""
            WITH stage AS (
                UPDATE rollout_stages SET prior_version = $4, published_version = $5, published_at = now()
                WHERE organization_id = $1 AND plan_id = $2 AND position = $3 AND published_version IS NULL RETURNING position
            )
            UPDATE rollout_plans p SET current_stage = s.position, revision = revision + 1, evaluated_at = NULL, gate = NULL
            FROM stage s WHERE p.organization_id = $1 AND p.id = $2
            """, transaction.Connection, transaction);
        AddParameters(update, org, plan.Id, position, target.Version, published.Version);
        if (await update.ExecuteNonQueryAsync(ct) != 1) throw new InvalidOperationException("The rollout stage was already published.");
    }

    private static async Task RestoreRolloutStage(NpgsqlTransaction transaction, RequestIdentity identity, LockedRollout plan, RolloutStage stage,
        CancellationToken ct)
    {
        var org = identity.OrganizationId;
        var current = (await ReadPolicyScope(transaction, org, stage.GroupId, ct))!;
        int? restored = null;
        if (current.Version == stage.PublishedVersion)
        {
            var now = (await ReadPolicySnapshot(transaction, org, current.Version, ct))!;
            var candidate = (await ReadPolicySnapshot(transaction, org, stage.PriorVersion!.Value, ct))! with { PromptExceptions = now.PromptExceptions };
            restored = (await WritePolicy(transaction, identity, candidate, stage.GroupId, stage.PriorVersion,
                stage.GroupId is { } groupId ? new PolicyGroupChange(groupId, current.Name, null, null) : null, ct, null,
                new RolloutAudit(plan.Id, plan.Name, "stage_restored", stage.Position, stage.GroupId, stage.GroupName, Automatic: false))).Version;
        }
        await using var update = new NpgsqlCommand("""
            UPDATE rollout_stages SET rollback_version = $4, rollback_outcome = CASE WHEN $4::integer IS NULL THEN 'changed' ELSE 'restored' END
            WHERE organization_id = $1 AND plan_id = $2 AND position = $3 AND rollback_outcome IS NULL
            """, transaction.Connection, transaction);
        AddParameters(update, org, plan.Id, stage.Position, (object?)restored ?? DBNull.Value);
        await update.ExecuteNonQueryAsync(ct);
    }

    private static async Task SetRolloutStatus(NpgsqlTransaction transaction, Guid org, Guid id, string status, string? reason, CancellationToken ct)
    {
        await using var update = new NpgsqlCommand("""
            UPDATE rollout_plans SET status = $3, pause_reason = $4, revision = revision + 1,
                decided_at = COALESCE(decided_at, now()),
                evaluated_at = CASE WHEN $3 = 'running' THEN NULL ELSE evaluated_at END,
                finished_at = CASE WHEN $3 IN ('running', 'paused') THEN NULL ELSE now() END
            WHERE organization_id = $1 AND id = $2
            """, transaction.Connection, transaction);
        AddParameters(update, org, id, status, (object?)reason ?? DBNull.Value);
        await update.ExecuteNonQueryAsync(ct);
    }

    private static async Task AuditRollout(NpgsqlTransaction transaction, Guid org, Guid? actor, RolloutAudit details, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            INSERT INTO control_audit (organization_id, action, actor_access_id, rollout_change) VALUES ($1, 'rollout_plan_changed', $2, $3::jsonb)
            """, transaction.Connection, transaction);
        AddParameters(command, org, (object?)actor ?? DBNull.Value, JsonSerializer.Serialize(details, JsonSerializerOptions.Web));
        await command.ExecuteNonQueryAsync(ct);
    }

    private async Task<bool> NamedAdministrator(NpgsqlTransaction transaction, RequestIdentity identity, CancellationToken ct) =>
        identity.Access is { Role: AccessRoles.Administrator } access && await ActiveAdministrator(transaction, identity, access.Id, ct);

    private static async Task<AccessIdentity?> ReadAccessIdentity(NpgsqlTransaction transaction, Guid org, Guid id, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("SELECT id, display_name, role FROM control_access WHERE organization_id = $1 AND id = $2",
            transaction.Connection, transaction);
        AddParameters(command, org, id);
        await using var rows = await command.ExecuteReaderAsync(ct);
        return await rows.ReadAsync(ct) ? ReadAccessIdentity(rows, 0) : null;
    }

    private static async Task<LockedRollout?> LockRollout(NpgsqlTransaction transaction, Guid org, Guid id, CancellationToken ct)
    {
        LockedRollout? plan;
        await using (var command = new NpgsqlCommand("""
            SELECT p.id, p.name, p.source_version,
                CASE WHEN p.status = 'pending_review' AND p.expires_at <= clock_timestamp() THEN 'expired' ELSE p.status END,
                p.current_stage, p.stage_count, p.requires_review, p.created_by, a.id, a.display_name, a.role, o.slug
            FROM rollout_plans p JOIN organizations o ON o.id = p.organization_id
            LEFT JOIN control_access a ON a.organization_id = p.organization_id AND a.id = p.approved_by
            WHERE p.organization_id = $1 AND p.id = $2 FOR UPDATE OF p
            """, transaction.Connection, transaction))
        {
            AddParameters(command, org, id);
            await using var rows = await command.ExecuteReaderAsync(ct);
            if (!await rows.ReadAsync(ct)) return null;
            plan = new(rows.GetGuid(0), rows.GetString(1), rows.GetInt32(2), rows.GetString(3), rows.GetInt32(4), rows.GetInt32(5),
                rows.GetBoolean(6), rows.IsDBNull(7) ? null : rows.GetGuid(7), ReadAccessIdentity(rows, 8), rows.GetString(11), []);
        }
        var stages = await ReadRolloutStages(transaction.Connection!, transaction, org, [id], ct);
        return plan with { Stages = stages.GetValueOrDefault(id) ?? [] };
    }

    private async Task<RolloutPlan?> ReadRolloutPlan(Guid org, Guid id, CancellationToken ct) =>
        (await ReadRolloutPlans(org, id, ct)).FirstOrDefault();

    private async Task<IReadOnlyList<RolloutPlan>> ReadRolloutPlans(Guid org, Guid? id, CancellationToken ct)
    {
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(System.Data.IsolationLevel.RepeatableRead, ct);
        var plans = new List<(Guid Id, Func<IReadOnlyList<RolloutStage>, RolloutPlan> Build)>();
        await using (var command = new NpgsqlCommand("""
            SELECT p.id, p.name, p.source_version,
                CASE WHEN p.status = 'pending_review' AND p.expires_at <= clock_timestamp() THEN 'expired' ELSE p.status END,
                p.current_stage, p.revision, p.requires_review, c.id, c.display_name, c.role, a.id, a.display_name, a.role,
                p.created_at, p.expires_at, p.decided_at, p.evaluated_at, p.pause_reason, p.gate, p.finished_at
            FROM rollout_plans p
            LEFT JOIN control_access c ON c.organization_id = p.organization_id AND c.id = p.created_by
            LEFT JOIN control_access a ON a.organization_id = p.organization_id AND a.id = p.approved_by
            WHERE p.organization_id = $1 AND ($2::uuid IS NULL OR p.id = $2)
            ORDER BY p.created_at DESC, p.id DESC LIMIT 50
            """, connection, transaction))
        {
            AddParameters(command, org, (object?)id ?? DBNull.Value);
            await using var rows = await command.ExecuteReaderAsync(ct);
            while (await rows.ReadAsync(ct))
            {
                var planId = rows.GetGuid(0);
                var (name, source, status, current, revision, review) = (rows.GetString(1), rows.GetInt32(2), rows.GetString(3), rows.GetInt32(4),
                    rows.GetInt32(5), rows.GetBoolean(6));
                var (creator, approver) = (ReadAccessIdentity(rows, 7), ReadAccessIdentity(rows, 10));
                var (created, expires) = (rows.GetDateTime(13), rows.GetDateTime(14));
                DateTime? decided = rows.IsDBNull(15) ? null : rows.GetDateTime(15);
                DateTime? evaluated = rows.IsDBNull(16) ? null : rows.GetDateTime(16);
                var reason = rows.IsDBNull(17) ? null : rows.GetString(17);
                var gate = rows.IsDBNull(18) ? null : JsonSerializer.Deserialize<RolloutGate>(rows.GetString(18), JsonSerializerOptions.Web);
                DateTime? finished = rows.IsDBNull(19) ? null : rows.GetDateTime(19);
                plans.Add((planId, stages =>
                {
                    DateTime? next = null;
                    if (status == "running" && current < stages.Count && stages[current].PublishedAt is { } published)
                    {
                        // While the stage soaks, the next decision is due when the soak ends. Afterwards the background pass repeats.
                        var soak = published.AddSeconds(stages[current].MinSoakSeconds);
                        next = gate is { Soaked: false } && gate.Stage == current ? soak : (evaluated ?? DateTime.UtcNow).Add(RolloutInterval);
                    }
                    var view = stages.Select(stage => stage with { State = stage.RollbackOutcome ?? (stage.PublishedVersion is null ? "waiting"
                        : stage.Position < current || status == "completed" ? "passed" : "active") }).ToArray();
                    return new RolloutPlan(planId, name, source, status, current, revision, review, creator, approver, created, expires, decided,
                        evaluated, next, reason, gate, finished, view);
                }));
            }
        }
        var stageRows = await ReadRolloutStages(connection, transaction, org, plans.Select(plan => plan.Id).ToArray(), ct);
        await transaction.CommitAsync(ct);
        return plans.Select(plan => plan.Build(stageRows.GetValueOrDefault(plan.Id) ?? [])).ToArray();
    }

    private static async Task<Dictionary<Guid, IReadOnlyList<RolloutStage>>> ReadRolloutStages(NpgsqlConnection connection,
        NpgsqlTransaction transaction, Guid org, Guid[] plans, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            SELECT s.plan_id, s.position, s.group_id, g.name, s.min_soak_seconds, s.min_acknowledged_percent, s.require_composer_ready,
                s.max_block_events, s.max_warn_override_percent, s.prior_version, s.published_version, s.published_at,
                s.rollback_version, s.rollback_outcome
            FROM rollout_stages s LEFT JOIN policy_groups g ON g.organization_id = s.organization_id AND g.id = s.group_id
            WHERE s.organization_id = $1 AND s.plan_id = ANY($2) ORDER BY s.plan_id, s.position
            """, connection, transaction);
        AddParameters(command, org, plans);
        var result = new Dictionary<Guid, List<RolloutStage>>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct))
        {
            var plan = rows.GetGuid(0);
            if (!result.TryGetValue(plan, out var stages)) result[plan] = stages = [];
            stages.Add(new(rows.GetInt32(1), rows.IsDBNull(2) ? null : rows.GetGuid(2), rows.IsDBNull(3) ? null : rows.GetString(3),
                rows.GetInt32(4), rows.GetInt32(5), rows.GetFieldValue<string[]>(6), rows.IsDBNull(7) ? null : rows.GetInt32(7),
                rows.IsDBNull(8) ? null : rows.GetInt32(8), rows.IsDBNull(9) ? null : rows.GetInt32(9), rows.IsDBNull(10) ? null : rows.GetInt32(10),
                rows.IsDBNull(11) ? null : rows.GetDateTime(11), rows.IsDBNull(12) ? null : rows.GetInt32(12),
                rows.IsDBNull(13) ? null : rows.GetString(13), "waiting"));
        }
        return result.ToDictionary(entry => entry.Key, entry => (IReadOnlyList<RolloutStage>)entry.Value);
    }
}
