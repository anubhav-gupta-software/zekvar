using System.Data;
using System.Text.Json;
using Npgsql;

namespace Control;

internal sealed partial class ControlStore
{
    private static readonly (string Name, string Table)[] InstallationData =
    [
        ("eventTriage", "event_triage"),
        ("caseMemberships", "incident_case_events"),
        ("alertEvidence", "security_alert_events"),
        ("promptExceptionRequests", "prompt_exception_requests"),
        ("securityEvents", "security_events"),
        ("aiAppObservations", "ai_app_observations"),
        ("inventorySnapshots", "extension_inventory_snapshots"),
        ("inventoryChanges", "extension_inventory_change_batches"),
        ("composerObservations", "composer_observations"),
        ("deliveryReceipts", "policy_deliveries"),
        ("saasObservations", "saas_app_observations"),
        ("enrollmentKeyRedemptions", "enrollment_key_redemptions"),
        ("billingSeatDays", "billing_seat_days"),
    ];

    // Permanently removes a revoked installation and every record derived from it. Audit history keeps only the
    // installation ID, and a tombstone entry records the per-dataset counts.
    public async Task<InstallationDeletionResult> DeleteInstallation(RequestIdentity identity, Guid installationId, CancellationToken ct)
    {
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using (var locked = BrowserRead(transaction, """
            SELECT revoked_at IS NOT NULL FROM installations WHERE organization_id = $1 AND id = $2 FOR UPDATE
            """, identity.OrganizationId, installationId))
        {
            switch (await locked.ExecuteScalarAsync(ct))
            {
                case null: return new(null, null);
                case false: return new(null, "installation_active");
            }
        }
        await using (var cases = BrowserRead(transaction, """
            UPDATE incident_cases c SET revision = c.revision + 1 WHERE c.organization_id = $1 AND c.id IN (
                SELECT case_id FROM incident_case_events WHERE organization_id = $1 AND installation_id = $2)
            """, identity.OrganizationId, installationId))
            await cases.ExecuteNonQueryAsync(ct);
        var counts = new Dictionary<string, long>();
        foreach (var (name, table) in InstallationData)
        {
            await using var delete = BrowserRead(transaction, $"""
                WITH removed AS (DELETE FROM {table} WHERE organization_id = $1 AND installation_id = $2 RETURNING 1)
                SELECT count(*) FROM removed
                """, identity.OrganizationId, installationId);
            counts[name] = (long)(await delete.ExecuteScalarAsync(ct))!;
        }
        await using (var remove = BrowserRead(transaction, """
            WITH removed AS (DELETE FROM installations WHERE organization_id = $1 AND id = $2 RETURNING organization_id, id)
            INSERT INTO control_audit (organization_id, action, actor_access_id, data_deletion)
            SELECT organization_id, 'installation_deleted', $3, jsonb_build_object('installationId', id, 'deletedRows', $4::jsonb) FROM removed
            """, identity.OrganizationId, installationId, (object?)identity.Access?.Id ?? DBNull.Value,
            JsonSerializer.Serialize(counts)))
            await remove.ExecuteNonQueryAsync(ct);
        await transaction.CommitAsync(ct);
        return new(new(installationId, counts), null);
    }

    // Deletes superseded policy versions of one scope published before the cutoff. A version stays while it is current
    // anywhere in the organization, referenced by an open review or an unfinished rollout, used by a retained event or
    // installation, or cited by retained inventory, template, or exception evidence. Audit, closed reviews, and finished
    // rollouts keep the version number after its snapshot is purged.
    public async Task<PolicyPurge?> PurgePolicyHistory(RequestIdentity identity, PurgePolicyHistory request, CancellationToken ct)
    {
        var org = identity.OrganizationId;
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        // Publishing, restoring, and promoting all update the organization row, so this serializes with them.
        await using (var gate = BrowserRead(transaction, """
            SELECT (SELECT 1 FROM organizations WHERE id = $1 FOR UPDATE) IS NOT NULL
                AND ($2::uuid IS NULL OR EXISTS (SELECT 1 FROM policy_groups WHERE organization_id = $1 AND id = $2))
            """, org, (object?)request.GroupId ?? DBNull.Value))
            if (!(bool)(await gate.ExecuteScalarAsync(ct))!) return null;
        var cutoff = request.PublishedBefore.UtcDateTime;
        await using var scan = BrowserRead(transaction, """
            WITH scoped AS (
                SELECT version FROM policy_versions
                WHERE organization_id = $1 AND policy_group_id IS NOT DISTINCT FROM $2::uuid AND published_at < $3
            ), event_versions AS (
                SELECT DISTINCT policy_version AS version FROM security_events
                WHERE organization_id = $1 AND policy_version IN (SELECT version FROM scoped)
            )
            SELECT s.version,
                s.version = o.policy_version OR EXISTS (SELECT 1 FROM policy_groups g WHERE g.organization_id = $1 AND g.policy_version = s.version),
                EXISTS (SELECT 1 FROM policy_reviews r WHERE r.organization_id = $1 AND r.status = 'pending'
                    AND s.version IN (r.base_version, r.source_version, r.published_version)),
                EXISTS (SELECT 1 FROM rollout_plans p WHERE p.organization_id = $1 AND p.status IN ('pending_review', 'running', 'paused')
                    AND (p.source_version = s.version OR EXISTS (SELECT 1 FROM rollout_stages t WHERE t.organization_id = $1 AND t.plan_id = p.id
                        AND s.version IN (t.prior_version, t.published_version, t.rollback_version)))),
                s.version IN (SELECT version FROM event_versions),
                EXISTS (SELECT 1 FROM installations i WHERE i.organization_id = $1 AND i.applied_policy_version = s.version),
                EXISTS (SELECT 1 FROM extension_inventory_snapshots x WHERE x.organization_id = $1 AND x.policy_version = s.version)
                    OR EXISTS (SELECT 1 FROM extension_inventory_change_batches x WHERE x.organization_id = $1 AND x.policy_version = s.version)
                    OR EXISTS (SELECT 1 FROM policy_template_revisions x WHERE x.organization_id = $1 AND x.source_version = s.version)
                    OR EXISTS (SELECT 1 FROM prompt_exception_requests x WHERE x.organization_id = $1 AND x.published_version = s.version)
            FROM scoped s JOIN organizations o ON o.id = $1 ORDER BY s.version
            """, org, (object?)request.GroupId ?? DBNull.Value, cutoff);
        var purgeable = new List<int>();
        int current = 0, review = 0, rollout = 0, events = 0, installations = 0, evidence = 0;
        await using (var rows = await scan.ExecuteReaderAsync(ct))
            while (await rows.ReadAsync(ct))
            {
                // Each retained version is counted once, under the first reason that keeps it.
                if (rows.GetBoolean(1)) current++;
                else if (rows.GetBoolean(2)) review++;
                else if (rows.GetBoolean(3)) rollout++;
                else if (rows.GetBoolean(4)) events++;
                else if (rows.GetBoolean(5)) installations++;
                else if (rows.GetBoolean(6)) evidence++;
                else purgeable.Add(rows.GetInt32(0));
            }
        var kept = new PolicyPurgeKept(current, review, rollout, events, installations, evidence);
        var scope = request.GroupId.HasValue ? "group" : "baseline";
        if (!request.DryRun && purgeable.Count > 0)
        {
            var versions = purgeable.ToArray();
            await using var purge = BrowserRead(transaction, """
                WITH deliveries AS (
                    DELETE FROM policy_deliveries WHERE organization_id = $1 AND policy_version = ANY($2)
                ), audit_rows AS (
                    DELETE FROM policy_audit WHERE organization_id = $1 AND version = ANY($2)
                )
                SELECT 1
                """, org, versions);
            await purge.ExecuteNonQueryAsync(ct);
            await using var remove = BrowserRead(transaction, """
                WITH removed AS (DELETE FROM policy_versions WHERE organization_id = $1 AND version = ANY($2) RETURNING version)
                INSERT INTO control_audit (organization_id, action, actor_access_id, data_deletion)
                SELECT $1, 'policy_history_purged', $3, jsonb_build_object('scope', $4::text, 'groupId', $5::uuid,
                    'publishedBefore', $6::timestamptz, 'versions', (SELECT jsonb_agg(version ORDER BY version) FROM removed),
                    'kept', $7::jsonb)
                """, org, versions, (object?)identity.Access?.Id ?? DBNull.Value, scope, (object?)request.GroupId ?? DBNull.Value,
                cutoff, JsonSerializer.Serialize(kept, JsonSerializerOptions.Web));
            await remove.ExecuteNonQueryAsync(ct);
        }
        await transaction.CommitAsync(ct);
        return new(scope, request.GroupId, cutoff, request.DryRun, purgeable.ToArray(), kept);
    }

    private const string DeletionColumns = """
        id, status, requested_at, purge_after, cancelled_at, started_at, completed_at,
        (SELECT COALESCE(sum(value::bigint), 0)::bigint FROM jsonb_each_text(deleted_rows)), batches, last_error
        """;

    private static OrganizationDeletionStatus ReadDeletion(NpgsqlDataReader rows, int offset = 0) => new(rows.GetGuid(offset),
        rows.GetString(offset + 1), rows.GetDateTime(offset + 2), rows.GetDateTime(offset + 3),
        rows.IsDBNull(offset + 4) ? null : rows.GetDateTime(offset + 4), rows.IsDBNull(offset + 5) ? null : rows.GetDateTime(offset + 5),
        rows.IsDBNull(offset + 6) ? null : rows.GetDateTime(offset + 6), rows.GetInt64(offset + 7), rows.GetInt32(offset + 8),
        rows.IsDBNull(offset + 9) ? null : rows.GetString(offset + 9));

    public async Task<OrganizationDeletionResult> RequestOrganizationDeletion(RequestIdentity identity, OrganizationDeletionOptions options,
        CancellationToken ct)
    {
        var receiptToken = Tokens.Generate();
        await using var command = Command($"""
            WITH requested AS (
                INSERT INTO organization_deletions (id, organization_id, slug_hash, owner_token_hash, receipt_token_hash, status, purge_after)
                SELECT $1, o.id, $3, m.token_hash, $4, 'pending', now() + $5 * interval '1 day'
                FROM organizations o JOIN admin_memberships m ON m.organization_id = o.id WHERE o.id = $2
                ON CONFLICT (organization_id) WHERE status IN ('pending', 'deleting') DO NOTHING
                RETURNING *
            ), audit AS (
                INSERT INTO control_audit (organization_id, action, data_deletion)
                SELECT organization_id, 'organization_deletion_requested', jsonb_build_object('deletionId', id,
                    'purgeAfter', purge_after, 'graceDays', $5::integer) FROM requested
            )
            SELECT {DeletionColumns} FROM requested
            """, Guid.NewGuid(), identity.OrganizationId, Tokens.Hash(identity.OrganizationSlug!), Tokens.Hash(receiptToken), options.GraceDays);
        await using var rows = await command.ExecuteReaderAsync(ct);
        return await rows.ReadAsync(ct)
            ? new(new(ReadDeletion(rows), receiptToken), null)
            : new(null, "organization_deletion_exists");
    }

    public async Task<OrganizationDeletionStatus?> OrganizationDeletion(Guid organizationId, CancellationToken ct)
    {
        await using var command = Command($"""
            SELECT {DeletionColumns} FROM organization_deletions WHERE organization_id = $1
            ORDER BY (status IN ('pending', 'deleting')) DESC, requested_at DESC LIMIT 1
            """, organizationId);
        await using var rows = await command.ExecuteReaderAsync(ct);
        return await rows.ReadAsync(ct) ? ReadDeletion(rows) : null;
    }

    public async Task<(OrganizationDeletionStatus? Deletion, string? Error)> CancelOrganizationDeletion(RequestIdentity identity, CancellationToken ct)
    {
        await using var command = Command($"""
            WITH cancelled AS (
                UPDATE organization_deletions SET status = 'cancelled', cancelled_at = now()
                WHERE organization_id = $1 AND status = 'pending' RETURNING *
            ), audit AS (
                INSERT INTO control_audit (organization_id, action, data_deletion)
                SELECT organization_id, 'organization_deletion_cancelled', jsonb_build_object('deletionId', id) FROM cancelled
            )
            SELECT {DeletionColumns}, false FROM cancelled
            UNION ALL
            SELECT NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, true
            WHERE NOT EXISTS (SELECT 1 FROM cancelled)
                AND EXISTS (SELECT 1 FROM organization_deletions WHERE organization_id = $1 AND status = 'deleting')
            """, identity.OrganizationId);
        await using var rows = await command.ExecuteReaderAsync(ct);
        if (!await rows.ReadAsync(ct)) return (null, null);
        return rows.GetBoolean(10) ? (null, "organization_deletion_in_progress") : (ReadDeletion(rows), null);
    }

    // The owner can download a signed receipt at any time: provisional (rows currently held) during the grace period
    // and deletion, and the stored final receipt after completion.
    public async Task<string?> OrganizationDeletionReceipt(Guid organizationId, OrganizationDeletionOptions options, CancellationToken ct)
    {
        await using var command = Command("""
            SELECT id FROM organization_deletions WHERE organization_id = $1
            ORDER BY (status IN ('pending', 'deleting')) DESC, requested_at DESC LIMIT 1
            """, organizationId);
        return await command.ExecuteScalarAsync(ct) is Guid id ? await DeletionReceipt(id, null, options, ct) : null;
    }

    public async Task<string?> DeletionReceipt(Guid id, string? receiptToken, OrganizationDeletionOptions options, CancellationToken ct)
    {
        if (options.ReceiptKey is not { } key) return null;
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var snapshot = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        OrganizationDeletionStatus deletion;
        Guid organizationId;
        string? stored = null, signature = null;
        await using (var command = BrowserRead(snapshot, $"""
            SELECT {DeletionColumns}, organization_id, receipt, receipt_signature FROM organization_deletions
            WHERE id = $1 AND ($2::text IS NULL OR receipt_token_hash = $2) AND status <> 'cancelled'
            """, id, receiptToken is null ? DBNull.Value : Tokens.Hash(receiptToken)))
        await using (var rows = await command.ExecuteReaderAsync(ct))
        {
            if (!await rows.ReadAsync(ct)) return null;
            deletion = ReadDeletion(rows);
            organizationId = rows.GetGuid(10);
            if (!rows.IsDBNull(11)) (stored, signature) = (rows.GetString(11), rows.GetString(12));
        }
        if (stored is not null) return DeletionReceipts.Envelope(key, stored, signature);
        var tables = new List<(string, long)>();
        foreach (var table in TenantTables.DeletionOrder)
        {
            await using var count = BrowserRead(snapshot, $"SELECT count(*) FROM {table.Name} WHERE {table.Scope}", organizationId);
            tables.Add((table.Name, (long)(await count.ExecuteScalarAsync(ct))!));
        }
        return DeletionReceipts.Envelope(key, DeletionReceipts.Build(deletion, organizationId, tables, null, null, options.BackupRetentionDays));
    }

    public async Task<IReadOnlyList<Guid>> DueOrganizationDeletions(CancellationToken ct)
    {
        await using var command = Command("""
            SELECT id FROM organization_deletions WHERE status = 'deleting' OR (status = 'pending' AND purge_after <= now())
            ORDER BY purge_after, id LIMIT 100
            """);
        var due = new List<Guid>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct)) due.Add(rows.GetGuid(0));
        return due;
    }

    // Tables in the public schema that the deletion plan does not handle.
    private static async Task<List<string>> UnhandledTables(NpgsqlTransaction transaction, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND NOT c.relispartition AND NOT (c.relname = ANY($1)) ORDER BY 1
            """, transaction.Connection, transaction);
        command.Parameters.AddWithValue(TenantTables.Handled.ToArray());
        var tables = new List<string>();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct)) tables.Add(rows.GetString(0));
        return tables;
    }

    // Runs one bounded deletion batch in its own transaction and records its progress with it, so a crash or a failed
    // batch resumes from the last committed batch. Returns not_due, busy, progress, completed, or failed.
    public async Task<string> RunOrganizationDeletionBatch(Guid id, OrganizationDeletionOptions options, CancellationToken ct)
    {
        try
        {
            return await DeletionBatch(id, options, ct);
        }
        catch (Exception error) when (error is NpgsqlException && !ct.IsCancellationRequested)
        {
            await using var record = Command("""
                UPDATE organization_deletions SET last_error = 'batch_failed' WHERE id = $1 AND status = 'deleting'
                """, id);
            await record.ExecuteNonQueryAsync(ct);
            return "failed";
        }
    }

    private async Task<string> DeletionBatch(Guid id, OrganizationDeletionOptions options, CancellationToken ct)
    {
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        // Issued billing documents and frozen usage snapshots refuse deletion unless this transaction is the offboarding job.
        await using (var purge = BrowserRead(transaction, "SELECT set_config('zekvar.billing_purge', 'on', true), set_config('zekvar.evidence_purge', 'on', true)"))
            await purge.ExecuteNonQueryAsync(ct);
        Guid organizationId;
        string status;
        Dictionary<string, long> deleted;
        await using (var claim = BrowserRead(transaction, """
            SELECT organization_id, status, purge_after <= now(), deleted_rows::text FROM organization_deletions
            WHERE id = $1 AND status IN ('pending', 'deleting') FOR UPDATE SKIP LOCKED
            """, id))
        await using (var rows = await claim.ExecuteReaderAsync(ct))
        {
            if (!await rows.ReadAsync(ct)) return "busy";
            if (rows.GetString(1) == "pending" && !rows.GetBoolean(2)) return "not_due";
            organizationId = rows.GetGuid(0);
            status = rows.GetString(1);
            deleted = JsonSerializer.Deserialize<Dictionary<string, long>>(rows.GetString(3))!;
        }
        if (options.ReceiptKey is not { } key) return "failed";
        if ((await UnhandledTables(transaction, ct)).Count > 0)
        {
            await using var refuse = BrowserRead(transaction, """
                UPDATE organization_deletions SET last_error = 'unhandled_tenant_table',
                    status = 'deleting', started_at = COALESCE(started_at, now()) WHERE id = $1
                """, id);
            await refuse.ExecuteNonQueryAsync(ct);
            await transaction.CommitAsync(ct);
            return "failed";
        }

        var budget = options.BatchSize;
        foreach (var table in TenantTables.DeletionOrder)
        {
            if (budget == 0) break;
            if (table.Name == "policy_versions")
            {
                // Groups and versions reference each other; clear group pointers before removing versions.
                await using var detach = BrowserRead(transaction,
                    "UPDATE policy_groups SET policy_version = NULL WHERE organization_id = $1 AND policy_version IS NOT NULL", organizationId);
                await detach.ExecuteNonQueryAsync(ct);
            }
            var count = 0;
            do
            {
                await using var delete = BrowserRead(transaction, $"""
                    WITH removed AS (
                        DELETE FROM {table.Name} WHERE ctid IN (SELECT ctid FROM {table.Name} WHERE {table.DeleteScope ?? table.Scope} LIMIT $2) RETURNING 1
                    )
                    SELECT count(*)::integer FROM removed
                    """, organizationId, budget);
                var removed = (int)(await delete.ExecuteScalarAsync(ct))!;
                count += removed;
                budget -= removed;
                if (removed == 0) break;
            } while (table.DeleteScope is not null && budget > 0);
            if (count == 0) continue;
            deleted[table.Name] = deleted.GetValueOrDefault(table.Name) + count;
        }

        string? receipt = null;
        if (budget > 0)
        {
            // Every step found nothing left within the budget: verify every tenant table is empty for this organization.
            var (tablesChecked, remaining) = await RemainingTenantRows(transaction, organizationId, ct);
            if (remaining == 0)
            {
                await using var clock = BrowserRead(transaction, $"""
                    SELECT {DeletionColumns} FROM organization_deletions WHERE id = $1
                    """, id);
                OrganizationDeletionStatus current;
                await using (var rows = await clock.ExecuteReaderAsync(ct))
                {
                    await rows.ReadAsync(ct);
                    var read = ReadDeletion(rows);
                    var clockTicks = DateTime.UtcNow.Ticks;
                    var now = new DateTime(clockTicks - clockTicks % 10, DateTimeKind.Utc); // PostgreSQL keeps microseconds
                    current = read with { Status = "completed", CompletedAt = now, StartedAt = read.StartedAt ?? now };
                }
                receipt = DeletionReceipts.Build(current, organizationId,
                    TenantTables.DeletionOrder.Select(table => (table.Name, deleted.GetValueOrDefault(table.Name))).ToList(),
                    tablesChecked, remaining, options.BackupRetentionDays);
                await using var complete = BrowserRead(transaction, """
                    UPDATE organization_deletions SET status = 'completed', started_at = $6, completed_at = $3,
                        deleted_rows = $2::jsonb, batches = batches + 1, last_error = NULL, receipt = $4, receipt_signature = $5
                    WHERE id = $1
                    """, id, JsonSerializer.Serialize(deleted), current.CompletedAt!.Value, receipt, DeletionReceipts.Sign(key, receipt), current.StartedAt!.Value);
                await complete.ExecuteNonQueryAsync(ct);
                await transaction.CommitAsync(ct);
                return "completed";
            }
        }
        await using (var progress = BrowserRead(transaction, """
            UPDATE organization_deletions SET status = 'deleting', started_at = COALESCE(started_at, now()),
                deleted_rows = $2::jsonb, batches = batches + 1, last_error = CASE WHEN $3 THEN 'verification_failed' END
            WHERE id = $1
            """, id, JsonSerializer.Serialize(deleted), budget > 0))
            await progress.ExecuteNonQueryAsync(ct);
        await transaction.CommitAsync(ct);
        return budget > 0 ? "failed" : "progress";
    }

    // Counts rows for the organization in every public table that has an organization_id column, discovered from the
    // catalog so tables added later are checked too, plus the organization row itself.
    private static async Task<(int Tables, long Remaining)> RemainingTenantRows(NpgsqlTransaction transaction, Guid organizationId, CancellationToken ct)
    {
        var tables = new List<string>();
        await using (var list = new NpgsqlCommand("""
            SELECT c.table_name FROM information_schema.columns c JOIN information_schema.tables t
                ON t.table_schema = c.table_schema AND t.table_name = c.table_name
            WHERE c.table_schema = 'public' AND c.column_name = 'organization_id' AND t.table_type = 'BASE TABLE'
                AND c.table_name <> 'organization_deletions' ORDER BY 1
            """, transaction.Connection, transaction))
        await using (var rows = await list.ExecuteReaderAsync(ct))
            while (await rows.ReadAsync(ct)) tables.Add(rows.GetString(0));
        long remaining = 0;
        foreach (var table in tables.Append("organizations"))
        {
            var column = table == "organizations" ? "id" : "organization_id";
            await using var count = new NpgsqlCommand($"SELECT count(*) FROM \"{table}\" WHERE {column} = $1", transaction.Connection, transaction);
            count.Parameters.AddWithValue(organizationId);
            remaining += (long)(await count.ExecuteScalarAsync(ct))!;
        }
        return (tables.Count + 1, remaining);
    }

    // Streams every exportable tenant record from one snapshot. Rows are written as they are read, so memory stays bounded.
    public async Task<long> WriteOrganizationExport(RequestIdentity identity, Stream body, CancellationToken ct)
    {
        await using (var audit = Command("""
            INSERT INTO control_audit (organization_id, action, data_deletion)
            VALUES ($1, 'organization_exported', jsonb_build_object('format', 'json', 'datasets', $2::integer))
            """, identity.OrganizationId, TenantTables.DeletionOrder.Count(table => table.Export)))
            await audit.ExecuteNonQueryAsync(ct);
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var snapshot = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        await using (var readOnly = BrowserRead(snapshot, "SET TRANSACTION READ ONLY")) await readOnly.ExecuteNonQueryAsync(ct);
        await using var json = new Utf8JsonWriter(body);
        json.WriteStartObject();
        json.WriteNumber("version", 1);
        json.WriteString("type", "zekvar.organization_export");
        json.WriteString("exportedAt", DeletionReceipts.Timestamp(DateTime.UtcNow));
        await using (var organization = BrowserRead(snapshot, "SELECT to_jsonb(o)::text FROM organizations o WHERE id = $1", identity.OrganizationId))
        {
            json.WritePropertyName("organization");
            json.WriteRawValue((string)(await organization.ExecuteScalarAsync(ct))!);
        }
        var counts = new List<(string, long)>();
        json.WriteStartObject("datasets");
        foreach (var table in TenantTables.DeletionOrder.Where(table => table.Export))
        {
            json.WriteStartArray(table.Name);
            long written = 0;
            await using var command = BrowserRead(snapshot, $"""
                SELECT (to_jsonb(t) - $2::text[])::text FROM {table.Name} t WHERE {table.Scope}
                """, identity.OrganizationId, table.Secrets ?? []);
            // Sealed columns are exported readable for the owner, for portability; the data keys never leave Control.
            var open = ExportOpener(table.Name, identity.OrganizationId);
            await using (var rows = await command.ExecuteReaderAsync(CommandBehavior.SequentialAccess, ct))
                while (await rows.ReadAsync(ct))
                {
                    json.WriteRawValue(open(rows.GetString(0)));
                    if (++written % 200 == 0) await json.FlushAsync(ct);
                }
            json.WriteEndArray();
            counts.Add((table.Name, written));
            await json.FlushAsync(ct);
        }
        json.WriteEndObject();
        json.WriteStartObject("counts");
        foreach (var (name, count) in counts) json.WriteNumber(name, count);
        json.WriteEndObject();
        json.WriteEndObject();
        await json.FlushAsync(ct);
        await snapshot.CommitAsync(ct);
        return counts.Sum(entry => entry.Item2);
    }

    private Func<string, string> ExportOpener(string table, Guid organizationId) => table switch
    {
        "policy_versions" => row => OpenSealedRow(row, organizationId, ("classification_protection", "terms", ClassificationField),
            ("identifier_protection", "formats", IdentifierField), ("health_protection", "recordFormats", HealthField)),
        "policy_reviews" => row =>
        {
            var node = System.Text.Json.Nodes.JsonNode.Parse(row)!.AsObject();
            if (node["snapshots"] is { } snapshots)
                node["snapshots"] = System.Text.Json.Nodes.JsonNode.Parse(protection.OpenObject(snapshots.ToJsonString(), organizationId, ReviewSnapshotField, Guid.Parse(node["id"]!.GetValue<string>()).ToString("D")));
            return node.ToJsonString();
        },
        "billing_invoices" or "billing_quotes" => row =>
        {
            var node = System.Text.Json.Nodes.JsonNode.Parse(row)!.AsObject();
            if (node["billing_email"]?.GetValue<string>() is { } email)
                node["billing_email"] = OpenBillingEmail(organizationId, Guid.Parse(node["id"]!.GetValue<string>()), email);
            return node.ToJsonString();
        },
        _ => row => row,
    };

    private string OpenSealedRow(string row, Guid organizationId, params (string Column, string Member, string Field)[] columns)
    {
        var node = System.Text.Json.Nodes.JsonNode.Parse(row)!.AsObject();
        var version = node["version"]!.GetValue<int>().ToString();
        foreach (var (column, member, field) in columns)
            if (node[column] is { } value)
                node[column] = System.Text.Json.Nodes.JsonNode.Parse(protection.OpenMember(value.ToJsonString(), member, organizationId, field, version));
        return node.ToJsonString();
    }
}
