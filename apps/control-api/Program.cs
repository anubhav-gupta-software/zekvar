using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json.Serialization;
using Control;
using Microsoft.AspNetCore.Http.Features;
using Npgsql;

var builder = WebApplication.CreateBuilder(args);
var hostedPilot = builder.Configuration.GetValue("Control:HostedPilot", false);
if (hostedPilot ? !builder.Environment.IsProduction() : !builder.Environment.IsDevelopment())
    throw new InvalidOperationException("Run Control in Development for the local demo or explicitly enable HostedPilot in Production.");

var connectionString = builder.Configuration.GetConnectionString("Control")
    ?? throw new InvalidOperationException("Set ConnectionStrings__Control for PostgreSQL.");
var port = builder.Configuration.GetValue("Control:Port", 5187);
if (port is < 1024 or > 65535)
    throw new InvalidOperationException("Configure a Control loopback port between 1024 and 65535.");
var sweepSeconds = builder.Configuration.GetValue("Control:RetentionSweepSeconds", 3600);
if (sweepSeconds is < 1 or > 86400)
    throw new InvalidOperationException("Configure a retention sweep interval between 1 and 86400 seconds.");
var organizations = builder.Configuration.GetSection("Control:Organizations").Get<DemoOrganization[]>();
if (organizations is not { Length: > 0 } || organizations.Any(org => !ValidOrganization(org)) ||
    organizations.Select(org => org.Slug).Distinct().Count() != organizations.Length ||
    organizations.Select(org => org.AdminToken).Distinct().Count() != organizations.Length)
    throw new InvalidOperationException("Configure distinct organization slugs and 32-byte hex admin tokens.");
var sso = ControlSso.Read(builder.Configuration, hostedPilot, organizations);
var alertWebhooks = AlertWebhooks.Read(builder.Configuration, builder.Environment.IsDevelopment(), organizations);

builder.WebHost.ConfigureKestrel(options =>
{
    options.Listen(IPAddress.Loopback, port);
    options.Limits.MaxRequestBodySize = 16 * 1024;
});
builder.Services.Configure<RouteHandlerOptions>(options => options.ThrowOnBadRequest = false);
builder.Services.ConfigureHttpJsonOptions(options =>
    options.SerializerOptions.UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow);
builder.Services.AddSingleton(_ => NpgsqlDataSource.Create(connectionString));
builder.Services.AddSingleton(alertWebhooks);
builder.Services.AddSingleton(services => new ControlStore(services.GetRequiredService<NpgsqlDataSource>(), sso, alertWebhooks));
builder.Services.AddHostedService<RetentionSweep>(services => new(services.GetRequiredService<ControlStore>(),
    services.GetRequiredService<ILogger<RetentionSweep>>(), TimeSpan.FromSeconds(sweepSeconds)));
if (alertWebhooks.Enabled) builder.Services.AddHostedService<AlertWebhookDispatcher>();

var app = builder.Build();
var store = app.Services.GetRequiredService<ControlStore>();
await store.Initialize(organizations, app.Lifetime.ApplicationStopping);

app.Use(async (context, next) =>
{
    context.Response.Headers.CacheControl = "no-store";
    if (context.Connection.RemoteIpAddress is not { } remote || !IPAddress.IsLoopback(remote))
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        return;
    }
    if (HttpMethods.IsPost(context.Request.Method) &&
        context.Request.Path.Value?.TrimEnd('/').Equals("/v1/browser/extension-inventory", StringComparison.OrdinalIgnoreCase) == true &&
        context.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } inventoryLimit)
        inventoryLimit.MaxRequestBodySize = ReportExtensionInventory.MaxBodySize;
    if (HttpMethods.IsPost(context.Request.Method) && context.Request.Path.StartsWithSegments("/v1/admin") &&
        context.Request.Path.Value?.TrimEnd('/').EndsWith("/policies", StringComparison.OrdinalIgnoreCase) == true &&
        context.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } policyLimit)
        policyLimit.MaxRequestBodySize = 48 * 1024;
    await next(context);
});

app.MapGet("/health", async (NpgsqlDataSource database, CancellationToken ct) =>
{
    if (!hostedPilot) return Results.Ok(new { status = "ready" });
    using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
    deadline.CancelAfter(TimeSpan.FromSeconds(2));
    try
    {
        await using var ping = database.CreateCommand("SELECT 1");
        await ping.ExecuteScalarAsync(deadline.Token);
        return Results.Ok(new { status = "ready" });
    }
    catch (Exception error) when (error is NpgsqlException or OperationCanceledException)
    {
        return Results.Json(new { status = "unavailable" }, statusCode: StatusCodes.Status503ServiceUnavailable);
    }
});

var admin = app.MapGroup("/v1/admin").AddEndpointFilter(Authenticate(browser: false));
admin.MapGet("/session", async (HttpContext http, CancellationToken ct) =>
{
    var identity = Identity(http);
    var reviewRequired = await store.PolicyReviewRequired(identity.OrganizationId, ct);
    return Results.Ok(new { organization = identity.OrganizationSlug, role = identity.Role, access = identity.Access, reviewRequired });
});
var access = admin.MapGroup("/access").AddEndpointFilter((context, next) =>
    Identity(context.HttpContext).Role == AccessRoles.Owner ? next(context) : ValueTask.FromResult<object?>(Results.StatusCode(403)));
access.MapGet("", async (HttpContext http, CancellationToken ct) =>
    Results.Ok(await store.ListAccess(Identity(http).OrganizationId, ct)));
access.MapPost("", async (IssueControlAccess request, HttpContext http, CancellationToken ct) =>
{
    var name = request.Name?.Trim();
    if (name is not { Length: >= 2 and <= 64 } || name.Any(char.IsControl) ||
        !AccessRoles.IsDelegated(request.Role) || request.Hours is < 1 or > 720)
        return Results.BadRequest(new { error = "Enter a name, a delegated role, and a lifetime from 1 to 720 hours." });
    return Results.Ok(await store.IssueAccess(Identity(http).OrganizationId, name, request.Role!, request.Hours, ct));
});
access.MapPost("/{id:guid}/revoke", async (Guid id, HttpContext http, CancellationToken ct) =>
    await store.RevokeAccess(Identity(http).OrganizationId, id, ct) ? Results.NoContent() : Results.NotFound());
access.MapGet("/event-feed", async (HttpContext http, CancellationToken ct) =>
    Results.Ok(await store.ListEventFeedKeys(Identity(http).OrganizationId, ct)));
access.MapPost("/event-feed", async (CreateEventFeedKey request, HttpContext http, CancellationToken ct) =>
{
    var name = request.Name?.Trim();
    if (request.RequestId == Guid.Empty || name is not { Length: >= 2 and <= 64 } || name.Any(char.IsControl) ||
        request.Days is < 1 or > 90)
        return Results.BadRequest(new { error = "Enter a request ID, a name, and a lifetime from 1 to 90 days." });
    var result = await store.IssueEventFeedKey(Identity(http).OrganizationId, request.RequestId, name, request.Days, ct);
    return result.Issued is { } issued ? Results.Ok(issued) : Results.Conflict(new { code = result.Error });
});
access.MapPost("/event-feed/{id:guid}/revoke", async (Guid id, HttpContext http, CancellationToken ct) =>
    await store.RevokeEventFeedKey(Identity(http).OrganizationId, id, ct) ? Results.NoContent() : Results.NotFound());
access.MapGet("/sso", (HttpContext http) => sso.TryGetValue(Identity(http).OrganizationSlug ?? "", out var provider)
    ? Results.Ok(new { provider.Issuer }) : Results.NoContent());
access.MapPost("/sso", async (AddSsoIdentity request, HttpContext http, CancellationToken ct) =>
{
    var identity = Identity(http);
    if (!sso.TryGetValue(identity.OrganizationSlug ?? "", out var provider)) return Results.NotFound();
    var name = request.Name?.Trim();
    if (name is not { Length: >= 2 and <= 64 } || name.Any(char.IsControl) ||
        !AccessRoles.IsDelegated(request.Role) || !ControlSso.ValidSubject(request.Subject))
        return Results.BadRequest(new { error = "Enter a name, delegated role, and exact OIDC subject." });
    var added = await store.AddSsoIdentity(identity.OrganizationId, provider.Issuer, request.Subject!, name, request.Role!, ct);
    return added is not null ? Results.Ok(added) : Results.Conflict(new { code = "sso_subject_exists" });
});

app.MapGet("/v1/integrations/events", async (HttpContext http, CancellationToken ct) =>
{
    if (ParseBearer(http) is not { } token || !EventFeedToken.IsValid(token)) return RejectEventFeed(http);
    var query = http.Request.Query;
    var limit = 100;
    if (query.Any(parameter => parameter.Key is not ("after" or "limit") || parameter.Value.Count != 1) ||
        (query.ContainsKey("limit") && (!int.TryParse(query["limit"], NumberStyles.None, CultureInfo.InvariantCulture, out limit) || limit is < 1 or > 500)))
        return Results.BadRequest(new { error = "Use an optional cursor and a page limit from 1 to 500." });
    EventFeedCursor? after = null;
    if (query.TryGetValue("after", out var received))
    {
        if (!EventFeedCursor.TryParse(received.ToString(), out var cursor))
            return Results.BadRequest(new { error = "Use the next cursor returned by the event feed." });
        after = cursor;
    }
    var result = await store.ReadEventFeed(token, after, limit, ct);
    if (!result.Authorized) return RejectEventFeed(http);
    return result.Page is { } page ? Results.Ok(page) : Results.Conflict(new { code = "event_feed_cursor_invalid" });
});

app.MapPost("/v1/internal/sso/session", async (ExchangeSsoIdentity request, HttpContext http, CancellationToken ct) =>
{
    if (sso.Count == 0) return Results.NotFound();
    var provider = request.OrganizationSlug is { } slug ? sso.GetValueOrDefault(slug) : sso.Values.SingleOrDefault(entry => entry.Legacy);
    if (provider is null || BearerToken(http) is not { } token || !provider.Authorizes(token) ||
        request.Issuer != provider.Issuer || !ControlSso.ValidSubject(request.Subject) || request.ExpiresAt <= DateTimeOffset.UtcNow)
        return Results.Unauthorized();
    return await store.ExchangeSsoIdentity(provider, request.Subject!, request.ExpiresAt, ct) is { } session
        ? Results.Ok(session) : Results.Unauthorized();
});
app.MapDelete("/v1/internal/sso/session", async (HttpContext http, CancellationToken ct) =>
{
    if (sso.Count == 0) return Results.NotFound();
    if (BearerToken(http) is not { } token) return Results.Unauthorized();
    await store.EndSsoSession(token, ct);
    return Results.NoContent();
});
admin.MapPost("/enrollment-grants", async (HttpContext http, CancellationToken ct) =>
    Results.Ok(await store.CreateGrant(Identity(http), ct)));
admin.MapGet("/enrollment-batches", async (HttpContext http, CancellationToken ct) =>
    Results.Ok(await store.EnrollmentBatches(Identity(http).OrganizationId, ct)));
admin.MapPost("/enrollment-batches", async (CreateEnrollmentBatch request, HttpContext http, CancellationToken ct) =>
{
    if (!request.IsValid()) return Results.BadRequest(new { error = "Choose a group and a batch size from 1 to 25." });
    var (batch, scopeExists) = await store.IssueEnrollmentBatch(Identity(http), request, ct);
    if (!scopeExists) return Results.NotFound();
    return batch is null ? Results.Conflict(new { code = "enrollment_batch_exists" }) : Results.Ok(batch);
});
admin.MapPost("/enrollment-batches/{id:guid}/cancel", async (Guid id, HttpContext http, CancellationToken ct) =>
    await store.CancelEnrollmentBatch(Identity(http), id, ct) ? Results.NoContent() : Results.NotFound());
admin.MapGet("/installations", async (HttpContext http, CancellationToken ct) =>
    Results.Ok(await store.Installations(Identity(http).OrganizationId, ct)));
admin.MapGet("/installations/fleet", async (HttpContext http, CancellationToken ct) =>
{
    var query = http.Request.Query;
    if (query.Any(entry => entry.Key is not ("rolloutGroup" or "beforeAt" or "beforeId") || entry.Value.Count != 1) ||
        !BrowserHealthFilter.TryParse(query["rolloutGroup"].FirstOrDefault(), null, out var filter))
        return Results.BadRequest(new { error = "Choose a valid rollout group and fleet cursor." });
    FleetCursor? before = null;
    if (query.ContainsKey("beforeAt") || query.ContainsKey("beforeId"))
    {
        if (!DateTimeOffset.TryParse(query["beforeAt"], CultureInfo.InvariantCulture, DateTimeStyles.None, out var enrolled) ||
            !Guid.TryParse(query["beforeId"], out var id) || id == Guid.Empty)
            return Results.BadRequest(new { error = "Use both values from the fleet cursor." });
        before = new(enrolled.UtcDateTime, id);
    }
    return await store.ReadFleet(Identity(http).OrganizationId, filter, before, ct) is { } fleet ? Results.Ok(fleet) : Results.NotFound();
});
admin.MapPost("/installations/fleet", async (FleetRequest request, HttpContext http, CancellationToken ct) =>
{
    if (!request.IsValid()) return Results.BadRequest(new { error = "Choose an action and 1 to 25 distinct browsers from the fleet." });
    var result = await store.ApplyFleetChange(Identity(http), request, ct);
    if (result.Change is { } change) return Results.Ok(change);
    return result.Error is "fleet_target_unavailable" or "fleet_selection_unavailable"
        ? Results.NotFound(new { code = result.Error }) : Results.Conflict(new { code = result.Error });
});
admin.MapGet("/browser-releases", async (HttpContext http, CancellationToken ct) =>
    Results.Ok(await store.BrowserReleases(Identity(http).OrganizationId, ct)));
admin.MapGet("/browser-health", async (HttpContext http, CancellationToken ct) =>
{
    if (!TryParseBrowserHealthFilter(http.Request.Query, out var filter)) return InvalidBrowserHealthFilter();
    return await store.BrowserHealth(Identity(http).OrganizationId, filter, ct) is { } health
        ? Results.Ok(health) : Results.NotFound();
});
admin.MapGet("/reports/composer-readiness", async (HttpContext http, CancellationToken ct) =>
{
    var query = http.Request.Query;
    if (query.Keys.Any(key => key is not ("rolloutGroup" or "browserVersion")) ||
        !TryParseBrowserHealthFilter(query, out var filter)) return InvalidBrowserHealthFilter();
    return await store.ReadComposerReadinessReport(Identity(http).OrganizationId, filter, ct) is { } report
        ? Results.Ok(report) : Results.NotFound();
});
admin.MapGet("/reports/policy-impact", async (HttpContext http, CancellationToken ct) =>
{
    var query = http.Request.Query;
    Guid? groupId = null;
    int? expectedVersion = null;
    if (query.Any(entry => entry.Key is not ("scope" or "expectedVersion") || entry.Value.Count != 1))
        return Results.BadRequest(new { error = "Choose a policy scope and an optional reviewed version." });
    if (query.TryGetValue("scope", out var scope) && scope != "baseline")
    {
        if (!Guid.TryParseExact(scope, "D", out var group) || group == Guid.Empty)
            return Results.BadRequest(new { error = "Choose the baseline or a rollout group." });
        groupId = group;
    }
    if (query.TryGetValue("expectedVersion", out var version))
    {
        if (!int.TryParse(version, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var parsed) || parsed < 1)
            return Results.BadRequest(new { error = "Choose a valid reviewed policy version." });
        expectedVersion = parsed;
    }
    var (report, stale) = await store.PolicyImpact(Identity(http).OrganizationId, groupId, expectedVersion, ct);
    return report is not null ? Results.Ok(report)
        : stale ? Results.Conflict(new { code = "policy_impact_stale" }) : Results.NotFound();
});
admin.MapGet("/extension-inventory", async (HttpContext http, CancellationToken ct) =>
    Results.Ok(await store.ExtensionInventory(Identity(http).OrganizationId, null, ct)));
admin.MapGet("/extension-inventory/{id:guid}", async (Guid id, HttpContext http, CancellationToken ct) =>
    (await store.ExtensionInventory(Identity(http).OrganizationId, id, ct)).FirstOrDefault() is { } installation
        ? Results.Ok(installation) : Results.NotFound());
admin.MapPost("/installations/{id:guid}/revoke", async (Guid id, HttpContext http, CancellationToken ct) =>
    await store.Revoke(Identity(http), id, ct) ? Results.NoContent() : Results.NotFound());
admin.MapGet("/policies", async (HttpContext http, CancellationToken ct) =>
    Results.Ok(await store.PolicyHistory(Identity(http).OrganizationId, ct)));
admin.MapPost("/policies", async (PublishPolicy request, HttpContext http, CancellationToken ct) =>
    await PublishSettings(request, http, ct));
admin.MapPost("/policies/{version:int}/restore", async (int version, HttpContext http, CancellationToken ct) =>
    PolicyOutcome(await store.ChangePolicy(Identity(http), null, version, ExpectsReview(http), ct), Results.NotFound()));
var templates = admin.MapGroup("/policy-templates");
templates.MapGet("", async (HttpContext http, CancellationToken ct) => Results.Ok(await store.ListTemplates(Identity(http).OrganizationId, ct)));
templates.MapGet("/{id:guid}", async (Guid id, HttpContext http, CancellationToken ct) =>
    await store.TemplateDetails(Identity(http).OrganizationId, id, ct) is { } details ? Results.Ok(details) : Results.NotFound());
templates.MapPost("", async (CreatePolicyTemplate request, HttpContext http, CancellationToken ct) =>
{
    var name = request.Name?.Trim();
    if (name is not { Length: >= 2 and <= 64 } || name.Any(char.IsControl) || request.SourceVersion < 1)
        return Results.BadRequest(new { error = "Enter a template name and a published policy version." });
    return TemplateOutcome(await store.CreateTemplate(Identity(http), name, request.SourceVersion, ct));
});
templates.MapPost("/{id:guid}/revisions", async (Guid id, RevisePolicyTemplate request, HttpContext http, CancellationToken ct) =>
    request.ExpectedRevision < 1 || request.SourceVersion < 1 ? Results.BadRequest()
        : TemplateOutcome(await store.ReviseTemplate(Identity(http), id, request, ct)));
templates.MapPost("/{id:guid}/archive", async (Guid id, ArchivePolicyTemplate request, HttpContext http, CancellationToken ct) =>
    request.ExpectedRevision < 1 ? Results.BadRequest()
        : TemplateOutcome(await store.ArchiveTemplate(Identity(http), id, request.ExpectedRevision, ct), archive: true));
templates.MapGet("/{id:guid}/preview", async (Guid id, int revision, Guid? groupId, HttpContext http, CancellationToken ct) =>
{
    if (revision < 1 || groupId == Guid.Empty || http.Request.Query.Any(entry => entry.Key is not ("revision" or "groupId") || entry.Value.Count != 1))
        return Results.BadRequest(new { error = "Choose a template revision and one destination." });
    return await store.CompareTemplate(Identity(http).OrganizationId, id, revision, groupId, ct) is { } preview
        ? Results.Ok(preview) : Results.NotFound();
});
templates.MapPost("/{id:guid}/apply", async (Guid id, ApplyPolicyTemplate request, HttpContext http, CancellationToken ct) =>
{
    if (request.Revision < 1 || request.ExpectedVersion < 1 || request.GroupId == Guid.Empty)
        return Results.BadRequest(new { error = "Review a template revision against a current policy before applying." });
    return PolicyOutcome(await store.ChangePolicy(Identity(http), null, null, ExpectsReview(http), ct, request.GroupId,
        template: (id, request.Revision, request.ExpectedVersion)), Results.Conflict(new { code = "template_target_changed" }));
});
var reviews = admin.MapGroup("/policy-reviews");
admin.MapGet("/prompt-exception-requests", async (HttpContext http, CancellationToken ct) =>
{
    var query = http.Request.Query;
    var status = query["status"].ToString();
    if (query.Any(entry => entry.Key != "status" || entry.Value.Count != 1) ||
        (query.ContainsKey("status") && status is not ("pending" or "decided")))
        return Results.BadRequest(new { error = "Choose pending or decided requests." });
    return Results.Ok(await store.PromptExceptionRequests(Identity(http).OrganizationId, status != "decided", ct));
});
admin.MapPost("/prompt-exception-requests/{id:guid}/decision", async (Guid id, DecidePromptException request, HttpContext http, CancellationToken ct) =>
{
    if (id == Guid.Empty || request.Status is not ("declined" or "exception_available")) return Results.BadRequest();
    var result = await store.DecideException(Identity(http), id, request.Status, ct);
    return result.Receipt is { } receipt ? Results.Ok(receipt) : result.Error is { } error
        ? Results.Conflict(new { code = error }) : Results.NotFound();
});
reviews.MapGet("", async (HttpContext http, CancellationToken ct) =>
    Results.Ok(await store.PolicyReviews(Identity(http).OrganizationId, ct)));
reviews.MapPost("/setting", async (SetPolicyReview request, HttpContext http, CancellationToken ct) =>
{
    var identity = Identity(http);
    if (identity.Role != AccessRoles.Owner) return Results.StatusCode(StatusCodes.Status403Forbidden);
    if (request.Required is not { } required) return Results.BadRequest();
    await store.SetPolicyReviewRequired(identity, required, ct);
    return Results.NoContent();
});
reviews.MapPost("/{id:guid}/decision", async (Guid id, ChoosePolicyReview request, HttpContext http, CancellationToken ct) =>
{
    if (request.Approve is not { } approve) return Results.BadRequest();
    return PolicyOutcome(await store.DecidePolicyReview(Identity(http), id, approve, ct), Results.NoContent());
});
var groups = admin.MapGroup("/policy-groups");
groups.MapGet("", async (HttpContext http, CancellationToken ct) => Results.Ok(await store.Groups(Identity(http).OrganizationId, ct)));
groups.MapPost("", async (CreatePolicyGroup request, HttpContext http, CancellationToken ct) =>
{
    var name = request.Name?.Trim();
    if (name is not { Length: >= 2 and <= 64 } || name.Any(char.IsControl))
        return Results.BadRequest(new { error = "Enter a group name from 2 to 64 characters." });
    return await store.CreateGroup(Identity(http), name, ct) is { } group
        ? Results.Ok(group) : Results.Conflict(new { error = "A group with this name already exists." });
});
groups.MapGet("/{groupId:guid}/policies", async (Guid groupId, HttpContext http, CancellationToken ct) =>
    Results.Ok(await store.PolicyHistory(Identity(http).OrganizationId, ct, groupId)));
groups.MapPost("/{groupId:guid}/policies", async (Guid groupId, PublishPolicy request, HttpContext http, CancellationToken ct) =>
    await PublishSettings(request, http, ct, groupId));
groups.MapPost("/{groupId:guid}/policies/{version:int}/restore", async (Guid groupId, int version, HttpContext http, CancellationToken ct) =>
    PolicyOutcome(await store.ChangePolicy(Identity(http), null, version, ExpectsReview(http), ct, groupId), Results.NotFound()));
groups.MapPost("/{groupId:guid}/promote", async (Guid groupId, PromotePolicyGroup request, HttpContext http, CancellationToken ct) =>
{
    if (request.ExpectedVersion <= 0 || request.ExpectedBaselineVersion is <= 0)
        return Results.BadRequest(new { error = "Choose the group and baseline versions you reviewed." });
    return PolicyOutcome(await store.ChangePolicy(Identity(http), null, null, ExpectsReview(http), ct, sourceGroupId: groupId,
        expectedSourceVersion: request.ExpectedVersion, expectedBaselineVersion: request.ExpectedBaselineVersion),
        Results.Conflict(new { error = "The reviewed group or baseline version is no longer current or available." }));
});
admin.MapPost("/installations/{id:guid}/policy-group", async (Guid id, AssignPolicyGroup request, HttpContext http, CancellationToken ct) =>
    await store.AssignGroup(Identity(http), id, request.GroupId, ct) switch
    {
        "assigned" => Results.NoContent(),
        "upgrade_required" => Results.Conflict(new { error = "Update this browser to Zekvar Browser v0.8.0 before moving it." }),
        _ => Results.NotFound()
    });
admin.MapGet("/events", async (string? appId, string? decision, DateTimeOffset? since, string? rolloutGroup,
    string? triageStatus, string? triageAssignee, HttpContext http, CancellationToken ct) =>
{
    if (http.Request.Query["rolloutGroup"].Count > 1 || EventRolloutFilter.Parse(rolloutGroup) is null)
        return Results.BadRequest(new { error = "Choose a valid event rollout group." });
    var filters = new EventFilters(appId, decision, since, null, null, rolloutGroup, triageStatus, triageAssignee);
    if (!filters.ValidTriage() || RepeatedTriageFilters(http.Request.Query))
        return Results.BadRequest(new { error = "Choose valid event triage filters." });
    http.Response.Headers["X-Zekvar-Event-Triage"] = "1";
    return Results.Ok((await store.EventHistory(Identity(http).OrganizationId, filters, null, ct)).Entries);
});
admin.MapGet("/events/history", async ([AsParameters] EventFilters filters, DateTimeOffset? beforeAt,
    Guid? beforeEventId, Guid? beforeInstallationId, HttpContext http, CancellationToken ct) =>
{
    if (!filters.Valid() || http.Request.Query["rolloutGroup"].Count > 1 || RepeatedTriageFilters(http.Request.Query) ||
        beforeAt.HasValue != beforeEventId.HasValue || beforeAt.HasValue != beforeInstallationId.HasValue ||
        beforeEventId == Guid.Empty || beforeInstallationId == Guid.Empty)
        return Results.BadRequest(new { error = "Choose valid event filters and a complete history cursor." });
    var cursor = beforeAt is { } at && beforeEventId is { } id && beforeInstallationId is { } installationId
        ? new EventCursor(at, id, installationId) : null;
    http.Response.Headers["X-Zekvar-Event-Rollout"] = "1";
    http.Response.Headers["X-Zekvar-Event-Triage"] = "1";
    return Results.Ok(await store.EventHistory(Identity(http).OrganizationId, filters, cursor, ct));
});
admin.MapGet("/events/export", ([AsParameters] EventFilters filters, HttpContext http, CancellationToken ct) =>
{
    if (!filters.Valid() || http.Request.Query["rolloutGroup"].Count > 1 || RepeatedTriageFilters(http.Request.Query))
        return Results.BadRequest(new { error = "Choose valid event filters." });
    var identity = Identity(http);
    http.Response.Headers.ContentDisposition = "attachment; filename=\"zekvar-security-events.json\"";
    http.Response.Headers.XContentTypeOptions = "nosniff";
    http.Response.Headers["X-Zekvar-Event-Rollout"] = "1";
    http.Response.Headers["X-Zekvar-Event-Triage"] = "1";
    return Results.Ok(new EventExport(identity.OrganizationSlug!, DateTime.UtcNow, filters,
        store.ReadEvents(identity.OrganizationId, filters, null, null, ct)));
});
admin.MapGet("/events/triage-assignees", async (HttpContext http, CancellationToken ct) =>
    Results.Ok(await store.EventTriageAssignees(Identity(http).OrganizationId, ct)));
admin.MapGet("/events/{installationId:guid}/{eventId:guid}", async (Guid installationId, Guid eventId, HttpContext http, CancellationToken ct) =>
    await store.EventDetail(Identity(http).OrganizationId, installationId, eventId, ct) is { } detail
        ? Results.Ok(detail) : Results.NotFound());
admin.MapPost("/events/{installationId:guid}/{eventId:guid}/triage",
    async (Guid installationId, Guid eventId, SetEventTriage request, HttpContext http, CancellationToken ct) =>
{
    if (!request.IsValid()) return Results.BadRequest(new { error = "Choose a valid triage status, resolution, and revision." });
    var result = await store.ChangeEventTriage(Identity(http), installationId, eventId, request, ct);
    return result switch
    {
        { Error: "event_triage_stale" } => Results.Conflict(new { code = result.Error }),
        { Error: "event_assignee_unavailable" } => Results.BadRequest(new { code = result.Error }),
        { Triage: { } triage } => Results.Ok(triage),
        _ => Results.NotFound()
    };
});
var cases = admin.MapGroup("/cases");
cases.MapGet("", async (string? status, bool? openOnly, DateTimeOffset? beforeAt, Guid? beforeId, HttpContext http, CancellationToken ct) =>
{
    if ((status is not null && !TriageStatus.IsValid(status)) || beforeAt.HasValue != beforeId.HasValue || beforeId == Guid.Empty ||
        http.Request.Query.Any(entry => entry.Value.Count != 1 || entry.Key is not ("status" or "openOnly" or "beforeAt" or "beforeId")))
        return Results.BadRequest(new { error = "Choose valid case filters and a complete cursor." });
    var cursor = beforeAt is { } at && beforeId is { } id ? new IncidentCaseCursor(at, id) : null;
    return Results.Ok(await store.IncidentCases(Identity(http).OrganizationId, status, openOnly == true, cursor, ct));
});
cases.MapGet("/{id:guid}", async (Guid id, HttpContext http, CancellationToken ct) =>
    await store.IncidentCaseDetail(Identity(http).OrganizationId, id, ct) is { } detail
        ? Results.Ok(detail) : Results.NotFound());
cases.MapGet("/{id:guid}/export", async (Guid id, HttpContext http, CancellationToken ct) =>
{
    var identity = Identity(http);
    if (await store.IncidentCaseDetail(identity.OrganizationId, id, ct) is not { } detail) return Results.NotFound();
    http.Response.Headers.ContentDisposition = $"attachment; filename=\"zekvar-case-{id:D}.json\"";
    http.Response.Headers.XContentTypeOptions = "nosniff";
    return Results.Ok(new { organization = identity.OrganizationSlug, exportedAt = DateTime.UtcNow, investigation = detail });
});
cases.MapPost("", async (CreateIncidentCase request, HttpContext http, CancellationToken ct) =>
    request.IsValid() ? CaseOutcome(await store.CreateIncidentCase(Identity(http), request, ct)) :
        Results.BadRequest(new { error = "Choose a valid case category and a security event." }));
cases.MapPost("/{id:guid}/triage", async (Guid id, SetEventTriage request, HttpContext http, CancellationToken ct) =>
    request.IsValid() && request.ExpectedRevision >= 1 ? CaseOutcome(await store.ChangeCaseTriage(Identity(http), id, request, ct)) :
        Results.BadRequest(new { error = "Choose a valid case status, resolution, and revision." }));
cases.MapPost("/{id:guid}/membership", async (Guid id, SetCaseMembership request, HttpContext http, CancellationToken ct) =>
    request.IsValid() ? CaseOutcome(await store.ChangeCaseMembership(Identity(http), id, request, ct)) :
        Results.BadRequest(new { error = "Choose a valid case revision and event." }));
var alerts = admin.MapGroup("/alerts");
alerts.MapGet("/settings", async (HttpContext http, CancellationToken ct) =>
    Results.Ok(await store.GetSecurityAlertSettings(Identity(http).OrganizationId, ct)));
alerts.MapPost("/settings", async (SetSecurityAlertSettings request, HttpContext http, CancellationToken ct) =>
{
    if (!request.IsValid()) return Results.BadRequest(new { error = "Choose an alert mode, a threshold from 2 to 100, and a settings revision." });
    return await store.UpdateSecurityAlertSettings(Identity(http), request, ct) is { } settings
        ? Results.Ok(settings) : Results.Conflict(new { code = "alert_settings_changed" });
});
alerts.MapGet("", async (string? appId, string? status, DateTimeOffset? beforeAt, Guid? beforeId, HttpContext http, CancellationToken ct) =>
{
    if ((appId is not null && !FixtureContract.IsAiPromptApp(appId)) || status is not (null or "open" or "acknowledged") ||
        beforeAt.HasValue != beforeId.HasValue || beforeId == Guid.Empty ||
        http.Request.Query.Any(entry => entry.Value.Count != 1 || entry.Key is not ("appId" or "status" or "beforeAt" or "beforeId")))
        return Results.BadRequest(new { error = "Choose a supported app, alert status, and complete cursor." });
    var cursor = beforeAt is { } at && beforeId is { } id ? new SecurityAlertCursor(at, id) : null;
    return Results.Ok(await store.SecurityAlerts(Identity(http).OrganizationId, appId, status, cursor, ct));
});
alerts.MapGet("/{id:guid}", async (Guid id, DateTimeOffset? beforeAt, Guid? beforeEventId, Guid? beforeInstallationId,
    HttpContext http, CancellationToken ct) =>
{
    var cursor = beforeAt is { } at && beforeEventId is { } eventId && beforeInstallationId is { } installationId
        && eventId != Guid.Empty && installationId != Guid.Empty ? new EventCursor(at, eventId, installationId) : null;
    if ((cursor is null && (beforeAt.HasValue || beforeEventId.HasValue || beforeInstallationId.HasValue)) ||
        http.Request.Query.Any(entry => entry.Value.Count != 1 || entry.Key is not ("beforeAt" or "beforeEventId" or "beforeInstallationId")))
        return Results.BadRequest(new { error = "Choose a complete evidence cursor." });
    return await store.SecurityAlertDetail(Identity(http).OrganizationId, id, cursor, ct) is { } detail
        ? Results.Ok(detail) : Results.NotFound();
});
alerts.MapPost("/{id:guid}/acknowledge", async (Guid id, HttpContext http, CancellationToken ct) =>
    await store.AcknowledgeSecurityAlert(Identity(http), id, ct) ? Results.NoContent() : Results.NotFound());
var extensionAlerts = alerts.MapGroup("/extensions");
extensionAlerts.MapGet("/settings", async (HttpContext http, CancellationToken ct) =>
    Results.Ok(await store.GetExtensionAccessSettings(Identity(http).OrganizationId, ct)));
extensionAlerts.MapPost("/settings", async (SetExtensionAccessSettings request, HttpContext http, CancellationToken ct) =>
{
    if (!request.IsValid()) return Results.BadRequest(new { error = "Choose an alert mode and a settings revision." });
    return await store.UpdateExtensionAccessSettings(Identity(http), request, ct) is { } settings
        ? Results.Ok(settings) : Results.Conflict(new { code = "alert_settings_changed" });
});
extensionAlerts.MapGet("", async (string? status, DateTimeOffset? beforeAt, Guid? beforeId, HttpContext http, CancellationToken ct) =>
{
    if (status is not (null or "open" or "acknowledged") || beforeAt.HasValue != beforeId.HasValue || beforeId == Guid.Empty ||
        http.Request.Query.Any(entry => entry.Value.Count != 1 || entry.Key is not ("status" or "beforeAt" or "beforeId")))
        return Results.BadRequest(new { error = "Choose a valid alert status and a complete cursor." });
    var cursor = beforeAt is { } at && beforeId is { } id ? new SecurityAlertCursor(at, id) : null;
    return Results.Ok(await store.ExtensionAccessAlerts(Identity(http).OrganizationId, status, cursor, ct));
});
extensionAlerts.MapGet("/{id:guid}", async (Guid id, HttpContext http, CancellationToken ct) =>
    await store.ExtensionAccessAlertDetails(Identity(http).OrganizationId, id, ct) is { } detail
        ? Results.Ok(detail) : Results.NotFound());
extensionAlerts.MapPost("/{id:guid}/acknowledge", async (Guid id, HttpContext http, CancellationToken ct) =>
    await store.AcknowledgeExtensionAccessAlert(Identity(http), id, ct) ? Results.NoContent() : Results.NotFound());
admin.MapGet("/reports/ai-enforcement", async (HttpContext http, CancellationToken ct) =>
{
    var query = AiReportQuery.Parse(http.Request.Query, DateTimeOffset.UtcNow);
    return query is null
        ? Results.BadRequest(new { error = "Choose a supported AI app, reporting window, and rollout group." })
        : Results.Ok(await store.ReadAiEnforcement(Identity(http), query, ct));
});
admin.MapGet("/audit", async (string? action, DateTimeOffset? since, DateTimeOffset? until, DateTimeOffset? beforeAt,
    Guid? beforeId, int? limit, HttpContext http, CancellationToken ct) =>
{
    var filters = new AuditFilters(action, since, until, beforeAt, beforeId, limit ?? 100);
    return filters.IsValid
        ? Results.Ok(await store.AuditHistory(Identity(http).OrganizationId, filters, ct))
        : Results.BadRequest(new { error = "Choose a valid audit action, time range, cursor, and limit." });
});
admin.MapGet("/retention", async (HttpContext http, CancellationToken ct) =>
    Results.Ok(await store.GetRetention(Identity(http).OrganizationId, ct)));
admin.MapPost("/retention", async (RetentionPolicy policy, HttpContext http, CancellationToken ct) =>
{
    if (!policy.IsValid()) return Results.BadRequest(new { error = "Choose retention windows from 1 to 3650 days or no expiry." });
    await store.SetRetention(Identity(http), policy, ct);
    return Results.NoContent();
});
admin.MapPost("/retention/cleanup", async (HttpContext http, CancellationToken ct) =>
    Results.Ok(await store.CleanupRetention(Identity(http).OrganizationId, scheduled: false, ct, Identity(http).Access?.Id)));
admin.MapGet("/ai-apps", async (HttpContext http, CancellationToken ct) =>
    Results.Ok(await store.DiscoveredApps(Identity(http).OrganizationId, ct)));
admin.MapPost("/ai-apps/{appId}/classification", async (string appId, ClassifyApp request, HttpContext http, CancellationToken ct) =>
{
    if (!DiscoveryCatalog.IsApp(appId) || !DiscoveryCatalog.IsStatus(request.Status))
        return Results.BadRequest(new { error = "Choose a cataloged app and a valid classification." });
    return await store.ClassifyApp(Identity(http), appId, request.Status, ct) ? Results.NoContent() : Results.NotFound();
});

app.MapPost("/v1/enroll", async (RedeemGrant request, HttpContext http, CancellationToken ct) =>
    Tokens.IsValid(request.Grant) && await store.Enroll(request.Grant, http.Request.Headers["X-Zekvar-Scoped-Enrollment"] == "1", ct) is { } enrollment
        ? Results.Ok(enrollment) : Results.Unauthorized());

var browser = app.MapGroup("/v1/browser").AddEndpointFilter(Authenticate(browser: true));
browser.MapGet("/policy", async (HttpContext http, CancellationToken ct) =>
{
    var aware = http.Request.Headers["X-Zekvar-Assignment-Aware"] == "1";
    var claudeAware = http.Request.Headers["X-Zekvar-Claude-Prompt"] == "1";
    var privateKeyAware = http.Request.Headers["X-Zekvar-Private-Key"] == "1";
    var fileInspectionAware = http.Request.Headers["X-Zekvar-File-Inspection"] == "1";
    var fileBlockAware = fileInspectionAware && http.Request.Headers["X-Zekvar-File-Content-Block"] == "1";
    var aiAppAccessAware = http.Request.Headers["X-Zekvar-AI-App-Access"] == "1";
    var identifiersAware = http.Request.Headers["X-Zekvar-Identifiers"] == "1";
    var presetDiscoveryAware = aware && http.Request.Headers["X-Zekvar-Preset-Discovery"] == "1";
    var ssnAware = http.Request.Headers["X-Zekvar-SSN"] == "1";
    var clipboardAware = aware && http.Request.Headers["X-Zekvar-Clipboard-Paste"] == "1";
    var githubTokenAware = aware && http.Request.Headers["X-Zekvar-GitHub-Token"] == "1";
    var promptAppModesAware = aware && http.Request.Headers["X-Zekvar-Prompt-App-Modes"] == "1";
    var claudeFilesAware = aware && claudeAware && fileBlockAware && http.Request.Headers["X-Zekvar-Claude-Files"] == "1";
    var detectionRulesAware = aware && http.Request.Headers["X-Zekvar-Detection-Rules"] == "1";
    var versionHeader = http.Request.Headers["X-Zekvar-Extension-Version"];
    var extensionVersion = versionHeader.Count == 1 ? BrowserRelease.ReadVersion(versionHeader[0]) : null;
    if (await store.CurrentPolicy(Identity(http).InstallationId!.Value, aware, claudeAware, extensionVersion, privateKeyAware,
        fileInspectionAware, aiAppAccessAware, fileBlockAware, identifiersAware, presetDiscoveryAware, ssnAware, clipboardAware, githubTokenAware,
        promptAppModesAware, claudeFilesAware, detectionRulesAware, ct) is { } policy)
        return Results.Ok(policy.ForBrowser(claudeAware, privateKeyAware, fileInspectionAware, aiAppAccessAware, fileBlockAware, identifiersAware,
            presetDiscoveryAware, ssnAware, clipboardAware, githubTokenAware, promptAppModesAware, claudeFilesAware, detectionRulesAware) with
        {
            PromptExceptionRequestsAvailable = aware && http.Request.Headers["X-Zekvar-Prompt-Exception-Requests"] == "1" ? true : null
        });
    return aware ? Results.Unauthorized() : Results.Conflict(new { error = "Update the browser to receive the assigned policy." });
});
browser.MapPost("/heartbeat", async (Heartbeat request, HttpContext http, CancellationToken ct) =>
    request.IsValid() &&
    await store.RecordHeartbeat(Identity(http).InstallationId!.Value, request, http.Request.Headers["X-Zekvar-Composer-Coverage"] == "1", ct)
        ? Results.NoContent() : Results.BadRequest(new { error = "Policy or browser enforcement could not be acknowledged." }));
browser.MapPost("/events", async (PolicyEvent request, HttpContext http, CancellationToken ct) =>
    FixtureContract.IsEvent(request) && await store.Ingest(Identity(http).InstallationId!.Value, request, ct)
        ? Results.NoContent() : Results.BadRequest(new { error = "Invalid policy event." }));
browser.MapPost("/prompt-exception-requests", async (RequestPromptException request, HttpContext http, CancellationToken ct) =>
{
    if (request.EventId == Guid.Empty || !FixtureContract.IsAiPromptApp(request.AppId)) return Results.BadRequest();
    return await store.RequestException(Identity(http), request, ct) is { } receipt ? Results.Ok(receipt) : Results.NotFound();
});
browser.MapPost("/ai-app-observations", async (AppObservation request, HttpContext http, CancellationToken ct) =>
    DiscoveryCatalog.IsApp(request.AppId) && request.PolicyVersion > 0 &&
    await store.ObserveApp(Identity(http).InstallationId!.Value, request, ct)
        ? Results.NoContent() : Results.BadRequest(new { error = "Invalid app observation or discovery disabled." }));
browser.MapPost("/extension-inventory", async (ReportExtensionInventory request, HttpContext http, CancellationToken ct) =>
{
    if (!request.IsValid(DateTimeOffset.UtcNow)) return Results.BadRequest(new { error = "Invalid extension inventory report." });
    return await store.ReportInventory(Identity(http).InstallationId!.Value, request, ct)
        ? Results.NoContent() : Results.Conflict(new { error = "The inventory report does not match the current enabled policy." });
});

await app.RunAsync();

async Task<IResult> PublishSettings(PublishPolicy request, HttpContext http, CancellationToken ct, Guid? groupId = null)
{
    if (request.ExpectedVersion is <= 0) return Results.BadRequest(new { error = "Choose a valid expected policy version." });
    if (request.RequireComposerReady is { } apps &&
        (!request.ExpectedVersion.HasValue || apps.Length == 0 || apps.Length > DiscoveryCatalog.ComposerAppIds.Length ||
            apps.Distinct(StringComparer.Ordinal).Count() != apps.Length || apps.Any(app => !DiscoveryCatalog.ComposerAppIds.Contains(app))))
        return Results.BadRequest(new { code = "invalid_composer_gate" });
    if (!(FixtureContract.IsMode(request.Mode) ||
          request.Mode is null && (request.DomainRules is not null || request.PaymentCardMode is not null ||
              request.PathRules is not null || request.UploadModes?.HasSettings() == true ||
              request.UploadTypes?.HasSettings() == true || request.ExtensionInventoryEnabled.HasValue || request.CustomApps is not null ||
              request.PromptExceptions is not null || request.ClaudePromptEnabled.HasValue || request.PrivateKeyMode is not null ||
              request.FileInspection?.HasSettings() == true || request.ExtensionDeployment is not null ||
              request.BlockedAiAppHosts is not null || request.FileContentModes?.HasSettings() == true ||
              request.IdentifierProtection is not null || request.PresetDiscoveryEnabled.HasValue || request.SsnMode is not null ||
              request.BrowserHardening is not null || request.ClipboardMode is not null || request.GithubTokenMode is not null ||
              request.PromptAppModes is not null || request.CloudCredentialMode is not null || request.ClassificationProtection is not null)) ||
        !FixtureContract.IsOptionalDetectorMode(request.GithubPatMode) || !FixtureContract.IsOptionalDetectorMode(request.PaymentCardMode) ||
        !FixtureContract.IsOptionalDetectorMode(request.PrivateKeyMode) || !FixtureContract.IsOptionalDetectorMode(request.SsnMode) ||
        !FixtureContract.IsOptionalDetectorMode(request.GithubTokenMode) || !FixtureContract.IsOptionalDetectorMode(request.CloudCredentialMode))
        return Results.BadRequest(new { error = "Choose a valid rule mode." });
    if (request.UploadModes?.IsValid() == false)
        return Results.BadRequest(new { error = "Choose Off, Monitor, or Block for each upload destination." });
    if (request.FileContentModes?.IsValid() == false)
        return Results.BadRequest(new { error = "Choose Off, Monitor, or Block for file contents on each supported app." });
    if (request.ClipboardMode is not null && !FixtureContract.IsClipboardMode(request.ClipboardMode))
        return Results.BadRequest(new { error = "Choose Off, Monitor, or Block for clipboard paste protection." });
    if (request.PromptAppModes?.Valid() == false)
        return Results.BadRequest(new { error = "Choose Monitor, Warn, Block, or inherit for each AI app prompt mode." });
    if (!UploadTypes.TryNormalize(request.UploadTypes, out var uploadTypes))
        return Results.BadRequest(new { error = "Enter up to 25 valid file extensions or media types per app, with at most 64 characters per type." });
    if (!CustomApps.TryNormalize(request.CustomApps, out var customApps))
        return Results.BadRequest(new { error = "Enter up to 25 unique app hostnames and names. Built-in domains are reserved." });
    if (!PromptException.TryNormalize(request.PromptExceptions, DateTimeOffset.UtcNow, out var exceptions))
        return Results.BadRequest(new { error = "Use one prompt exception per app and detector, with a reason and an expiry within 24 hours." });
    if (!DomainRules.TryNormalize(request.DomainRules, out var domainRules))
        return Results.BadRequest(new { error = "Enter up to 50 domains with no domain in both lists." });
    if (!PathRules.TryNormalize(request.PathRules, out var pathRules))
        return Results.BadRequest(new { error = "Use distinct hostname/path prefixes with paths up to 64 characters long." });
    if (!ExtensionDeployment.TryNormalize(request.ExtensionDeployment, out var extensionDeployment) ||
        (extensionDeployment is not null && request.ExpectedVersion is null))
        return Results.BadRequest(new { error = "Use a current policy version, distinct Chrome extension IDs, and HTTPS update manifest URLs for force installs." });
    if (request.BrowserHardening is { } hardening && (!hardening.IsValid() || request.ExpectedVersion is null))
        return Results.BadRequest(new { error = "Use a current policy version and supported Chrome hardening settings." });
    if (!AiAppAccess.TryNormalize(request.BlockedAiAppHosts, out var blockedAiAppHosts))
        return Results.BadRequest(new { error = "Select distinct AI app hostnames from the policy catalog." });
    if (!IdentifierProtection.TryNormalize(request.IdentifierProtection, out var identifiers))
        return Results.BadRequest(new { error = "Use a valid identifier mode and up to 16 distinct prefixes with 4 to 12 suffix digits." });
    if (!ClassificationProtection.TryNormalize(request.ClassificationProtection, out var classification))
        return Results.BadRequest(new { error = "Use a valid classification mode and up to 16 distinct labels or phrases of 3 to 64 supported characters." });
    var normalized = request with { DomainRules = domainRules, PathRules = pathRules, UploadTypes = uploadTypes,
        ExtensionDeployment = extensionDeployment, BlockedAiAppHosts = blockedAiAppHosts, IdentifierProtection = identifiers,
        ClassificationProtection = classification };
    var result = await store.ChangePolicy(Identity(http), normalized, null, ExpectsReview(http), ct, groupId,
        customApps: customApps, promptExceptions: exceptions);
    return PolicyOutcome(result, request.ExpectedVersion.HasValue
        ? Results.Conflict(new { error = "The policy changed after preview or is unavailable." }) : Results.NotFound());
}

static bool ExpectsReview(HttpContext http) => http.Request.Headers["X-Zekvar-Expect-Review"] == "1";
static bool RepeatedTriageFilters(IQueryCollection query) => query["triageStatus"].Count > 1 || query["triageAssignee"].Count > 1;

static bool TryParseBrowserHealthFilter(IQueryCollection query, out BrowserHealthFilter filter)
{
    var group = query["rolloutGroup"];
    var version = query["browserVersion"];
    return BrowserHealthFilter.TryParse(group.FirstOrDefault(), version.FirstOrDefault(), out filter) &&
        group.Count <= 1 && version.Count <= 1;
}

static IResult InvalidBrowserHealthFilter() =>
    Results.BadRequest(new { error = "Choose a rollout group and enter an exact extension version or unreported." });

static IResult CaseOutcome(IncidentCaseResult result) => result switch
{
    { CaseId: { } id } => Results.Ok(new { caseId = id }),
    { Error: "event_assignee_unavailable" } => Results.BadRequest(new { code = result.Error }),
    { Error: { } code } => Results.Conflict(new { code }),
    _ => Results.NotFound()
};

static IResult PolicyOutcome(PolicyChangeResult result, IResult fallback)
{
    if (result.Policy is { } policy) return Results.Ok(policy);
    if (result.ReviewId is { } id) return Results.Accepted(value: new { reviewId = id });
    var code = result.Error;
    return code switch
    {
        "navigation_rule_limit" => Results.BadRequest(new { error = "A policy can contain up to 50 domain, path, and AI app access rules combined.", code }),
        "ai_app_access_unknown_host" => Results.BadRequest(new { error = "Clear the access block for each removed AI app host or keep it in the policy catalog.", code }),
        "exception_expired" => Results.BadRequest(new { error = "Choose a future expiry for each new or changed exception.", code }),
        "review_unavailable" or "template_unavailable" => Results.NotFound(),
        "named_administrator_required" or "self_approval" => Results.Json(new { code }, statusCode: StatusCodes.Status403Forbidden),
        "review_mode_changed" or "review_closed" or "review_stale" or "composer_coverage_incomplete" => Results.Conflict(new { code }),
        _ => fallback
    };
}

static IResult TemplateOutcome(PolicyTemplateResult result, bool archive = false)
{
    if (result.Template is { } template) return archive ? Results.NoContent() : Results.Ok(template);
    return result.Error is "template_unavailable" or "template_source_unavailable"
        ? Results.NotFound(new { code = result.Error }) : Results.Conflict(new { code = result.Error });
}

Func<EndpointFilterInvocationContext, EndpointFilterDelegate, ValueTask<object?>> Authenticate(bool browser) =>
    async (context, next) =>
{
    var http = context.HttpContext;
    if (BearerToken(http) is not { } token || await store.Authenticate(token, browser, http.RequestAborted) is not { } identity)
    {
        http.Response.Headers.WWWAuthenticate = "Bearer";
        return Results.Unauthorized();
    }
    if (identity.Role == AccessRoles.Auditor && !HttpMethods.IsGet(http.Request.Method) && !HttpMethods.IsHead(http.Request.Method))
        return Results.StatusCode(StatusCodes.Status403Forbidden);
    http.Items[typeof(RequestIdentity)] = identity;
    return await next(context);
};

static IResult RejectEventFeed(HttpContext http)
{
    http.Response.Headers.WWWAuthenticate = "Bearer";
    return Results.Unauthorized();
}

static string? ParseBearer(HttpContext http) => AuthenticationHeaderValue.TryParse(http.Request.Headers.Authorization, out var auth) &&
    auth.Scheme.Equals("Bearer", StringComparison.OrdinalIgnoreCase) ? auth.Parameter : null;

static string? BearerToken(HttpContext http) => ParseBearer(http) is { } token && Tokens.IsValid(token) ? token : null;

static RequestIdentity Identity(HttpContext http) => (RequestIdentity)http.Items[typeof(RequestIdentity)]!;

static bool ValidOrganization(DemoOrganization org) => org.Slug is { Length: > 0 and <= 63 } &&
    org.Slug.All(character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-') &&
    Tokens.IsValid(org.AdminToken);
