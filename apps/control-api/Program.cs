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

builder.WebHost.ConfigureKestrel(options =>
{
    options.Listen(IPAddress.Loopback, port);
    options.Limits.MaxRequestBodySize = 16 * 1024;
});
builder.Services.Configure<RouteHandlerOptions>(options => options.ThrowOnBadRequest = false);
builder.Services.ConfigureHttpJsonOptions(options =>
    options.SerializerOptions.UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow);
builder.Services.AddSingleton(_ => NpgsqlDataSource.Create(connectionString));
builder.Services.AddSingleton(services => new ControlStore(services.GetRequiredService<NpgsqlDataSource>(), sso));
builder.Services.AddHostedService<RetentionSweep>(services => new(services.GetRequiredService<ControlStore>(),
    services.GetRequiredService<ILogger<RetentionSweep>>(), TimeSpan.FromSeconds(sweepSeconds)));

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
access.MapGet("/sso", (HttpContext http) => sso is not null && Identity(http).OrganizationSlug == sso.OrganizationSlug
    ? Results.Ok(new { sso.Issuer }) : Results.NoContent());
access.MapPost("/sso", async (AddSsoIdentity request, HttpContext http, CancellationToken ct) =>
{
    var identity = Identity(http);
    if (sso is null || identity.OrganizationSlug != sso.OrganizationSlug) return Results.NotFound();
    var name = request.Name?.Trim();
    if (name is not { Length: >= 2 and <= 64 } || name.Any(char.IsControl) ||
        !AccessRoles.IsDelegated(request.Role) || !ControlSso.ValidSubject(request.Subject))
        return Results.BadRequest(new { error = "Enter a name, delegated role, and exact OIDC subject." });
    var added = await store.AddSsoIdentity(identity.OrganizationId, sso.Issuer, request.Subject!, name, request.Role!, ct);
    return added is not null ? Results.Ok(added) : Results.Conflict(new { code = "sso_subject_exists" });
});

app.MapPost("/v1/internal/sso/session", async (ExchangeSsoIdentity request, HttpContext http, CancellationToken ct) =>
{
    if (sso is null) return Results.NotFound();
    if (BearerToken(http) is not { } token || !sso.Authorizes(token)) return Results.Unauthorized();
    if (request.Issuer != sso.Issuer || !ControlSso.ValidSubject(request.Subject) || request.ExpiresAt <= DateTimeOffset.UtcNow)
        return Results.Unauthorized();
    return await store.ExchangeSsoIdentity(sso, request.Subject!, request.ExpiresAt, ct) is { } session
        ? Results.Ok(session) : Results.Unauthorized();
});
app.MapDelete("/v1/internal/sso/session", async (HttpContext http, CancellationToken ct) =>
{
    if (sso is null) return Results.NotFound();
    if (BearerToken(http) is not { } token) return Results.Unauthorized();
    await store.EndSsoSession(token, sso.BridgeHash, ct);
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
admin.MapGet("/browser-releases", async (HttpContext http, CancellationToken ct) =>
    Results.Ok(await store.BrowserReleases(Identity(http).OrganizationId, ct)));
admin.MapGet("/browser-health", async (HttpContext http, CancellationToken ct) =>
{
    var group = http.Request.Query["rolloutGroup"];
    var version = http.Request.Query["browserVersion"];
    if (group.Count > 1 || version.Count > 1 || !BrowserHealthFilter.TryParse(group.FirstOrDefault(), version.FirstOrDefault(), out var filter))
        return Results.BadRequest(new { error = "Choose a rollout group and enter an exact extension version or unreported." });
    return await store.BrowserHealth(Identity(http).OrganizationId, filter, ct) is { } health
        ? Results.Ok(health) : Results.NotFound();
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
var reviews = admin.MapGroup("/policy-reviews");
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
    if (request.ExpectedVersion <= 0) return Results.BadRequest(new { error = "Choose the group version you reviewed." });
    return PolicyOutcome(await store.ChangePolicy(Identity(http), null, null, ExpectsReview(http), ct, sourceGroupId: groupId,
        expectedSourceVersion: request.ExpectedVersion), Results.Conflict(new { error = "The reviewed group version is no longer current or available." }));
});
admin.MapPost("/installations/{id:guid}/policy-group", async (Guid id, AssignPolicyGroup request, HttpContext http, CancellationToken ct) =>
    await store.AssignGroup(Identity(http), id, request.GroupId, ct) switch
    {
        "assigned" => Results.NoContent(),
        "upgrade_required" => Results.Conflict(new { error = "Update this browser to Zekvar Browser v0.8.0 before moving it." }),
        _ => Results.NotFound()
    });
admin.MapGet("/events", async (string? appId, string? decision, DateTimeOffset? since, HttpContext http, CancellationToken ct) =>
    Results.Ok((await store.EventHistory(Identity(http).OrganizationId, new(appId, decision, since, null, null), null, ct)).Entries));
admin.MapGet("/events/history", async ([AsParameters] EventFilters filters, DateTimeOffset? beforeAt,
    Guid? beforeEventId, Guid? beforeInstallationId, HttpContext http, CancellationToken ct) =>
{
    if (!filters.Valid() || beforeAt.HasValue != beforeEventId.HasValue || beforeAt.HasValue != beforeInstallationId.HasValue ||
        beforeEventId == Guid.Empty || beforeInstallationId == Guid.Empty)
        return Results.BadRequest(new { error = "Choose valid event filters and a complete history cursor." });
    var cursor = beforeAt is { } at && beforeEventId is { } id && beforeInstallationId is { } installationId
        ? new EventCursor(at, id, installationId) : null;
    return Results.Ok(await store.EventHistory(Identity(http).OrganizationId, filters, cursor, ct));
});
admin.MapGet("/events/export", ([AsParameters] EventFilters filters, HttpContext http, CancellationToken ct) =>
{
    if (!filters.Valid()) return Results.BadRequest(new { error = "Choose valid event filters." });
    var identity = Identity(http);
    http.Response.Headers.ContentDisposition = "attachment; filename=\"zekvar-security-events.json\"";
    http.Response.Headers.XContentTypeOptions = "nosniff";
    return Results.Ok(new EventExport(identity.OrganizationSlug!, DateTime.UtcNow, filters,
        store.ReadEvents(identity.OrganizationId, filters, null, null, ct)));
});
admin.MapGet("/reports/ai-enforcement", async (HttpContext http, CancellationToken ct) =>
{
    var query = AiReportQuery.Parse(http.Request.Query, DateTimeOffset.UtcNow);
    return query is null
        ? Results.BadRequest(new { error = "Choose a supported AI app and a 7- or 30-day reporting window." })
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
    var versionHeader = http.Request.Headers["X-Zekvar-Extension-Version"];
    var extensionVersion = versionHeader.Count == 1 ? BrowserRelease.ReadVersion(versionHeader[0]) : null;
    if (await store.CurrentPolicy(Identity(http).InstallationId!.Value, aware, claudeAware, extensionVersion, privateKeyAware, fileInspectionAware, ct) is { } policy)
        return Results.Ok(policy.ForBrowser(claudeAware, privateKeyAware, fileInspectionAware));
    return aware ? Results.Unauthorized() : Results.Conflict(new { error = "Update the browser to receive the assigned policy." });
});
browser.MapPost("/heartbeat", async (Heartbeat request, HttpContext http, CancellationToken ct) =>
    request.IsValid() &&
    await store.RecordHeartbeat(Identity(http).InstallationId!.Value, request, http.Request.Headers["X-Zekvar-Composer-Coverage"] == "1", ct)
        ? Results.NoContent() : Results.BadRequest(new { error = "Policy or browser enforcement could not be acknowledged." }));
browser.MapPost("/events", async (PolicyEvent request, HttpContext http, CancellationToken ct) =>
    FixtureContract.IsEvent(request) && await store.Ingest(Identity(http).InstallationId!.Value, request, ct)
        ? Results.NoContent() : Results.BadRequest(new { error = "Invalid policy event." }));
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
    if (!(FixtureContract.IsMode(request.Mode) ||
          request.Mode is null && (request.DomainRules is not null || request.PaymentCardMode is not null ||
              request.PathRules is not null || request.UploadModes?.HasSettings() == true ||
              request.UploadTypes?.HasSettings() == true || request.ExtensionInventoryEnabled.HasValue || request.CustomApps is not null ||
              request.PromptExceptions is not null || request.ClaudePromptEnabled.HasValue || request.PrivateKeyMode is not null ||
              request.FileInspection?.HasSettings() == true)) ||
        !FixtureContract.IsOptionalDetectorMode(request.GithubPatMode) || !FixtureContract.IsOptionalDetectorMode(request.PaymentCardMode) ||
        !FixtureContract.IsOptionalDetectorMode(request.PrivateKeyMode))
        return Results.BadRequest(new { error = "Choose a valid rule mode." });
    if (request.UploadModes?.IsValid() == false)
        return Results.BadRequest(new { error = "Choose Off, Monitor, or Block for each upload destination." });
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
    var normalized = request with { DomainRules = domainRules, PathRules = pathRules, UploadTypes = uploadTypes };
    var result = await store.ChangePolicy(Identity(http), normalized, null, ExpectsReview(http), ct, groupId,
        customApps: customApps, promptExceptions: exceptions);
    return PolicyOutcome(result, request.ExpectedVersion.HasValue
        ? Results.Conflict(new { error = "The policy changed after preview or is unavailable." }) : Results.NotFound());
}

static bool ExpectsReview(HttpContext http) => http.Request.Headers["X-Zekvar-Expect-Review"] == "1";

static IResult PolicyOutcome(PolicyChangeResult result, IResult fallback)
{
    if (result.Policy is { } policy) return Results.Ok(policy);
    if (result.ReviewId is { } id) return Results.Accepted(value: new { reviewId = id });
    var code = result.Error;
    return code switch
    {
        "navigation_rule_limit" => Results.BadRequest(new { error = "A policy can contain up to 50 domain and path rules combined." }),
        "exception_expired" => Results.BadRequest(new { error = "Choose a future expiry for each new or changed exception.", code }),
        "review_unavailable" => Results.NotFound(),
        "named_administrator_required" or "self_approval" => Results.Json(new { code }, statusCode: StatusCodes.Status403Forbidden),
        "review_mode_changed" or "review_closed" or "review_stale" => Results.Conflict(new { code }),
        _ => fallback
    };
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

static string? BearerToken(HttpContext http) => AuthenticationHeaderValue.TryParse(http.Request.Headers.Authorization, out var auth) &&
    auth.Scheme.Equals("Bearer", StringComparison.OrdinalIgnoreCase) && Tokens.IsValid(auth.Parameter) ? auth.Parameter : null;

static RequestIdentity Identity(HttpContext http) => (RequestIdentity)http.Items[typeof(RequestIdentity)]!;

static bool ValidOrganization(DemoOrganization org) => org.Slug is { Length: > 0 and <= 63 } &&
    org.Slug.All(character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-') &&
    Tokens.IsValid(org.AdminToken);
