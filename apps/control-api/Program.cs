using System.Net;
using System.Net.Http.Headers;
using System.Text.Json.Serialization;
using Control;
using Npgsql;

var builder = WebApplication.CreateBuilder(args);
if (!builder.Environment.IsDevelopment())
    throw new InvalidOperationException("The Control API demo requires the Development environment.");

var connectionString = builder.Configuration.GetConnectionString("Control")
    ?? throw new InvalidOperationException("Set ConnectionStrings__Control for the demo PostgreSQL database.");
var port = builder.Configuration.GetValue("Control:Port", 5187);
if (port is < 1024 or > 65535)
    throw new InvalidOperationException("Configure a Control loopback port between 1024 and 65535.");
var organizations = builder.Configuration.GetSection("Control:Organizations").Get<DemoOrganization[]>();
if (organizations is not { Length: > 0 } || organizations.Any(org => !ValidOrganization(org)) ||
    organizations.Select(org => org.Slug).Distinct().Count() != organizations.Length ||
    organizations.Select(org => org.AdminToken).Distinct().Count() != organizations.Length)
    throw new InvalidOperationException("Configure distinct organization slugs and 32-byte hex admin tokens.");

builder.WebHost.ConfigureKestrel(options =>
{
    options.Listen(IPAddress.Loopback, port);
    options.Limits.MaxRequestBodySize = 16 * 1024;
});
builder.Services.Configure<RouteHandlerOptions>(options => options.ThrowOnBadRequest = false);
builder.Services.ConfigureHttpJsonOptions(options =>
    options.SerializerOptions.UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow);
builder.Services.AddSingleton(_ => NpgsqlDataSource.Create(connectionString));
builder.Services.AddSingleton<ControlStore>();

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
    await next(context);
});

app.MapGet("/health", () => Results.Ok(new { status = "ready" }));

var admin = app.MapGroup("/v1/admin").AddEndpointFilter(Authenticate(browser: false));
admin.MapGet("/session", (HttpContext http) => Results.Ok(new { organization = Identity(http).OrganizationSlug }));
admin.MapPost("/enrollment-grants", async (HttpContext http, CancellationToken ct) =>
    Results.Ok(await store.CreateGrant(Identity(http).OrganizationId, ct)));
admin.MapGet("/installations", async (HttpContext http, CancellationToken ct) =>
    Results.Ok(await store.Installations(Identity(http).OrganizationId, ct)));
admin.MapPost("/installations/{id:guid}/revoke", async (Guid id, HttpContext http, CancellationToken ct) =>
    await store.Revoke(Identity(http).OrganizationId, id, ct) ? Results.NoContent() : Results.NotFound());
admin.MapGet("/policies", async (HttpContext http, CancellationToken ct) =>
    Results.Ok(await store.PolicyHistory(Identity(http).OrganizationId, ct)));
admin.MapPost("/policies", async (PublishPolicy request, HttpContext http, CancellationToken ct) =>
    FixtureContract.IsMode(request.Mode)
        ? Results.Ok(await store.Publish(Identity(http).OrganizationId, request.Mode, null, ct))
        : Results.BadRequest(new { error = "Choose monitor, warn, or block." }));
admin.MapPost("/policies/{version:int}/restore", async (int version, HttpContext http, CancellationToken ct) =>
    await store.Publish(Identity(http).OrganizationId, null, version, ct) is { } published
        ? Results.Ok(published) : Results.NotFound());
admin.MapGet("/events", async (string? appId, string? decision, DateTimeOffset? since, HttpContext http, CancellationToken ct) =>
    Results.Ok(appId is null or FixtureContract.AppId
        ? await store.Events(Identity(http).OrganizationId, decision, since, ct)
        : Array.Empty<StoredEvent>()));

app.MapPost("/v1/enroll", async (RedeemGrant request, CancellationToken ct) =>
    Tokens.IsValid(request.Grant) && await store.Enroll(request.Grant, ct) is { } enrollment
        ? Results.Ok(enrollment) : Results.Unauthorized());

var browser = app.MapGroup("/v1/browser").AddEndpointFilter(Authenticate(browser: true));
browser.MapGet("/policy", async (HttpContext http, CancellationToken ct) =>
    await store.CurrentPolicy(Identity(http).InstallationId!.Value, ct) is { } policy
        ? Results.Ok(policy) : Results.Unauthorized());
browser.MapPost("/heartbeat", async (Heartbeat request, HttpContext http, CancellationToken ct) =>
    await store.RecordHeartbeat(Identity(http).InstallationId!.Value, request.PolicyVersion, ct)
        ? Results.NoContent() : Results.BadRequest(new { error = "Policy version is unavailable." }));
browser.MapPost("/events", async (PolicyEvent request, HttpContext http, CancellationToken ct) =>
    FixtureContract.IsEvent(request) && await store.Ingest(Identity(http).InstallationId!.Value, request, ct)
        ? Results.NoContent() : Results.BadRequest(new { error = "Invalid policy event." }));

await app.RunAsync();

Func<EndpointFilterInvocationContext, EndpointFilterDelegate, ValueTask<object?>> Authenticate(bool browser) =>
    async (context, next) =>
{
    var http = context.HttpContext;
    if (!AuthenticationHeaderValue.TryParse(http.Request.Headers.Authorization, out var auth) ||
        !auth.Scheme.Equals("Bearer", StringComparison.OrdinalIgnoreCase) || !Tokens.IsValid(auth.Parameter) ||
        await store.Authenticate(auth.Parameter!, browser, http.RequestAborted) is not { } identity)
    {
        http.Response.Headers.WWWAuthenticate = "Bearer";
        return Results.Unauthorized();
    }
    http.Items[typeof(RequestIdentity)] = identity;
    return await next(context);
};

static RequestIdentity Identity(HttpContext http) => (RequestIdentity)http.Items[typeof(RequestIdentity)]!;

static bool ValidOrganization(DemoOrganization org) => org.Slug is { Length: > 0 and <= 63 } &&
    org.Slug.All(character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-') &&
    Tokens.IsValid(org.AdminToken);
