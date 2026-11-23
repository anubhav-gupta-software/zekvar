using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Control;

internal sealed record ConfiguredAlertWebhook(string? OrganizationSlug, string? Endpoint, string? SigningSecret);
internal sealed record AlertWebhookRoute(Uri Endpoint, byte[] SigningKey, string Fingerprint);

internal sealed class AlertWebhooks
{
    private readonly Dictionary<string, AlertWebhookRoute> routes = new(StringComparer.Ordinal);
    public bool Enabled => routes.Count > 0;
    public string Routing { get; private set; } = "{}";

    public AlertWebhookRoute? Find(string organization, string fingerprint) =>
        routes.TryGetValue(organization, out var route) && route.Fingerprint == fingerprint ? route : null;

    public static AlertWebhooks Read(IConfiguration configuration, bool development, DemoOrganization[] organizations)
    {
        var result = new AlertWebhooks();
        var entries = configuration.GetSection("Control:AlertWebhooks").Get<ConfiguredAlertWebhook[]>() ?? [];
        foreach (var entry in entries)
        {
            if (string.IsNullOrEmpty(entry.Endpoint) && string.IsNullOrEmpty(entry.SigningSecret)) continue;
            if (entry.OrganizationSlug is not { } organization || !organizations.Any(org => org.Slug == organization) ||
                !IsEndpoint(entry.Endpoint, development, out var endpoint) || !Tokens.IsValid(entry.SigningSecret) ||
                organizations.Any(org => org.AdminToken == entry.SigningSecret) ||
                !result.routes.TryAdd(organization, new(endpoint!, Convert.FromHexString(entry.SigningSecret!),
                    Tokens.Hash(endpoint!.AbsoluteUri))))
                throw new InvalidOperationException("Configure one HTTPS alert webhook and a distinct 32-byte hex signing key per Control organization.");
        }
        result.Routing = JsonSerializer.Serialize(result.routes.ToDictionary(entry => entry.Key, entry => entry.Value.Fingerprint));
        return result;
    }

    private static bool IsEndpoint(string? value, bool development, out Uri? endpoint)
    {
        endpoint = null;
        return value is { Length: >= 1 and <= 2048 } && Uri.TryCreate(value, UriKind.Absolute, out endpoint) &&
            endpoint.Host.Length > 0 && endpoint.UserInfo == "" && endpoint.Query == "" && endpoint.Fragment == "" &&
            (endpoint.Scheme == Uri.UriSchemeHttps ||
                development && endpoint.Scheme == Uri.UriSchemeHttp && endpoint.Host == "127.0.0.1");
    }
}

internal sealed record AlertWebhookPayload(int SchemaVersion, string Type, Guid DeliveryId, string Organization, Guid AlertId,
    string AppId, string Rollout, Guid? RolloutGroupId, DateTime WindowStart, DateTime WindowEnd, DateTime TriggeredAt, int Threshold);
internal sealed record ClaimedAlertWebhook(Guid OrganizationId, Guid LeaseId, string RouteFingerprint, int Attempt, AlertWebhookPayload Payload);
internal sealed record AlertWebhookDelivery(string Status, int Attempts, DateTime? LastAttemptAt, DateTime? NextAttemptAt,
    DateTime? SentAt, string? FailureCode, int? LastHttpStatus);
internal sealed record AlertWebhookOutcome(string? FailureCode = null, int? HttpStatus = null, bool Retryable = false, TimeSpan? RetryAfter = null);

internal sealed class AlertWebhookDispatcher(ControlStore store, AlertWebhooks webhooks, ILogger<AlertWebhookDispatcher> logger) : BackgroundService
{
    internal const int MaxAttempts = 6;
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);
    private readonly HttpClient client = new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false, UseCookies = false, UseProxy = false, PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        MaxResponseHeadersLength = 16, MaxResponseDrainSize = 0
    }) { Timeout = System.Threading.Timeout.InfiniteTimeSpan };

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var schedule = new PeriodicTimer(TimeSpan.FromSeconds(2));
        do
        {
            try
            {
                for (var sent = 0; sent < 20 && !stoppingToken.IsCancellationRequested; sent++)
                {
                    if (await store.ClaimAlertWebhook(stoppingToken) is not { } job) break;
                    var route = webhooks.Find(job.Payload.Organization, job.RouteFingerprint)!;
                    var outcome = await Deliver(route, job.Payload, stoppingToken);
                    await store.FinishAlertWebhook(job, outcome, stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception error)
            {
                logger.LogWarning("Alert webhook processing will retry after an error of type {ErrorType}.", error.GetType().Name);
            }
        } while (await schedule.WaitForNextTickAsync(stoppingToken));
    }

    private async Task<AlertWebhookOutcome> Deliver(AlertWebhookRoute route, AlertWebhookPayload payload, CancellationToken ct)
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(payload, JsonSerializerOptions.Web);
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        using var signer = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, route.SigningKey);
        signer.AppendData(Encoding.ASCII.GetBytes(timestamp + "."));
        signer.AppendData(body);
        using var request = new HttpRequestMessage(HttpMethod.Post, route.Endpoint) { Content = new ByteArrayContent(body) };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        request.Headers.Add("X-Zekvar-Delivery-Id", payload.DeliveryId.ToString("D"));
        request.Headers.Add("X-Zekvar-Timestamp", timestamp);
        request.Headers.Add("X-Zekvar-Signature", "v1=" + Convert.ToHexStringLower(signer.GetHashAndReset()));
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(Timeout);
        try
        {
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
            var status = (int)response.StatusCode;
            if (response.IsSuccessStatusCode) return new(HttpStatus: status);
            var retryAfter = response.Headers.RetryAfter;
            return new("http_status", status is >= 200 and <= 599 ? status : null, status is 408 or 425 or 429 or >= 500,
                retryAfter?.Delta ?? (retryAfter?.Date - DateTimeOffset.UtcNow));
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new("request_timeout", Retryable: true);
        }
        catch (HttpRequestException)
        {
            return new("network_error", Retryable: true);
        }
    }

    public override void Dispose()
    {
        client.Dispose();
        base.Dispose();
    }
}
