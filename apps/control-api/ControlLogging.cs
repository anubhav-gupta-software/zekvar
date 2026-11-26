using Npgsql;

namespace Control;

// Control logs one JSON object per line to stdout for the systemd journal and docker logs.
// Framework categories that can describe a request (URL with query string, headers, bodies, SQL parameters,
// exception messages that echo input) are pinned to Warning or above, and no configuration can lower them.
// Control's own categories log fixed messages with error types, SQL states and route templates only.
internal static class ControlLogging
{
    private static readonly (string Category, LogLevel Level)[] Floors =
    [
        ("Microsoft", LogLevel.Warning),
        ("Microsoft.Hosting.Lifetime", LogLevel.Information),
        ("System", LogLevel.Warning),
        ("Npgsql", LogLevel.Warning),
    ];

    public static void Configure(ILoggingBuilder logging)
    {
        logging.ClearProviders();
        logging.AddJsonConsole(options =>
        {
            options.IncludeScopes = false;
            options.UseUtcTimestamp = true;
            options.TimestampFormat = "yyyy-MM-ddTHH:mm:ss.fffZ";
        });
        logging.Services.PostConfigure<LoggerFilterOptions>(options =>
        {
            foreach (var rule in options.Rules.Where(rule => rule.CategoryName is { } category && Floors.Any(floor => Covers(floor.Category, category))).ToArray())
                options.Rules.Remove(rule);
            foreach (var (category, level) in Floors) options.Rules.Add(new LoggerFilterRule(null, category, level, null));
            if (options.MinLevel < LogLevel.Information) options.MinLevel = LogLevel.Information;
        });
    }

    private static bool Covers(string prefix, string category) =>
        category.Equals(prefix, StringComparison.OrdinalIgnoreCase) ||
        category.StartsWith(prefix + ".", StringComparison.OrdinalIgnoreCase) ||
        category.Contains('*');

    // Replaces the framework's unhandled-exception logging, which records the exception message. Messages can embed
    // request values (for example PostgreSQL input syntax errors), so only the type, SQL state, method, route template,
    // trace identifier, and stack frames are logged.
    public static Func<HttpContext, RequestDelegate, Task> ContainUnhandledErrors(ILoggerFactory factory)
    {
        var logger = factory.CreateLogger("Control.Requests");
        return async (context, next) =>
        {
            try
            {
                await next(context);
            }
            catch (Exception) when (context.RequestAborted.IsCancellationRequested)
            {
                context.Abort();
            }
            catch (Exception error)
            {
                var status = error is BadHttpRequestException bad ? bad.StatusCode : StatusCodes.Status500InternalServerError;
                if (status >= 500)
                    logger.LogError("Control request failed with {ErrorType} ({SqlState}) on {Method} {Route}. Trace {TraceId}. {StackTrace}",
                        error.GetType().Name, (error as PostgresException)?.SqlState, context.Request.Method,
                        (context.GetEndpoint() as RouteEndpoint)?.RoutePattern.RawText ?? "unmatched route", context.TraceIdentifier,
                        error.StackTrace);
                if (context.Response.HasStarted)
                {
                    context.Abort();
                    return;
                }
                context.Response.Clear();
                context.Response.Headers.CacheControl = "no-store";
                context.Response.StatusCode = status;
            }
        };
    }
}
