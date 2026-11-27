namespace Control;

// Mirrors contracts/policy/saas-catalog.json. The API suite fails when the two lists differ.
internal static class SaasCatalog
{
    public const int Version = 1;
    public static readonly string[] AppIds =
    [
        "slack", "microsoft-teams", "zoom", "webex", "google-meet", "atlassian", "trello", "asana",
        "monday", "clickup", "smartsheet", "basecamp", "miro", "loom", "discord", "whatsapp-web",
        "telegram-web", "messenger", "notion", "airtable", "evernote", "calendly", "docusign", "google-docs",
        "microsoft-365", "google-drive", "sharepoint", "box", "egnyte", "dropbox", "onedrive-personal", "icloud",
        "wetransfer", "mega", "pcloud", "mediafire", "smash", "github", "gitlab", "bitbucket",
        "linear", "vercel", "netlify", "heroku", "aws-console", "azure-portal", "google-cloud-console", "docker-hub",
        "npm", "postman", "replit", "github-gist", "pastebin", "codepen", "salesforce", "hubspot",
        "pipedrive", "zoho", "zendesk", "intercom", "freshdesk", "workday", "bamboohr", "gusto",
        "rippling", "adp", "greenhouse", "lever", "quickbooks", "xero", "expensify", "bill-com",
        "stripe-dashboard", "brex", "ramp", "paypal", "figma", "canva", "mailchimp", "surveymonkey",
        "typeform", "gmail", "outlook-personal", "yahoo-mail", "proton-mail", "aol-mail", "gmx", "poe",
        "character-ai", "mistral-le-chat", "you-com", "pi-ai", "hugging-face", "quillbot", "grammarly", "jasper",
        "otter", "notebooklm",
    ];
    private static readonly HashSet<string> Known = new(AppIds, StringComparer.Ordinal);

    public static bool IsApp(string? appId) => appId is not null && Known.Contains(appId);
    public static bool IsStatus(string? status) => status is "unclassified" or "under_review" or "sanctioned" or "unsanctioned";
}
