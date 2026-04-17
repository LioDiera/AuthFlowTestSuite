using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Identity.Client;

// ── Load config ──────────────────────────────────────────────────────────────
IConfiguration config = new ConfigurationBuilder()
    .SetBasePath(AppContext.BaseDirectory)
    .AddJsonFile("appsettings.json", optional: false)
    .Build();

// ── Detect configured providers ──────────────────────────────────────────────
bool entraidConfigured = IsConfigured(config["EntraId:TenantId"]) && IsConfigured(config["EntraId:ClientId"]);
bool adfsConfigured    = IsConfigured(config["Adfs:Authority"])   && IsConfigured(config["Adfs:ClientId"]);

if (!entraidConfigured && !adfsConfigured)
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine("No provider configured. Fill in EntraId or Adfs values in appsettings.json.");
    Console.ResetColor();
    return;
}

// ── Choose provider ───────────────────────────────────────────────────────────
bool runEntraId = false, runAdfs = false;

if (entraidConfigured && adfsConfigured)
{
    Console.WriteLine("Both providers are configured. Which would you like to use?");
    Console.WriteLine("  [1] Entra ID");
    Console.WriteLine("  [2] ADFS");
    Console.WriteLine("  [3] Both");
    Console.Write("Enter choice: ");
    string? choice = Console.ReadLine()?.Trim();
    Console.WriteLine();

    runEntraId = choice == "1" || choice == "3";
    runAdfs    = choice == "2" || choice == "3";

    if (!runEntraId && !runAdfs)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("Invalid choice. Exiting.");
        Console.ResetColor();
        return;
    }
}
else
{
    runEntraId = entraidConfigured;
    runAdfs    = adfsConfigured;
}

// ── Run flows ─────────────────────────────────────────────────────────────────
if (runEntraId) await RunEntraIdFlow(config);
if (runAdfs)    await RunAdfsFlow(config);

// ── Check if a config value is set (non-null, non-placeholder) ────────────────
static bool IsConfigured(string? value) =>
    !string.IsNullOrWhiteSpace(value) && !value.StartsWith('<');

// ── Entra ID interactive flow ─────────────────────────────────────────────────
async Task RunEntraIdFlow(IConfiguration cfg)
{
    string tenantId      = cfg["EntraId:TenantId"]!;
    string clientId      = cfg["EntraId:ClientId"]!;
    string? clientSecret = cfg["EntraId:ClientSecret"];
    string[] scopes      = cfg.GetSection("EntraId:Scopes")
        .GetChildren()
        .Select(c => c.Value!)
        .Where(v => !string.IsNullOrEmpty(v))
        .DefaultIfEmpty("User.Read")
        .ToArray();

    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("══ Entra ID ══════════════════════════════════════════════");
    Console.ResetColor();

    AuthenticationResult? result;

    if (IsConfigured(clientSecret))
    {
        var builder = ConfidentialClientApplicationBuilder
            .Create(clientId)
            .WithAuthority(AzureCloudInstance.AzurePublic, tenantId)
            .WithClientSecret(clientSecret!);
        result = await AcquireTokenConfidential(builder, scopes);
    }
    else
    {
        IPublicClientApplication publicApp = PublicClientApplicationBuilder
            .Create(clientId)
            .WithAuthority(AzureCloudInstance.AzurePublic, tenantId)
            .WithRedirectUri("http://localhost")
            .Build();
        result = await AcquireTokenPublic(publicApp, scopes);
    }

    if (result is null) return;

    ShowTokenSummary(result);
    await CallGraphMe(result.AccessToken);
}

// ── ADFS interactive flow ─────────────────────────────────────────────────────
async Task RunAdfsFlow(IConfiguration cfg)
{
    string authority     = cfg["Adfs:Authority"]!;
    string clientId      = cfg["Adfs:ClientId"]!;
    string? clientSecret = cfg["Adfs:ClientSecret"];
    string[] scopes      = cfg.GetSection("Adfs:Scopes")
        .GetChildren()
        .Select(c => c.Value!)
        .Where(v => !string.IsNullOrEmpty(v))
        .Append("allatclaims")
        .Distinct()
        .ToArray();

    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("══ ADFS ══════════════════════════════════════════════════");
    Console.ResetColor();

    AuthenticationResult? result;

    if (IsConfigured(clientSecret))
    {
        var builder = ConfidentialClientApplicationBuilder
            .Create(clientId)
            .WithAdfsAuthority(authority)
            .WithClientSecret(clientSecret!);
        result = await AcquireTokenConfidential(builder, scopes);
    }
    else
    {
        IPublicClientApplication publicApp = PublicClientApplicationBuilder
            .Create(clientId)
            .WithAdfsAuthority(authority)
            .WithRedirectUri("http://localhost")
            .Build();
        result = await AcquireTokenPublic(publicApp, scopes);
    }

    if (result is null) return;

    ShowTokenSummary(result);
    DecodeJwtClaims("Access token claims", result.AccessToken);
    if (!string.IsNullOrEmpty(result.IdToken))
        DecodeJwtClaims("ID token claims", result.IdToken);
    await CallAdfsUserInfo(authority, result.AccessToken);
}

// ── Public client: acquire token interactively (MSAL handles PKCE) ───────────
async Task<AuthenticationResult?> AcquireTokenPublic(IPublicClientApplication app, string[] scopes)
{
    Console.WriteLine("Opening browser for interactive sign-in...");
    Console.WriteLine();
    try
    {
        return await app.AcquireTokenInteractive(scopes)
            .WithUseEmbeddedWebView(false)
            .ExecuteAsync();
    }
    catch (MsalClientException ex) when (ex.ErrorCode == "authentication_canceled")
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("Sign-in was cancelled.");
        Console.ResetColor();
        return null;
    }
    catch (MsalServiceException ex) when (ex.ErrorCode == "access_denied")
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("Sign-in was declined.");
        Console.ResetColor();
        return null;
    }
    catch (MsalServiceException ex) when (ex.ErrorCode == "invalid_client")
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("Authentication failed: invalid_client.");
        Console.ResetColor();
        Console.WriteLine();
        Console.WriteLine("Your app registration requires a client secret (AADSTS7000218).");
        Console.WriteLine("To fix this, either:");
        Console.WriteLine("  • On the Authentication tab set 'Allow public client flows' to Yes, or");
        Console.WriteLine("  • Add a ClientSecret to appsettings.json and register a Web platform redirect URI.");
        return null;
    }
    catch (OperationCanceledException)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("Sign-in was cancelled.");
        Console.ResetColor();
        return null;
    }
}

// ── Confidential client: Auth Code + PKCE via local HTTP listener ─────────────
async Task<AuthenticationResult?> AcquireTokenConfidential(ConfidentialClientApplicationBuilder appBuilder, string[] scopes)
{
    int port = GetFreePort();
    string redirectUri = $"http://localhost:{port}/";

    // Build the app with the dynamic redirect URI so MSAL includes it in the token exchange POST
    IConfidentialClientApplication app = appBuilder
        .WithRedirectUri(redirectUri)
        .Build();

    // Generate a random state value to protect against CSRF
    string state = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));

    Uri authUri = await app.GetAuthorizationRequestUrl(scopes)
        .WithRedirectUri(redirectUri)
        .WithExtraQueryParameters(new Dictionary<string, (string, bool)> { ["state"] = (state, false) })
        .ExecuteAsync();

    using var listener = new HttpListener();
    listener.Prefixes.Add(redirectUri);
    listener.Start();

    Console.WriteLine("Opening browser for interactive sign-in...");
    Console.WriteLine($"Redirect URI: {redirectUri}");
    Console.WriteLine();
    OpenBrowser(authUri.AbsoluteUri);

    HttpListenerContext ctx = await listener.GetContextAsync();

    // Respond to the browser immediately
    const string html = "<html><body><p>Authentication complete. You can close this tab.</p></body></html>";
    byte[] bytes = System.Text.Encoding.UTF8.GetBytes(html);
    ctx.Response.ContentType     = "text/html; charset=utf-8";
    ctx.Response.ContentLength64 = bytes.Length;
    await ctx.Response.OutputStream.WriteAsync(bytes);
    ctx.Response.Close();

    // Parse the redirect query string
    string rawQuery = ctx.Request.Url?.Query?.TrimStart('?') ?? string.Empty;
    Dictionary<string, string> qs = rawQuery
        .Split('&', StringSplitOptions.RemoveEmptyEntries)
        .Select(p => p.Split('=', 2))
        .Where(p => p.Length == 2)
        .ToDictionary(p => Uri.UnescapeDataString(p[0]), p => Uri.UnescapeDataString(p[1]));

    if (qs.TryGetValue("error", out string? err))
    {
        string desc = qs.TryGetValue("error_description", out string? d) ? Uri.UnescapeDataString(d) : string.Empty;
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"Sign-in error: {err} — {desc}");
        Console.ResetColor();
        return null;
    }

    // Validate the state parameter to prevent CSRF attacks
    if (!qs.TryGetValue("state", out string? returnedState) || returnedState != state)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("State mismatch — possible CSRF attack. Aborting.");
        Console.ResetColor();
        return null;
    }

    if (!qs.TryGetValue("code", out string? code))
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("No authorization code received.");
        Console.ResetColor();
        return null;
    }

    try
    {
        return await app.AcquireTokenByAuthorizationCode(scopes, code)
            .ExecuteAsync();
    }
    catch (MsalServiceException ex)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"Token exchange failed: {ex.Message}");
        Console.ResetColor();
        return null;
    }
}

// ── Get a free local TCP port ─────────────────────────────────────────────────
static int GetFreePort()
{
    using var tmp = new TcpListener(System.Net.IPAddress.Loopback, 0);
    tmp.Start();
    int port = ((System.Net.IPEndPoint)tmp.LocalEndpoint).Port;
    tmp.Stop();
    return port;
}

// ── Open the default system browser ──────────────────────────────────────────
static void OpenBrowser(string url)
{
    try
    {
        System.Diagnostics.Process.Start(
            new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true });
    }
    catch
    {
        Console.WriteLine($"Please open this URL in your browser:\n{url}");
    }
}

// ── Shared: show token summary ────────────────────────────────────────────────
void ShowTokenSummary(AuthenticationResult result)
{
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine($"Successfully signed in as: {result.Account.Username}");
    Console.ResetColor();
    Console.WriteLine($"Token expires:  {result.ExpiresOn.ToLocalTime():g}");
    Console.WriteLine($"Scopes granted: {string.Join(", ", result.Scopes)}");
    Console.WriteLine();
}

// ── ADFS only: decode and display JWT payload claims ──────────────────────────
void DecodeJwtClaims(string label, string jwt)
{
    string[] parts = jwt.Split('.');
    if (parts.Length < 2) return;

    string payload = parts[1];
    int pad = (4 - payload.Length % 4) % 4;
    payload += new string('=', pad);
    payload = payload.Replace('-', '+').Replace('_', '/');

    string json;
    try { json = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(payload)); }
    catch { return; }

    using JsonDocument doc = JsonDocument.Parse(json);

    Console.WriteLine();
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine($"── {label} ──────────────────────────────────────────────");
    Console.ResetColor();

    foreach (JsonProperty prop in doc.RootElement.EnumerateObject())
        Console.WriteLine($"  {prop.Name,-30} {prop.Value}");

    Console.WriteLine();
}

// ── ADFS only: call userinfo endpoint ────────────────────────────────────────
async Task CallAdfsUserInfo(string authority, string accessToken)
{
    string userInfoUrl = authority.TrimEnd('/') + "/userinfo";
    Console.WriteLine($"Calling ADFS userinfo endpoint: {userInfoUrl} ...");

    using HttpClient http = new();
    http.DefaultRequestHeaders.Authorization =
        new AuthenticationHeaderValue("Bearer", accessToken);

    HttpResponseMessage response = await http.GetAsync(userInfoUrl);

    if (!response.IsSuccessStatusCode)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"Userinfo call failed: {response.StatusCode}");
        Console.ResetColor();
        string error = await response.Content.ReadAsStringAsync();
        Console.WriteLine(error);
        return;
    }

    string json = await response.Content.ReadAsStringAsync();
    using JsonDocument doc = JsonDocument.Parse(json);
    JsonElement root = doc.RootElement;

    Console.WriteLine();
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine("── userinfo response ────────────────────────────────────");
    Console.ResetColor();

    foreach (JsonProperty prop in root.EnumerateObject())
        Console.WriteLine($"  {prop.Name,-20} {prop.Value}");

    Console.WriteLine();
}

// ── Entra ID only: call Microsoft Graph /me ───────────────────────────────────
async Task CallGraphMe(string accessToken)
{
    Console.WriteLine("Calling Microsoft Graph /me ...");

    using HttpClient http = new();
    http.DefaultRequestHeaders.Authorization =
        new AuthenticationHeaderValue("Bearer", accessToken);
    http.DefaultRequestHeaders.Add("ConsistencyLevel", "eventual");

    HttpResponseMessage response = await http.GetAsync("https://graph.microsoft.com/v1.0/me");

    if (!response.IsSuccessStatusCode)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"Graph call failed: {response.StatusCode}");
        Console.ResetColor();
        string error = await response.Content.ReadAsStringAsync();
        Console.WriteLine(error);
        return;
    }

    string json = await response.Content.ReadAsStringAsync();
    using JsonDocument doc = JsonDocument.Parse(json);
    JsonElement root = doc.RootElement;

    Console.WriteLine();
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine("── /me response ─────────────────────────────────────────");
    Console.ResetColor();

    string[] fields = ["displayName", "userPrincipalName", "id", "mail", "jobTitle", "officeLocation"];
    foreach (string field in fields)
    {
        if (root.TryGetProperty(field, out JsonElement value) && value.ValueKind != JsonValueKind.Null)
            Console.WriteLine($"  {field,-20} {value.GetString()}");
    }

    Console.WriteLine();
    Console.ForegroundColor = ConsoleColor.DarkGray;
    Console.WriteLine("Raw JSON:");
    Console.WriteLine(JsonSerializer.Serialize(root, new JsonSerializerOptions { WriteIndented = true }));
    Console.ResetColor();
}
