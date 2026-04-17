using System.Net.Http.Headers;
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

// ── Entra ID device code flow ─────────────────────────────────────────────────
async Task RunEntraIdFlow(IConfiguration cfg)
{
    string tenantId  = cfg["EntraId:TenantId"]!;
    string clientId  = cfg["EntraId:ClientId"]!;
    string[] scopes  = cfg.GetSection("EntraId:Scopes")
        .GetChildren()
        .Select(c => c.Value!)
        .Where(v => !string.IsNullOrEmpty(v))
        .DefaultIfEmpty("User.Read")
        .ToArray();

    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("══ Entra ID ══════════════════════════════════════════════");
    Console.ResetColor();

    IPublicClientApplication app = PublicClientApplicationBuilder
        .Create(clientId)
        .WithAuthority(AzureCloudInstance.AzurePublic, tenantId)
        .Build();

    AuthenticationResult? result = await AcquireToken(app, scopes);
    if (result is null) return;

    ShowTokenSummary(result);
    await CallGraphMe(result.AccessToken);
}

// ── ADFS device code flow ─────────────────────────────────────────────────────
async Task RunAdfsFlow(IConfiguration cfg)
{
    string authority = cfg["Adfs:Authority"]!;
    string clientId  = cfg["Adfs:ClientId"]!;
    string[] scopes  = cfg.GetSection("Adfs:Scopes")
        .GetChildren()
        .Select(c => c.Value!)
        .Where(v => !string.IsNullOrEmpty(v))
        .Append("allatclaims")
        .Distinct()
        .ToArray();

    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("══ ADFS ══════════════════════════════════════════════════");
    Console.ResetColor();

    IPublicClientApplication app = PublicClientApplicationBuilder
        .Create(clientId)
        .WithAdfsAuthority(authority)
        .Build();

    AuthenticationResult? result = await AcquireToken(app, scopes);
    if (result is null) return;

    ShowTokenSummary(result);
    DecodeJwtClaims("Access token claims", result.AccessToken);
    if (!string.IsNullOrEmpty(result.IdToken))
        DecodeJwtClaims("ID token claims", result.IdToken);
    await CallAdfsUserInfo(authority, result.AccessToken);
}

// ── Shared: acquire token via device code ─────────────────────────────────────
async Task<AuthenticationResult?> AcquireToken(IPublicClientApplication app, string[] scopes)
{
    Console.WriteLine("Acquiring token via device code flow...");
    Console.WriteLine();
    try
    {
        return await app.AcquireTokenWithDeviceCode(scopes, deviceCodeResult =>
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(deviceCodeResult.Message);
            Console.ResetColor();
            Console.WriteLine();
            return Task.CompletedTask;
        }).ExecuteAsync();
    }
    catch (MsalServiceException ex) when (ex.ErrorCode == "authorization_declined")
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("Sign-in was declined.");
        Console.ResetColor();
        return null;
    }
    catch (MsalServiceException ex) when (ex.ErrorCode == "code_expired")
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("The device code expired. Please run the app again.");
        Console.ResetColor();
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

    // Base64url decode the payload
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

// ── ADFS only: call userinfo endpoint ───────────────────────────────────────
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
    {
        Console.WriteLine($"  {prop.Name,-20} {prop.Value}");
    }
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
