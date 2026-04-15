using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Identity.Client;

// ── Load config ──────────────────────────────────────────────────────────────
IConfiguration config = new ConfigurationBuilder()
    .SetBasePath(AppContext.BaseDirectory)
    .AddJsonFile("appsettings.json", optional: false)
    .Build();

string tenantId = config["AzureAd:TenantId"]
    ?? throw new InvalidOperationException("AzureAd:TenantId is not set in appsettings.json");
string clientId = config["AzureAd:ClientId"]
    ?? throw new InvalidOperationException("AzureAd:ClientId is not set in appsettings.json");
string[] scopes = config.GetSection("AzureAd:Scopes")
    .GetChildren()
    .Select(c => c.Value!)
    .Where(v => !string.IsNullOrEmpty(v))
    .DefaultIfEmpty("User.Read")
    .ToArray();

// ── Build MSAL public client ──────────────────────────────────────────────────
IPublicClientApplication app = PublicClientApplicationBuilder
    .Create(clientId)
    .WithAuthority(AzureCloudInstance.AzurePublic, tenantId)
    .Build();

// ── Acquire token via device code flow ───────────────────────────────────────
Console.WriteLine("Acquiring token via device code flow...");
Console.WriteLine();

AuthenticationResult result;
try
{
    result = await app.AcquireTokenWithDeviceCode(scopes, deviceCodeResult =>
    {
        // Print the user-facing message (contains the URL and code)
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
    return;
}
catch (MsalServiceException ex) when (ex.ErrorCode == "code_expired")
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine("The device code expired. Please run the app again.");
    Console.ResetColor();
    return;
}
catch (OperationCanceledException)
{
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("Sign-in was cancelled.");
    Console.ResetColor();
    return;
}

// ── Show token summary ────────────────────────────────────────────────────────
Console.ForegroundColor = ConsoleColor.Green;
Console.WriteLine($"Successfully signed in as: {result.Account.Username}");
Console.ResetColor();
Console.WriteLine($"Token expires:  {result.ExpiresOn.ToLocalTime():g}");
Console.WriteLine($"Scopes granted: {string.Join(", ", result.Scopes)}");
Console.WriteLine();

// ── Call Microsoft Graph /me ──────────────────────────────────────────────────
Console.WriteLine("Calling Microsoft Graph /me ...");

using HttpClient http = new();
http.DefaultRequestHeaders.Authorization =
    new AuthenticationHeaderValue("Bearer", result.AccessToken);
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
