using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Broker; // Required for WithBroker(BrokerOptions) extension method

// ── Load config ───────────────────────────────────────────────────────────────
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
    Console.Write("Enter choice: ");
    string? choice = Console.ReadLine()?.Trim();
    Console.WriteLine();
    runEntraId = choice == "1";
    runAdfs    = choice == "2";
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

// ── Run flow ──────────────────────────────────────────────────────────────────
if (runEntraId) await RunEntraIdFlow(config);
if (runAdfs)    await RunAdfsFlow(config);

// ── Check if a config value is set (not blank and not a placeholder) ──────────
static bool IsConfigured(string? value) =>
    !string.IsNullOrWhiteSpace(value) && !value.StartsWith('<');

// ── Entra ID — WAM flow ───────────────────────────────────────────────────────
async Task RunEntraIdFlow(IConfiguration cfg)
{
    string tenantId  = cfg["EntraId:TenantId"]!;
    string clientId  = cfg["EntraId:ClientId"]!;
    string apiBaseUrl = cfg["EntraId:ApiBaseUrl"] ?? "http://localhost:7001";
    string[] scopes  = cfg.GetSection("EntraId:Scopes").GetChildren()
        .Select(c => c.Value!).Where(v => !string.IsNullOrEmpty(v))
        .ToArray();

    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("══ Entra ID — Web Account Manager (WAM) ══════════════════");
    Console.ResetColor();

    // WAM (Web Account Manager) is the modern Windows authentication broker.
    // It replaces the older IWA (Kerberos/NTLM) approach and uses the Windows
    // account broker (wam.dll / AccountsControl) to acquire tokens for the
    // currently signed-in Windows identity — still no browser, no redirect URI,
    // no credentials in code. WAM is the recommended path for Entra ID on Windows.
    // ADFS does not support WAM; that flow below uses the classic IWA path instead.
    IPublicClientApplication app = PublicClientApplicationBuilder
        .Create(clientId)
        .WithAuthority(AzureCloudInstance.AzurePublic, tenantId)
        // WithBroker enables the Windows account broker. BrokerOptions restricts it
        // to Windows so the build succeeds on other platforms (though WAM is Windows-only).
        // The using Microsoft.Identity.Client.Broker directive above is required to resolve
        // this overload — without it the compiler picks a different WithBroker(bool) overload.
        .WithBroker(new BrokerOptions(BrokerOptions.OperatingSystems.Windows))
        // WAM requires a parent window handle so the broker knows where to anchor any
        // interactive UI it may need to show. For console apps we retrieve the console
        // window HWND via a P/Invoke to kernel32 GetConsoleWindow.
        .WithParentActivityOrWindow(NativeMethods.GetConsoleOrTerminalWindow)
        .Build();

    // openid + profile are added so the id_token contains login_hint / UPN claims
    // needed for the signed-out page and the token summary display
    string[] requestScopes = scopes.Concat(new[] { "openid", "profile" }).Distinct().ToArray();

    TokenResult? result = await AcquireTokenWam(app, requestScopes);
    if (result is null) return;

    ShowTokenSummary(result);
    string? endSession = await GetEndSessionEndpoint($"https://login.microsoftonline.com/{tenantId}/v2.0");
    await ServeStockroomApp(result, app, requestScopes, apiBaseUrl, endSession,
        authMethodDescription: "Web Account Manager (WAM)");
}

// ── ADFS — IWA flow ───────────────────────────────────────────────────────────
async Task RunAdfsFlow(IConfiguration cfg)
{
    string authority  = cfg["Adfs:Authority"]!;
    string clientId   = cfg["Adfs:ClientId"]!;
    string apiBaseUrl = cfg["Adfs:ApiBaseUrl"] ?? "http://localhost:7001";
    string[] scopes   = cfg.GetSection("Adfs:Scopes").GetChildren()
        .Select(c => c.Value!).Where(v => !string.IsNullOrEmpty(v))
        // allatclaims is an ADFS-specific scope that includes all configured claim
        // rules in the token rather than only the default minimal set
        .Append("allatclaims").Distinct().ToArray();

    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("══ ADFS — Integrated Windows Authentication (IWA) ════════");
    Console.ResetColor();

    // ADFS does not support the WAM broker — WAM is specific to Entra ID and MSA.
    // For ADFS we use the classic IWA path: MSAL negotiates Kerberos/NTLM with the
    // domain controller, then exchanges that assertion with the ADFS token endpoint.
    // WithAdfsAuthority() cannot be used here — MSAL explicitly blocks IWA when that
    // builder is used. WithAuthority(..., validateAuthority: false) points MSAL at the
    // ADFS endpoint without triggering that restriction.
    IPublicClientApplication app = PublicClientApplicationBuilder
        .Create(clientId)
        .WithAuthority(authority, validateAuthority: false)
        .WithDefaultRedirectUri()
        .Build();

    string[] requestScopes = scopes.Concat(new[] { "openid", "profile" }).Distinct().ToArray();

    TokenResult? result = await AcquireTokenIwa(app, requestScopes);
    if (result is null) return;

    ShowTokenSummary(result);
    string? endSession = await GetEndSessionEndpoint(authority);
    await ServeStockroomApp(result, app, requestScopes, apiBaseUrl, endSession,
        authMethodDescription: "Integrated Windows Authentication (IWA)");
}

// ── Acquire token via WAM (Web Account Manager) — Entra ID ──────────────────
// WAM is the modern Windows authentication broker, replacing the older IWA
// Kerberos/NTLM approach. Instead of negotiating a Kerberos ticket directly,
// MSAL delegates to the Windows account broker (wam.dll / AccountsControl),
// which uses the account already signed into Windows — no browser, no redirect
// URI, no credentials in code. The resulting JWT is identical to one produced
// by any other OAuth 2.0 flow; SweetSalesAPI validates it the same way.
//
// PublicClientApplication.OperatingSystemAccount is a sentinel value telling
// MSAL to use the currently signed-in Windows account rather than a cached
// MSAL account. This is the WAM equivalent of "current user" in IWA.
//
// Fails with MsalUiRequiredException if:
//   - The tenant has a Conditional Access policy requiring MFA
//   - The device is not Entra-joined or hybrid-joined
//   - The app registration does not have "Allow public client flows" enabled
async Task<TokenResult?> AcquireTokenWam(IPublicClientApplication app, string[] scopes)
{
    if (!OperatingSystem.IsWindows())
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("WAM authentication is only available on Windows.");
        Console.ResetColor();
        return null;
    }

    Console.WriteLine("Authenticating via Windows Account Manager (WAM)...");
    Console.WriteLine("(Using the current Windows identity — no browser will open)");
    Console.WriteLine();
    try
    {
        AuthenticationResult r = await app
            .AcquireTokenSilent(scopes, PublicClientApplication.OperatingSystemAccount)
            .ExecuteAsync();
        return new TokenResult(r.AccessToken, r.IdToken, r.ExpiresOn, r.Scopes.ToArray(), r.Account.Username);
    }
    catch (MsalUiRequiredException ex)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("Silent authentication failed — user interaction is required.");
        Console.ResetColor();
        Console.WriteLine();
        Console.WriteLine($"  Error code : {ex.ErrorCode}");
        Console.WriteLine($"  Reason     : {ex.Message}");
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("WAM silent sign-in requires:");
        Console.WriteLine("  • A domain-joined, hybrid-joined, or Entra-joined Windows machine");
        Console.WriteLine("  • No MFA or Conditional Access policy on the account");
        Console.WriteLine("  • 'Allow public client flows' enabled on the app registration");
        Console.WriteLine("  • An organisational account (not a personal Microsoft account)");
        Console.WriteLine();
        Console.WriteLine("If your tenant enforces MFA, use the InteractiveAuthWithWebAPI app instead.");
        Console.ResetColor();
        return null;
    }
    catch (MsalServiceException ex)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("Authentication failed.");
        Console.ResetColor();
        Console.WriteLine();
        Console.WriteLine($"  Error code : {ex.ErrorCode}");
        Console.WriteLine($"  Message    : {ex.Message}");

        // WAM surfaces Entra errors via inner exception or the message itself.
        // Extract the AADSTS code so we can give a specific fix hint.
        string fullMessage = ex.Message
            + (ex.InnerException?.Message ?? string.Empty)
            + (ex.AdditionalExceptionData != null
                ? string.Join(" ", ex.AdditionalExceptionData.Values) : string.Empty);

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Yellow;

        if (fullMessage.Contains("AADSTS7000218") || ex.Message.Contains("invalid_client"))
        {
            // The token endpoint received a public-client token request but the app
            // registration does not have "Allow public client flows" enabled.
            Console.WriteLine("Fix: in the Entra portal, go to:");
            Console.WriteLine("  App registrations → <your app> → Authentication → Advanced settings");
            Console.WriteLine("  Set 'Allow public client flows' to Yes, then Save.");
        }
        else if (fullMessage.Contains("AADSTS700016") || fullMessage.Contains("application was not found"))
        {
            Console.WriteLine("Fix: the Client ID in appsettings.json does not match any app registration");
            Console.WriteLine("  in the configured tenant. Check EntraId:ClientId and EntraId:TenantId.");
        }
        else if (fullMessage.Contains("AADSTS90002") || fullMessage.Contains("Tenant") && fullMessage.Contains("not found"))
        {
            Console.WriteLine("Fix: the Tenant ID in appsettings.json is not recognised.");
            Console.WriteLine("  Check EntraId:TenantId — it should be the Directory (tenant) ID GUID.");
        }
        else if (fullMessage.Contains("AADSTS65001") || fullMessage.Contains("consent"))
        {
            Console.WriteLine("Fix: the API permission has not been granted.");
            Console.WriteLine("  Go to App registrations → API permissions and grant admin consent,");
            Console.WriteLine("  or ask a Global Admin to do so.");
        }
        else
        {
            Console.WriteLine("Check the Entra portal app registration and appsettings.json values.");
        }

        Console.ResetColor();
        return null;
    }
    catch (MsalClientException ex)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"MSAL client error: [{ex.ErrorCode}] {ex.Message}");
        Console.ResetColor();
        return null;
    }
}

// ── Acquire token via IWA (Integrated Windows Authentication) — ADFS ──────────
// WAM does not support ADFS federation — it is specific to Entra ID and MSA.
// For ADFS we use the classic IWA path: MSAL negotiates a Kerberos or NTLM
// ticket with the domain controller and exchanges it with the ADFS /token
// endpoint using grant_type=urn:ietf:params:oauth:grant-type:windows.
// AcquireTokenByIntegratedWindowsAuth is obsolete in MSAL 4.x (WAM is preferred
// for Entra ID), but it remains the correct choice for ADFS.
async Task<TokenResult?> AcquireTokenIwa(IPublicClientApplication app, string[] scopes)
{
    Console.WriteLine("Authenticating via Integrated Windows Authentication (IWA)...");
    Console.WriteLine("(Using the current Windows identity — no browser will open)");
    Console.WriteLine();
    try
    {
        // WithUsername is optional — MSAL discovers the UPN from the current Windows
        // session via the Kerberos/NTLM ticket when omitted.
#pragma warning disable CS0618 // obsolete for Entra ID; correct for ADFS — see comment above
        AuthenticationResult r = await app.AcquireTokenByIntegratedWindowsAuth(scopes)
            .ExecuteAsync();
#pragma warning restore CS0618
        return new TokenResult(r.AccessToken, r.IdToken, r.ExpiresOn, r.Scopes.ToArray(), r.Account.Username);
    }
    catch (MsalUiRequiredException ex)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("Silent authentication failed — user interaction is required.");
        Console.ResetColor();
        Console.WriteLine();
        Console.WriteLine($"  Error code : {ex.ErrorCode}");
        Console.WriteLine($"  Reason     : {ex.Message}");
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("IWA requires:");
        Console.WriteLine("  • A domain-joined Windows machine");
        Console.WriteLine("  • No MFA or Conditional Access policy on the account");
        Console.WriteLine("  • 'Allow public client flows' enabled on the app registration");
        Console.WriteLine("  • An organisational account (not a personal Microsoft account)");
        Console.ResetColor();
        return null;
    }
    catch (MsalServiceException ex)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"Authentication failed: [{ex.ErrorCode}] {ex.Message}");
        Console.ResetColor();
        return null;
    }
    catch (MsalClientException ex)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"MSAL client error: [{ex.ErrorCode}] {ex.Message}");
        Console.ResetColor();
        return null;
    }
}

// ── Serve the Stockroom Manager SPA ──────────────────────────────────────────
// Opens a local HttpListener on :8401, launches SweetSalesAPI if not already
// running, then opens the browser. Because the token was acquired silently via
// WAM or IWA the browser opens directly to the authenticated SPA — no sign-in page.
// The session cookie architecture is identical to InteractiveAuthWithWebAPI:
//   - Token stored server-side, keyed by an opaque session ID
//   - Browser only holds the HttpOnly session cookie, never the Bearer token
//   - /api/* requests are proxied server-side with the Bearer token injected
//
// Token refresh: MSAL's in-memory token cache is used by TryRefreshToken. When
// the access token is within 5 minutes of expiry the proxy silently acquires a
// new one via the cache. If the cache is empty or refresh fails the original
// token is kept (it may still be valid for a few more minutes).
async Task ServeStockroomApp(
    TokenResult initialResult,
    IPublicClientApplication msalApp,
    string[] scopes,
    string apiBaseUrl,
    string? endSessionEndpoint,
    string authMethodDescription = "Windows Authentication")
{
    const string listenOn = "http://localhost:8401/";
    using var listener = new HttpListener();
    listener.Prefixes.Add(listenOn);
    listener.Start();

    // ── Launch SweetSalesAPI if not already listening ─────────────────────────
    // SweetSalesAPI lives in InteractiveAuthWithWebAPI/SweetSalesAPI relative to
    // the solution root. From WindowsAuthApp's bin/Debug/net10.0/ we go up 4 levels to
    // the solution root, then into the API project directory.
    Process? apiProcess = null;
    bool portInUse = System.Net.NetworkInformation.IPGlobalProperties
        .GetIPGlobalProperties().GetActiveTcpListeners()
        .Any(e => e.Port == 7001);

    if (!portInUse)
    {
        string apiDir = Path.GetFullPath(
            Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..",
                         "InteractiveAuthWithWebAPI", "SweetSalesAPI"));
        apiProcess = new Process
        {
            StartInfo = new ProcessStartInfo("dotnet", "run")
            {
                WorkingDirectory       = apiDir,
                UseShellExecute        = false,
                RedirectStandardOutput = false,
                RedirectStandardError  = false,
                CreateNoWindow         = false,
            }
        };
        apiProcess.Start();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("Starting SweetSalesAPI...");
        Console.ResetColor();
        // Poll until port 7001 is accepting connections rather than sleeping a fixed
        // amount of time. On a fresh clone, 'dotnet run' must restore and build before
        // Kestrel binds — this can take 10-30 seconds. A fixed 3-second delay is
        // not enough and causes an immediate connection-refused crash on the first
        // proxied API request. We try every 500 ms for up to 60 seconds.
        using var pollCts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        while (!pollCts.Token.IsCancellationRequested)
        {
            try
            {
                using var probe = new System.Net.Sockets.TcpClient();
                await probe.ConnectAsync("localhost", 7001, pollCts.Token);
                break; // connected — API is ready
            }
            catch
            {
                await Task.Delay(500, pollCts.Token).ContinueWith(_ => { }); // swallow cancellation
            }
        }
    }

    Console.CancelKeyPress += (_, e) =>
    {
        e.Cancel = true;
        listener.Stop();
        if (apiProcess is { HasExited: false })
        {
            apiProcess.Kill(entireProcessTree: true);
            Console.WriteLine("SweetSalesAPI stopped.");
        }
    };
    AppDomain.CurrentDomain.ProcessExit += (_, _) =>
    {
        if (apiProcess is { HasExited: false })
            apiProcess.Kill(entireProcessTree: true);
    };

    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine($"Sweet Sales Stockroom Manager running at {listenOn}");
    Console.ResetColor();
    Console.WriteLine("Press Ctrl+C to stop.");
    Console.WriteLine();

    // ── One-time bootstrap token ──────────────────────────────────────────────
    // Same pattern as InteractiveAuthWithWebAPI: the browser opens to
    // ?init=<bootstrapToken>. The listener immediately exchanges that token for
    // an opaque session cookie and redirects to /. This means the access token
    // never appears in the browser address bar or history — even though there was
    // no OAuth redirect, we still use the same session isolation approach.
    string bootstrapToken = Convert.ToHexString(
        System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));

    OpenBrowser(listenOn + "?init=" + bootstrapToken);

    using HttpClient apiClient = new();

    // Bootstrap map: one-time init token → tokens (consumed on first use)
    var bootstrapTokens = new Dictionary<string, (string AccessToken, string? IdToken)>
        { [bootstrapToken] = (initialResult.AccessToken, initialResult.IdToken) };
    // Active sessions: sessionId → tokens
    var sessions = new Dictionary<string, (string AccessToken, string? IdToken)>();

    // The tokens currently forwarded to the API (updated on silent refresh)
    string currentAccessToken = initialResult.AccessToken;
    string? currentIdToken    = initialResult.IdToken;

    // ── Main request loop ─────────────────────────────────────────────────────
    while (true)
    {
        HttpListenerContext ctx;
        try { ctx = await listener.GetContextAsync(); }
        catch { break; }

        string path     = ctx.Request.Url?.AbsolutePath ?? "/";
        string rawQuery = ctx.Request.Url?.Query ?? "";
        var qs = rawQuery.TrimStart('?')
            .Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Split('=', 2)).Where(p => p.Length == 2)
            .ToDictionary(p => Uri.UnescapeDataString(p[0]), p => Uri.UnescapeDataString(p[1]),
                          StringComparer.OrdinalIgnoreCase);

        // ── Bootstrap: ?init=<token> → create session + set cookie ───────────
        // Unlike InteractiveAuthWithWebAPI there is no IdP redirect involved —
        // the browser opens directly to the ?init= URL. The same one-time
        // bootstrap mechanism is used to ensure the token is never in the URL
        // after the first request.
        if (qs.TryGetValue("init", out string? initToken) &&
            bootstrapTokens.TryGetValue(initToken, out var btTokens))
        {
            bootstrapTokens.Remove(initToken);
            string newSid = Convert.ToHexString(
                System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
            sessions[newSid] = btTokens;
            currentAccessToken = btTokens.AccessToken;
            currentIdToken     = btTokens.IdToken;
            SetSessionCookie(ctx, newSid);
            SendRedirect(ctx, "/");
            continue;
        }

        // ── Post-sign-out landing page (?signed_out=1) ────────────────────────
        if (rawQuery.Contains("signed_out=1"))
        {
            string? expiredSid = GetSessionCookie(ctx);
            if (expiredSid is not null) sessions.Remove(expiredSid);
            ClearSessionCookie(ctx);
            await RespondWithHtml(ctx, BuildSignedOutHtml());
            continue;
        }

        // ── Session gate ──────────────────────────────────────────────────────
        string? sessionId  = GetSessionCookie(ctx);
        bool    hasSession = sessionId is not null && sessions.ContainsKey(sessionId);

        // ── Logout ────────────────────────────────────────────────────────────
        // Drops the local session and cookie, then redirects to the IdP's
        // end_session_endpoint if available, otherwise to the local signed-out page.
        if (path.Equals("/logout", StringComparison.OrdinalIgnoreCase))
        {
            if (sessionId is not null) sessions.Remove(sessionId);
            ClearSessionCookie(ctx);
            const string postLogoutUri = "http://localhost:8401/?signed_out=1";
            string dest;
            if (!string.IsNullOrEmpty(endSessionEndpoint))
            {
                string logoutQs = "?post_logout_redirect_uri=" + Uri.EscapeDataString(postLogoutUri);
                if (!string.IsNullOrEmpty(currentIdToken))
                    logoutQs += "&id_token_hint=" + Uri.EscapeDataString(currentIdToken);
                string? loginHint = ExtractJwtClaim(currentIdToken ?? currentAccessToken, "login_hint");
                if (!string.IsNullOrEmpty(loginHint))
                    logoutQs += "&logout_hint=" + Uri.EscapeDataString(loginHint);
                dest = endSessionEndpoint + logoutQs;
            }
            else
            {
                dest = postLogoutUri;
            }
            SendRedirect(ctx, dest);
            continue;
        }

        // ── No valid session → signed-out page ────────────────────────────────
        // Unlike InteractiveAuthWithWebAPI there is no /login route to re-initiate
        // IWA — that would require restarting the console process. The signed-out
        // page explains this to the user.
        if (!hasSession)
        {
            await RespondWithHtml(ctx, BuildSignedOutHtml());
            continue;
        }

        // ── Silent token refresh ──────────────────────────────────────────────
        // MSAL caches tokens and can silently renew them using the refresh token
        // stored in its in-memory cache. We attempt this before every proxied API
        // call so the Bearer token forwarded to SweetSalesAPI is always fresh.
        // AcquireTokenSilent checks the cache first; if the access token has not
        // yet expired it is returned immediately without a network call.
        // WithForceRefresh(false) is the default — only refresh when truly needed.
        currentAccessToken = await TryRefreshToken(msalApp, scopes, currentAccessToken);

        // ── Proxy /api/* → SweetSalesAPI ─────────────────────────────────────
        // Same server-side proxy pattern as InteractiveAuthWithWebAPI. The Bearer
        // token is injected here in the .NET process — the browser never sees it.
        if (path.StartsWith("/api/", StringComparison.OrdinalIgnoreCase))
        {
            string targetUrl = apiBaseUrl.TrimEnd('/') + path;
            if (!string.IsNullOrEmpty(ctx.Request.Url?.Query))
                targetUrl += ctx.Request.Url.Query;

            HttpRequestMessage req = new(new HttpMethod(ctx.Request.HttpMethod), targetUrl);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", currentAccessToken);
            if (ctx.Request.HasEntityBody)
            {
                using var reader = new System.IO.StreamReader(ctx.Request.InputStream);
                string bodyStr = await reader.ReadToEndAsync();
                req.Content = new StringContent(bodyStr, System.Text.Encoding.UTF8,
                    ctx.Request.ContentType ?? "application/json");
            }

            HttpResponseMessage apiResp = await apiClient.SendAsync(req);
            string apiBody = await apiResp.Content.ReadAsStringAsync();
            ctx.Response.StatusCode  = (int)apiResp.StatusCode;
            ctx.Response.ContentType = "application/json; charset=utf-8";
            byte[] apiBytes = System.Text.Encoding.UTF8.GetBytes(apiBody);
            ctx.Response.ContentLength64 = apiBytes.Length;
            await ctx.Response.OutputStream.WriteAsync(apiBytes);
            ctx.Response.Close();
            continue;
        }

        // ── Serve Stockroom SPA ───────────────────────────────────────────────
        await RespondWithHtml(ctx, BuildStockroomHtml(currentAccessToken, authMethodDescription));
    }
}

// ── Silent token refresh via MSAL cache ──────────────────────────────────────
// Tries to get a fresh access token from MSAL's in-memory cache. If the token
// is still valid MSAL returns it without a network call. If a refresh token is
// available MSAL will use it automatically. Returns the original token on any
// failure so the caller can continue with the potentially still-valid token.
async Task<string> TryRefreshToken(IPublicClientApplication app, string[] scopes, string current)
{
    try
    {
        // GetAccountsAsync returns accounts MSAL has tokens for in its cache.
        // For IWA there will be exactly one account after the initial sign-in.
        var accounts = await app.GetAccountsAsync();
        IAccount? account = accounts.FirstOrDefault();
        if (account is null) return current;

        // AcquireTokenSilent checks expiry and uses the refresh token if needed.
        // It throws MsalUiRequiredException only if interaction is genuinely required
        // (e.g. refresh token expired, MFA step-up) — not on normal cache hits.
        AuthenticationResult r = await app.AcquireTokenSilent(scopes, account).ExecuteAsync();
        return r.AccessToken;
    }
    catch (MsalUiRequiredException)
    {
        // Silent refresh not possible (e.g. refresh token expired or MFA required).
        // Return the original token — it may still be within its validity window.
        return current;
    }
    catch
    {
        return current;
    }
}

// ── Stockroom SPA HTML ────────────────────────────────────────────────────────
static string BuildStockroomHtml(string accessToken, string authMethodDescription = "Windows Authentication")
{
    string fullName = ExtractNameFromJwt(accessToken);
    string username = ExtractUpnFromJwt(accessToken);
    return $$"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8"/>
      <meta name="viewport" content="width=device-width, initial-scale=1"/>
      <title>Sweet Sales — Stockroom</title>
      <style>
        *, *::before, *::after { box-sizing:border-box; margin:0; padding:0; }
        body { min-height:100vh; display:flex; flex-direction:column;
               font-family:"Segoe UI",system-ui,-apple-system,sans-serif;
               background:#f0f4f8; color:#1e293b; }

        /* ── Header ── */
        header { background:#1e3a5f; color:#fff; padding:0 28px; height:56px;
                 display:flex; align-items:center; justify-content:space-between;
                 box-shadow:0 2px 6px rgba(0,0,0,.3); flex-shrink:0; }
        .brand { display:flex; align-items:center; gap:10px; font-size:1.05rem; font-weight:700; }
        .brand-badge { background:#3b82f6; color:#fff; font-size:.65rem;
                       font-weight:700; padding:2px 7px; border-radius:20px;
                       text-transform:uppercase; letter-spacing:.5px; }
        .user-pill { font-size:.8rem; color:rgba(255,255,255,.85);
                     background:rgba(255,255,255,.12); padding:5px 14px;
                     border-radius:20px; display:flex; align-items:center;
                     gap:10px; }
        .user-pill span { white-space:nowrap; }
        .logout-btn { background:rgba(255,255,255,.15); border:none; color:#fff;
                      font:inherit; font-size:.75rem; padding:4px 10px;
                      border-radius:6px; cursor:pointer; transition:.15s; }
        .logout-btn:hover { background:rgba(255,255,255,.28); }

        /* ── Layout ── */
        main { flex:1; display:flex; flex-direction:column; padding:28px 32px; gap:24px; overflow-y:auto; }

        /* ── Auth banner ── */
        .auth-banner { background:#dbeafe; border:1px solid #bfdbfe; border-radius:10px;
                       padding:14px 18px; display:flex; align-items:flex-start; gap:12px;
                       font-size:.85rem; color:#1e3a5f; line-height:1.6; }
        .auth-banner .icon { font-size:1.4rem; flex-shrink:0; margin-top:1px; }
        .auth-banner strong { display:block; font-size:.9rem; margin-bottom:2px; }

        /* ── Toolbar ── */
        .toolbar { display:flex; align-items:center; gap:12px; flex-wrap:wrap; }
        .toolbar h2 { font-size:1rem; font-weight:700; color:#1e3a5f; flex:1; }
        input[type=search] { padding:7px 12px; border:1px solid #cbd5e1; border-radius:8px;
                              font:inherit; font-size:.85rem; width:220px; background:#fff; }
        input[type=search]:focus { outline:none; border-color:#3b82f6;
                                   box-shadow:0 0 0 3px rgba(59,130,246,.15); }

        /* ── Buttons ── */
        .btn { padding:7px 16px; border:none; border-radius:8px; font:inherit;
               font-size:.83rem; font-weight:600; cursor:pointer; transition:.15s; }
        .btn-primary { background:#1e3a5f; color:#fff; }
        .btn-primary:hover { background:#15304f; }
        .btn-success { background:#16a34a; color:#fff; }
        .btn-success:hover { background:#15803d; }
        .btn-warning { background:#d97706; color:#fff; }
        .btn-warning:hover { background:#b45309; }
        .btn-danger  { background:#dc2626; color:#fff; }
        .btn-danger:hover  { background:#b91c1c; }
        .btn-ghost   { background:transparent; color:#475569; border:1px solid #cbd5e1; }
        .btn-ghost:hover   { background:#f1f5f9; }
        .btn-sm { padding:4px 10px; font-size:.78rem; }

        /* ── Table ── */
        .card { background:#fff; border:1px solid #e2e8f0; border-radius:12px;
                overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,.06); }
        table { width:100%; border-collapse:collapse; font-size:.85rem; }
        th { background:#f8fafc; padding:10px 14px; text-align:left;
             font-size:.75rem; font-weight:700; text-transform:uppercase;
             letter-spacing:.5px; color:#64748b; border-bottom:1px solid #e2e8f0; }
        td { padding:11px 14px; border-bottom:1px solid #f1f5f9; vertical-align:middle; }
        tr:last-child td { border-bottom:none; }
        tr:hover td { background:#f8fafc; }

        /* ── Stock badges ── */
        .stock-badge { display:inline-block; padding:2px 9px; border-radius:20px;
                       font-size:.75rem; font-weight:700; }
        .stock-ok  { background:#dcfce7; color:#15803d; }
        .stock-low { background:#fef9c3; color:#a16207; }
        .stock-out { background:#fee2e2; color:#dc2626; }

        /* ── Summary cards ── */
        .summary-row { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:16px; }
        .summary-card { background:#fff; border:1px solid #e2e8f0; border-radius:12px;
                        padding:16px 20px; box-shadow:0 1px 3px rgba(0,0,0,.06); }
        .summary-card .label { font-size:.72rem; text-transform:uppercase; letter-spacing:.5px;
                                color:#94a3b8; margin-bottom:6px; }
        .summary-card .value { font-size:1.6rem; font-weight:800; color:#1e3a5f; }
        .summary-card .sub   { font-size:.78rem; color:#64748b; margin-top:3px; }

        /* ── Modal ── */
        .modal-bg { display:none; position:fixed; inset:0; background:rgba(0,0,0,.45);
                    z-index:200; align-items:center; justify-content:center; }
        .modal-bg.open { display:flex; }
        .modal { background:#fff; border-radius:14px; padding:28px 32px;
                 width:420px; max-width:95vw;
                 box-shadow:0 20px 60px rgba(0,0,0,.25); }
        .modal h3 { font-size:1rem; margin-bottom:20px; color:#1e3a5f; }
        .field { margin-bottom:14px; }
        .field label { display:block; font-size:.78rem; font-weight:600;
                       color:#475569; margin-bottom:5px; }
        .field input, .field select {
          width:100%; padding:8px 10px; border:1px solid #cbd5e1; border-radius:8px;
          font:inherit; font-size:.85rem; }
        .field input:focus, .field select:focus {
          outline:none; border-color:#3b82f6;
          box-shadow:0 0 0 3px rgba(59,130,246,.15); }
        .modal-actions { display:flex; justify-content:flex-end; gap:10px; margin-top:22px; }

        .toast { display:none; position:fixed; bottom:24px; right:24px;
                 background:#1e293b; color:#fff; padding:10px 18px;
                 border-radius:10px; font-size:.83rem; z-index:300;
                 box-shadow:0 4px 12px rgba(0,0,0,.25); }
        .toast.show { display:block; }
      </style>
    </head>
    <body>
      <header>
        <div class="brand">
          🏪 Sweet Sales
          <span class="brand-badge">Stockroom</span>
        </div>
        <div class="user-pill">
          <span>{{fullName.Replace("\"","&quot;")}}</span>
          <button class="logout-btn" onclick="window.location='/logout'">Sign out</button>
        </div>
      </header>

      <main>
        <!-- Auth banner: explains the silent auth method so the app is self-documenting -->
        <div class="auth-banner">
          <div class="icon">🪟</div>
          <div>
            <strong>Signed in via {{authMethodDescription}}</strong>
            No browser sign-in was required. Your Windows identity (<strong>{{username.Replace("\"","&quot;")}}</strong>)
            was authenticated silently. The same JWT Bearer token used by the POS cashier
            app is sent to SweetSalesAPI — the API cannot tell which client acquired the token.
          </div>
        </div>

        <!-- Summary cards -->
        <div class="summary-row" id="summary-row">
          <div class="summary-card"><div class="label">Total Items</div><div class="value" id="s-total">—</div></div>
          <div class="summary-card"><div class="label">Total Units</div><div class="value" id="s-units">—</div></div>
          <div class="summary-card"><div class="label">Low Stock (≤5)</div><div class="value" id="s-low">—</div><div class="sub">items need reorder</div></div>
          <div class="summary-card"><div class="label">Out of Stock</div><div class="value" id="s-out">—</div><div class="sub">items unavailable</div></div>
          <div class="summary-card"><div class="label">Inventory Value</div><div class="value" id="s-value">—</div></div>
        </div>

        <!-- Toolbar -->
        <div class="toolbar">
          <h2>📦 Inventory</h2>
          <input type="search" id="search" placeholder="Search items…" oninput="filterTable()"/>
          <button class="btn btn-primary" onclick="openAddModal()">+ Add Item</button>
        </div>

        <!-- Table -->
        <div class="card">
          <table>
            <thead>
              <tr>
                <th>Item</th>
                <th>Category</th>
                <th>Price</th>
                <th>Stock</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody id="inv-tbody">
              <tr><td colspan="5" style="text-align:center;color:#94a3b8;padding:32px">Loading…</td></tr>
            </tbody>
          </table>
        </div>
      </main>

      <!-- Add / Edit modal -->
      <div class="modal-bg" id="modal-bg">
        <div class="modal">
          <h3 id="modal-title">Add Item</h3>
          <input type="hidden" id="edit-id"/>
          <div class="field"><label>Name</label><input id="f-name" placeholder="Butter Croissant"/></div>
          <div class="field"><label>Emoji</label><input id="f-emoji" placeholder="🥐" maxlength="2"/></div>
          <div class="field"><label>Category</label><select id="f-cat"></select></div>
          <div class="field"><label>Price ($)</label><input id="f-price" type="number" step="0.01" min="0"/></div>
          <div class="field"><label>Stock</label><input id="f-stock" type="number" min="0"/></div>
          <div class="modal-actions">
            <button class="btn btn-ghost" onclick="closeModal()">Cancel</button>
            <button class="btn btn-primary" onclick="saveItem()">Save</button>
          </div>
        </div>
      </div>

      <!-- Restock modal -->
      <div class="modal-bg" id="restock-bg">
        <div class="modal">
          <h3>Adjust Stock — <span id="restock-name"></span></h3>
          <input type="hidden" id="restock-id"/>
          <input type="hidden" id="restock-item-json"/>
          <div class="field">
            <label>New Stock Level</label>
            <input id="restock-qty" type="number" min="0"/>
          </div>
          <div style="font-size:.8rem;color:#64748b;margin-top:-8px;margin-bottom:14px">
            Current: <span id="restock-current"></span> units
          </div>
          <div class="modal-actions">
            <button class="btn btn-ghost" onclick="closeRestock()">Cancel</button>
            <button class="btn btn-success" onclick="saveRestock()">Update Stock</button>
          </div>
        </div>
      </div>

      <div class="toast" id="toast"></div>

      <script>
        let allItems = [];
        let currency = '$';

        async function apiFetch(path, opts = {}) {
          opts.headers = { ...(opts.headers||{}), 'Content-Type': 'application/json' };
          const r = await fetch(path, opts);
          if (!r.ok) throw new Error(await r.text());
          return r.status === 204 ? null : r.json();
        }

        function showToast(msg, ms = 2500) {
          const t = document.getElementById('toast');
          t.textContent = msg;
          t.classList.add('show');
          setTimeout(() => t.classList.remove('show'), ms);
        }

        async function loadInventory() {
          allItems = await apiFetch('/api/inventory');
          renderTable(allItems);
          renderSummary();
        }

        async function loadSettings() {
          try {
            const s = await apiFetch('/api/settings');
            currency = s.currency || '$';
          } catch {}
        }

        function renderSummary() {
          document.getElementById('s-total').textContent = allItems.length;
          document.getElementById('s-units').textContent = allItems.reduce((s,i)=>s+i.stock,0);
          document.getElementById('s-low').textContent   = allItems.filter(i=>i.stock>0&&i.stock<=5).length;
          document.getElementById('s-out').textContent   = allItems.filter(i=>i.stock===0).length;
          const val = allItems.reduce((s,i)=>s+(i.price*i.stock),0);
          document.getElementById('s-value').textContent = currency + val.toFixed(2);
        }

        function renderTable(items) {
          document.getElementById('inv-tbody').innerHTML = items.map(i => {
            const badge = i.stock === 0 ? 'stock-out' : i.stock <= 5 ? 'stock-low' : 'stock-ok';
            return `<tr>
              <td>${i.emoji} ${i.name}</td>
              <td>${i.category}</td>
              <td>${currency}${i.price.toFixed(2)}</td>
              <td><span class="stock-badge ${badge}">${i.stock}</span></td>
              <td style="display:flex;gap:6px;flex-wrap:wrap;">
                <button class="btn btn-success btn-sm" onclick='openRestock(${JSON.stringify(i)})'>Restock</button>
                <button class="btn btn-ghost btn-sm" onclick='openEditModal(${JSON.stringify(i)})'>Edit</button>
                <button class="btn btn-danger btn-sm" onclick="deleteItem(${i.id})">Delete</button>
              </td>
            </tr>`;
          }).join('');
        }

        function filterTable() {
          const q = document.getElementById('search').value.toLowerCase();
          renderTable(allItems.filter(i =>
            i.name.toLowerCase().includes(q) || i.category.toLowerCase().includes(q)));
        }

        function buildCatOptions(selected) {
          const cats = [...new Set(allItems.map(i=>i.category))];
          if (selected && !cats.includes(selected)) cats.push(selected);
          document.getElementById('f-cat').innerHTML =
            cats.map(c=>`<option${c===selected?' selected':''}>${c}</option>`).join('');
        }

        function openAddModal() {
          document.getElementById('modal-title').textContent = 'Add Item';
          document.getElementById('edit-id').value = '';
          ['name','emoji','price','stock'].forEach(f => document.getElementById('f-'+f).value='');
          buildCatOptions('Pastries');
          document.getElementById('modal-bg').classList.add('open');
        }

        function openEditModal(item) {
          document.getElementById('modal-title').textContent = 'Edit Item';
          document.getElementById('edit-id').value  = item.id;
          document.getElementById('f-name').value   = item.name;
          document.getElementById('f-emoji').value  = item.emoji;
          document.getElementById('f-price').value  = item.price;
          document.getElementById('f-stock').value  = item.stock;
          buildCatOptions(item.category);
          document.getElementById('modal-bg').classList.add('open');
        }

        function closeModal() { document.getElementById('modal-bg').classList.remove('open'); }

        async function saveItem() {
          const id   = document.getElementById('edit-id').value;
          const body = JSON.stringify({
            name:     document.getElementById('f-name').value,
            category: document.getElementById('f-cat').value,
            emoji:    document.getElementById('f-emoji').value,
            price:    parseFloat(document.getElementById('f-price').value),
            stock:    parseInt(document.getElementById('f-stock').value),
          });
          try {
            if (id) await apiFetch(`/api/inventory/${id}`, { method:'PUT', body });
            else    await apiFetch('/api/inventory', { method:'POST', body });
            closeModal();
            await loadInventory();
            showToast(id ? 'Item updated.' : 'Item added.');
          } catch (e) { alert('Save failed: ' + e.message); }
        }

        async function deleteItem(id) {
          if (!confirm('Delete this item?')) return;
          try {
            await apiFetch(`/api/inventory/${id}`, { method:'DELETE' });
            await loadInventory();
            showToast('Item deleted.');
          } catch (e) { alert('Delete failed: ' + e.message); }
        }

        // ── Restock modal ─────────────────────────────────────────────────────
        // Restock is a focused workflow: shows only the stock field so warehouse
        // staff can quickly adjust levels without accidentally editing other fields.
        function openRestock(item) {
          document.getElementById('restock-id').value      = item.id;
          document.getElementById('restock-name').textContent = item.name;
          document.getElementById('restock-current').textContent = item.stock;
          document.getElementById('restock-qty').value    = item.stock;
          document.getElementById('restock-item-json').value = JSON.stringify(item);
          document.getElementById('restock-bg').classList.add('open');
        }

        function closeRestock() { document.getElementById('restock-bg').classList.remove('open'); }

        async function saveRestock() {
          const id   = document.getElementById('restock-id').value;
          const qty  = parseInt(document.getElementById('restock-qty').value);
          const item = JSON.parse(document.getElementById('restock-item-json').value);
          const body = JSON.stringify({ ...item, stock: qty });
          try {
            await apiFetch(`/api/inventory/${id}`, { method:'PUT', body });
            closeRestock();
            await loadInventory();
            showToast(`Stock updated to ${qty}.`);
          } catch (e) { alert('Update failed: ' + e.message); }
        }

        (async () => { await loadSettings(); await loadInventory(); })();
      </script>
    </body>
    </html>
    """;
}

// ── Signed-out page ───────────────────────────────────────────────────────────
// Unlike InteractiveAuthWithWebAPI there is no /login route — IWA re-login
// requires restarting the process. The page explains this clearly.
static string BuildSignedOutHtml() => """
    <!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/>
    <style>
      *, *::before, *::after { box-sizing:border-box; margin:0; padding:0; }
      body { font-family:"Segoe UI",system-ui,sans-serif; background:#f0f4f8;
             color:#1e293b; display:flex; align-items:center;
             justify-content:center; height:100vh; }
      .box { text-align:center; max-width:380px; }
      h2 { font-size:1.3rem; margin-bottom:10px; color:#1e3a5f; }
      p  { color:#64748b; font-size:.88rem; line-height:1.6; }
    </style>
    </head><body>
      <div class="box">
        <div style="font-size:2.5rem;margin-bottom:16px">🪟</div>
        <h2>You have been signed out.</h2>
        <p>IWA authentication is tied to the current Windows session.<br/>
           Restart the application to sign in again.</p>
      </div>
    </body></html>
    """;

// ── HTML response helper ──────────────────────────────────────────────────────
static async Task RespondWithHtml(HttpListenerContext ctx, string html)
{
    byte[] bytes = System.Text.Encoding.UTF8.GetBytes(html);
    ctx.Response.ContentType     = "text/html; charset=utf-8";
    ctx.Response.ContentLength64 = bytes.Length;
    await ctx.Response.OutputStream.WriteAsync(bytes);
    ctx.Response.Close();
}

// ── Cookie helpers ────────────────────────────────────────────────────────────
static string? GetSessionCookie(HttpListenerContext ctx)
{
    string? hdr = ctx.Request.Headers["Cookie"];
    if (hdr is null) return null;
    foreach (string part in hdr.Split(';'))
    {
        string[] kv = part.Trim().Split('=', 2);
        if (kv.Length == 2 && kv[0].Trim() == "session") return kv[1].Trim();
    }
    return null;
}

static void SetSessionCookie(HttpListenerContext ctx, string sid)
    => ctx.Response.Headers.Add("Set-Cookie", $"session={sid}; Path=/; HttpOnly; SameSite=Lax");

static void ClearSessionCookie(HttpListenerContext ctx)
    => ctx.Response.Headers.Add("Set-Cookie", "session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");

static void SendRedirect(HttpListenerContext ctx, string location)
{
    ctx.Response.StatusCode        = 302;
    ctx.Response.RedirectLocation  = location;
    ctx.Response.ContentLength64   = 0;
    ctx.Response.Close();
}

// ── Token summary console output ──────────────────────────────────────────────
void ShowTokenSummary(TokenResult result)
{
    string fullName = ExtractNameFromJwt(result.AccessToken);
    Console.ForegroundColor = ConsoleColor.Green;
    Console.Write("Successfully authenticated via IWA");
    if (!string.IsNullOrEmpty(fullName))
        Console.Write($" — Welcome, {fullName}!");
    Console.WriteLine();
    Console.ResetColor();
    Console.WriteLine($"Account:        {result.Username}");
    Console.WriteLine($"Token expires:  {result.ExpiresOn.ToLocalTime():g}");
    Console.WriteLine($"Scopes granted: {string.Join(", ", result.Scopes)}");
    Console.WriteLine();
}

// ── JWT helpers ───────────────────────────────────────────────────────────────
static string ExtractNameFromJwt(string jwt)
{
    try
    {
        string[] parts = jwt.Split('.');
        if (parts.Length < 2) return string.Empty;
        string payload = parts[1].Replace('-', '+').Replace('_', '/');
        payload += new string('=', (4 - payload.Length % 4) % 4);
        using JsonDocument doc = JsonDocument.Parse(Convert.FromBase64String(payload));
        JsonElement root = doc.RootElement;
        string? first = null, last = null;
        foreach (string c in new[] { "Firstname", "given_name" })
            if (root.TryGetProperty(c, out JsonElement v) && v.ValueKind == JsonValueKind.String)
            { first = v.GetString(); break; }
        foreach (string c in new[] { "Lastname", "family_name" })
            if (root.TryGetProperty(c, out JsonElement v) && v.ValueKind == JsonValueKind.String)
            { last = v.GetString(); break; }
        return string.Join(" ", new[] { first, last }.Where(s => !string.IsNullOrWhiteSpace(s)));
    }
    catch { }
    return string.Empty;
}

static string? ExtractJwtClaim(string jwt, string claimName)
{
    try
    {
        string[] parts = jwt.Split('.');
        if (parts.Length < 2) return null;
        string payload = parts[1].Replace('-', '+').Replace('_', '/');
        payload += new string('=', (4 - payload.Length % 4) % 4);
        using JsonDocument doc = JsonDocument.Parse(Convert.FromBase64String(payload));
        if (doc.RootElement.TryGetProperty(claimName, out JsonElement v) && v.ValueKind == JsonValueKind.String)
            return v.GetString();
    }
    catch { }
    return null;
}

static string ExtractUpnFromJwt(string jwt)
{
    try
    {
        string[] parts = jwt.Split('.');
        if (parts.Length < 2) return "unknown";
        string payload = parts[1].Replace('-', '+').Replace('_', '/');
        payload += new string('=', (4 - payload.Length % 4) % 4);
        using JsonDocument doc = JsonDocument.Parse(Convert.FromBase64String(payload));
        JsonElement root = doc.RootElement;
        foreach (string claim in new[] { "preferred_username", "upn", "unique_name", "sub" })
            if (root.TryGetProperty(claim, out JsonElement v) && v.ValueKind == JsonValueKind.String)
                return v.GetString()!;
    }
    catch { }
    return "unknown";
}

// ── OIDC discovery ────────────────────────────────────────────────────────────
static async Task<string?> GetEndSessionEndpoint(string authority)
{
    try
    {
        string metaUrl = authority.TrimEnd('/') + "/.well-known/openid-configuration";
        using var http = new HttpClient();
        string json = await http.GetStringAsync(metaUrl);
        using JsonDocument doc = JsonDocument.Parse(json);
        if (doc.RootElement.TryGetProperty("end_session_endpoint", out JsonElement ep))
            return ep.GetString();
    }
    catch { }
    return null;
}

// ── Browser launcher ──────────────────────────────────────────────────────────
static void OpenBrowser(string url)
{
    try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
    catch { Console.WriteLine($"Open this URL in your browser:\n{url}"); }
}

// ── Value type for token results ──────────────────────────────────────────────
record TokenResult(string AccessToken, string? IdToken, DateTimeOffset ExpiresOn, IReadOnlyList<string> Scopes, string Username);

// ── Native window handle helpers (WAM parent window requirement) ───────────────
// WAM requires a parent HWND so it can anchor its interactive UI to the correct
// window. For console apps we retrieve the console window handle via kernel32's
// GetConsoleWindow, then walk to its root owner via user32's GetAncestor to get
// a stable top-level HWND that won't move or close unexpectedly.
// These P/Invokes are Windows-only; the WAM path is already guarded by
// OperatingSystem.IsWindows() in AcquireTokenWam so they will never be reached
// on non-Windows platforms.
static class NativeMethods
{
    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();

    // GetAncestor(hwnd, GA_ROOTOWNER=3) walks the owner chain to find the top-level
    // root window. This is more stable than using the raw console handle directly.
    [System.Runtime.InteropServices.DllImport("user32.dll", ExactSpelling = true)]
    private static extern IntPtr GetAncestor(IntPtr hwnd, uint flags);

    public static IntPtr GetConsoleOrTerminalWindow()
    {
        IntPtr consoleHandle = GetConsoleWindow();
        // GA_ROOTOWNER = 3: retrieves the owned root window by walking the owner chain
        return GetAncestor(consoleHandle, 3);
    }
}
