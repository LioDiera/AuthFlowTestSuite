using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Identity.Client;

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

// ── Check if a config value is set ───────────────────────────────────────────
static bool IsConfigured(string? value) =>
    !string.IsNullOrWhiteSpace(value) && !value.StartsWith('<');

// ── Entra ID flow ─────────────────────────────────────────────────────────────
async Task RunEntraIdFlow(IConfiguration cfg)
{
    string tenantId      = cfg["EntraId:TenantId"]!;
    string clientId      = cfg["EntraId:ClientId"]!;
    string? clientSecret = cfg["EntraId:ClientSecret"];
    string? redirectUri  = cfg["EntraId:RedirectUri"];
    bool usePkce         = bool.TryParse(cfg["EntraId:UsePkce"], out bool ep) && ep;
    string apiBaseUrl    = cfg["EntraId:ApiBaseUrl"]!;
    string[] scopes      = cfg.GetSection("EntraId:Scopes").GetChildren()
        .Select(c => c.Value!).Where(v => !string.IsNullOrEmpty(v))
        .DefaultIfEmpty("User.Read").ToArray();

    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("══ Entra ID ══════════════════════════════════════════════");
    Console.ResetColor();

    TokenResult? result;
    if (IsConfigured(clientSecret))
    {
        string tokenEndpoint = $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token";
        var builder = ConfidentialClientApplicationBuilder
            .Create(clientId).WithAuthority(AzureCloudInstance.AzurePublic, tenantId)
            .WithClientSecret(clientSecret!);
        result = await AcquireTokenConfidential(builder, scopes, tokenEndpoint, clientId, clientSecret!, redirectUri, usePkce);
    }
    else
    {
        IPublicClientApplication pub = PublicClientApplicationBuilder
            .Create(clientId).WithAuthority(AzureCloudInstance.AzurePublic, tenantId)
            .WithRedirectUri("http://localhost").Build();
        result = await AcquireTokenPublic(pub, scopes);
    }

    if (result is null) return;
    ShowTokenSummary(result);
    await ServePosApp(result.AccessToken, apiBaseUrl);
}

// ── ADFS flow ─────────────────────────────────────────────────────────────────
async Task RunAdfsFlow(IConfiguration cfg)
{
    string authority     = cfg["Adfs:Authority"]!;
    string clientId      = cfg["Adfs:ClientId"]!;
    string? clientSecret = cfg["Adfs:ClientSecret"];
    string? redirectUri  = cfg["Adfs:RedirectUri"];
    bool usePkce         = bool.TryParse(cfg["Adfs:UsePkce"], out bool ap) && ap;
    string apiBaseUrl    = cfg["Adfs:ApiBaseUrl"]!;
    string[] scopes      = cfg.GetSection("Adfs:Scopes").GetChildren()
        .Select(c => c.Value!).Where(v => !string.IsNullOrEmpty(v))
        .Append("allatclaims").Distinct().ToArray();

    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("══ ADFS ══════════════════════════════════════════════════");
    Console.ResetColor();

    TokenResult? result;
    if (IsConfigured(clientSecret))
    {
        if (!IsConfigured(redirectUri))
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("ADFS confidential client requires a fixed RedirectUri in appsettings.json.");
            Console.ResetColor();
            return;
        }
        string tokenEndpoint = authority.TrimEnd('/') + "/oauth2/token";
        var builder = ConfidentialClientApplicationBuilder
            .Create(clientId).WithAdfsAuthority(authority).WithClientSecret(clientSecret!);
        result = await AcquireTokenConfidential(builder, scopes, tokenEndpoint, clientId, clientSecret!, redirectUri!, usePkce);
    }
    else
    {
        IPublicClientApplication pub = PublicClientApplicationBuilder
            .Create(clientId).WithAdfsAuthority(authority)
            .WithRedirectUri("http://localhost").Build();
        result = await AcquireTokenPublic(pub, scopes);
    }

    if (result is null) return;
    ShowTokenSummary(result);
    await ServePosApp(result.AccessToken, apiBaseUrl);
}

// ── Public client (MSAL handles PKCE) ────────────────────────────────────────
async Task<TokenResult?> AcquireTokenPublic(IPublicClientApplication app, string[] scopes)
{
    Console.WriteLine("Opening browser for interactive sign-in...");
    try
    {
        AuthenticationResult r = await app.AcquireTokenInteractive(scopes)
            .WithUseEmbeddedWebView(false).ExecuteAsync();
        return new TokenResult(r.AccessToken, r.IdToken, r.ExpiresOn, r.Scopes.ToArray(), r.Account.Username);
    }
    catch (MsalClientException ex) when (ex.ErrorCode == "authentication_canceled")
    { Console.WriteLine("Sign-in was cancelled."); return null; }
    catch (MsalServiceException ex) when (ex.ErrorCode == "access_denied")
    { Console.WriteLine("Sign-in was declined."); return null; }
    catch (OperationCanceledException)
    { Console.WriteLine("Sign-in was cancelled."); return null; }
}

// ── Confidential client (manual PKCE, raw HTTP POST for token exchange) ───────
async Task<TokenResult?> AcquireTokenConfidential(
    ConfidentialClientApplicationBuilder appBuilder, string[] scopes,
    string tokenEndpoint, string clientId, string clientSecret,
    string? fixedRedirectUri = null, bool usePkce = false)
{
    string redirectUri = IsConfigured(fixedRedirectUri)
        ? fixedRedirectUri!.TrimEnd('/') + "/"
        : $"http://localhost:{GetFreePort()}/";

    IConfidentialClientApplication app = appBuilder.WithRedirectUri(redirectUri).Build();
    string state = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
    string? codeVerifier = null;

    Console.WriteLine($"Mode: confidential client{(usePkce ? " + PKCE" : " (no PKCE)")}");

    var pkceParams = new Dictionary<string, (string, bool)> { ["state"] = (state, false) };
    if (usePkce)
    {
        codeVerifier = GeneratePkceVerifier();
        pkceParams["code_challenge"]        = (GeneratePkceChallenge(codeVerifier), false);
        pkceParams["code_challenge_method"] = ("S256", false);
    }

    Uri authUri = await app.GetAuthorizationRequestUrl(scopes)
        .WithRedirectUri(redirectUri)
        .WithExtraQueryParameters(pkceParams)
        .ExecuteAsync();

    using var listener = new HttpListener();
    listener.Prefixes.Add(redirectUri);
    listener.Start();

    Console.WriteLine($"Opening browser for sign-in... Redirect URI: {redirectUri}");
    OpenBrowser(authUri.AbsoluteUri);

    HttpListenerContext ctx = await listener.GetContextAsync();
    ctx.Response.StatusCode = 302;
    ctx.Response.RedirectLocation = "http://localhost:8400/";
    ctx.Response.ContentLength64 = 0;
    ctx.Response.Close();
    listener.Stop();

    string rawQuery = ctx.Request.Url?.Query?.TrimStart('?') ?? string.Empty;
    var qs = rawQuery.Split('&', StringSplitOptions.RemoveEmptyEntries)
        .Select(p => p.Split('=', 2)).Where(p => p.Length == 2)
        .ToDictionary(p => Uri.UnescapeDataString(p[0]), p => Uri.UnescapeDataString(p[1]));

    if (qs.TryGetValue("error", out string? err))
    { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine($"Sign-in error: {err}"); Console.ResetColor(); return null; }
    if (!qs.TryGetValue("state", out string? retState) || retState != state)
    { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine("State mismatch — aborting."); Console.ResetColor(); return null; }
    if (!qs.TryGetValue("code", out string? code))
    { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine("No authorization code received."); Console.ResetColor(); return null; }

    if (usePkce && codeVerifier is not null)
    {
        var body = new Dictionary<string, string>
        {
            ["grant_type"]    = "authorization_code",
            ["client_id"]     = clientId,
            ["client_secret"] = clientSecret,
            ["code"]          = code,
            ["redirect_uri"]  = redirectUri,
            ["code_verifier"] = codeVerifier,
            ["scope"]         = string.Join(" ", scopes),
        };
        using var http = new HttpClient();
        HttpResponseMessage resp = await http.PostAsync(tokenEndpoint, new FormUrlEncodedContent(body));
        string json = await resp.Content.ReadAsStringAsync();
        if (!resp.IsSuccessStatusCode)
        { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine($"Token exchange failed: {json}"); Console.ResetColor(); return null; }
        using JsonDocument doc = JsonDocument.Parse(json);
        JsonElement root = doc.RootElement;
        string at   = root.GetProperty("access_token").GetString()!;
        string? idt = root.TryGetProperty("id_token", out JsonElement i) ? i.GetString() : null;
        int exp     = root.TryGetProperty("expires_in", out JsonElement e) ? e.GetInt32() : 3600;
        string[] sc = root.TryGetProperty("scope", out JsonElement s)
            ? s.GetString()!.Split(' ', StringSplitOptions.RemoveEmptyEntries) : scopes;
        return new TokenResult(at, idt, DateTimeOffset.UtcNow.AddSeconds(exp), sc, ExtractUpnFromJwt(idt ?? at));
    }
    else
    {
        try
        {
            AuthenticationResult r = await app.AcquireTokenByAuthorizationCode(scopes, code).ExecuteAsync();
            return new TokenResult(r.AccessToken, r.IdToken, r.ExpiresOn, r.Scopes.ToArray(), r.Account.Username);
        }
        catch (MsalServiceException ex)
        { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine($"Token exchange failed: {ex.Message}"); Console.ResetColor(); return null; }
    }
}

// ── Serve the POS app and proxy /api/* calls to SweetSalesAPI ─────────────────
async Task ServePosApp(string accessToken, string apiBaseUrl)
{
    const string listenOn = "http://localhost:8400/";
    using var listener = new HttpListener();
    listener.Prefixes.Add(listenOn);
    listener.Start();

    // Launch SweetSalesAPI as a child process if it isn't already listening
    Process? apiProcess = null;
    bool portInUse = System.Net.NetworkInformation.IPGlobalProperties
        .GetIPGlobalProperties().GetActiveTcpListeners()
        .Any(e => e.Port == 7001);

    if (!portInUse)
    {
        // Resolve SweetSalesAPI directory relative to this project's source root
        // AppContext.BaseDirectory = bin/Debug/net10.0/ → go up 3 levels to project root, then into SweetSalesAPI
        string apiDir = Path.GetFullPath(
            Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "SweetSalesAPI"));
        apiProcess = new Process
        {
            StartInfo = new ProcessStartInfo("dotnet", "run")
            {
                WorkingDirectory      = apiDir,
                UseShellExecute       = false,
                RedirectStandardOutput = false,
                RedirectStandardError  = false,
                CreateNoWindow        = false,
            }
        };
        apiProcess.Start();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("Starting SweetSalesAPI...");
        Console.ResetColor();
        // Give Kestrel a moment to bind
        await Task.Delay(3000);
    }

    // Ensure API is killed when this process exits
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

    Console.WriteLine();
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine($"Sweet Sales POS running at {listenOn}");
    Console.ResetColor();
    Console.WriteLine("Press Ctrl+C to stop.");

    using HttpClient apiClient = new();
    apiClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

    while (true)
    {
        HttpListenerContext ctx;
        try { ctx = await listener.GetContextAsync(); }
        catch { break; }

        string path = ctx.Request.Url?.AbsolutePath ?? "/";

        // Proxy /api/* → SweetSalesAPI
        if (path.StartsWith("/api/", StringComparison.OrdinalIgnoreCase))
        {
            string targetUrl = apiBaseUrl.TrimEnd('/') + path;
            if (!string.IsNullOrEmpty(ctx.Request.Url?.Query))
                targetUrl += ctx.Request.Url.Query;

            HttpRequestMessage req = new(new HttpMethod(ctx.Request.HttpMethod), targetUrl);
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

        // Serve POS SPA
        await RespondWithHtml(ctx, BuildPosHtml(accessToken));
    }
}

// ── POS HTML — fully interactive SPA backed by /api/inventory and /api/settings ─
static string BuildPosHtml(string accessToken)
{
    string fullName = ExtractNameFromJwt(accessToken);
    return $$"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8"/>
      <meta name="viewport" content="width=device-width, initial-scale=1"/>
      <title>Sweet Sales POS</title>
      <style>
        *, *::before, *::after { box-sizing:border-box; margin:0; padding:0; }
        body { min-height:100vh; display:flex; flex-direction:column;
               font-family:"Segoe UI",system-ui,-apple-system,sans-serif;
               background:#fdf6ee; color:#2c1a0e; }

        /* ── Header ── */
        header { background:#7b3f00; color:#fff; padding:0 28px; height:56px;
                 display:flex; align-items:center; justify-content:space-between;
                 box-shadow:0 2px 6px rgba(0,0,0,.25); flex-shrink:0; }
        .brand { display:flex; align-items:center; gap:10px; font-size:1.1rem; font-weight:700; }
        nav { display:flex; gap:4px; font-size:.85rem; }
        nav button { background:transparent; border:none; color:rgba(255,255,255,.75);
                     font:inherit; padding:6px 14px; border-radius:8px; cursor:pointer; transition:.15s; }
        nav button:hover, nav button.active { background:rgba(255,255,255,.18); color:#fff; }
        .user-pill { font-size:.8rem; color:rgba(255,255,255,.85); background:rgba(255,255,255,.15);
                     padding:5px 12px; border-radius:20px; white-space:nowrap; }

        /* ── Layout ── */
        main { flex:1; display:grid; grid-template-columns:220px 1fr 300px; min-height:0; overflow:hidden; }

        /* ── Sidebar / Categories ── */
        .sidebar { background:#fff8f0; border-right:1px solid #e8d5c0;
                   padding:20px 14px; overflow-y:auto; }
        .sidebar h3 { font-size:.68rem; text-transform:uppercase; letter-spacing:1px;
                      color:#a0714f; margin-bottom:12px; }
        .cat-item { display:flex; align-items:center; gap:10px; padding:9px 12px;
                    border-radius:10px; cursor:pointer; font-size:.88rem;
                    transition:.15s; margin-bottom:3px; user-select:none; }
        .cat-item:hover  { background:#f4e4d4; }
        .cat-item.active { background:#7b3f00; color:#fff; }
        .cat-item .emoji { font-size:1.15rem; }

        /* ── Content panels ── */
        .panel { padding:22px 24px; overflow-y:auto; }
        .panel h2 { font-size:1.05rem; font-weight:700; margin-bottom:16px; color:#5c2d0a; }

        /* ── Product grid (Dashboard) ── */
        .product-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(148px,1fr)); gap:14px; }
        .product-card { background:#fff; border:1px solid #e8d5c0; border-radius:14px;
                        padding:16px 12px; text-align:center; cursor:pointer; position:relative;
                        transition:.15s; user-select:none; }
        .product-card:hover  { transform:translateY(-3px); box-shadow:0 8px 20px rgba(123,63,0,.13); }
        .product-card:active { transform:translateY(0); }
        .product-card .big-emoji { font-size:2.3rem; display:block; margin-bottom:8px; }
        .product-card .name  { font-size:.82rem; font-weight:600; margin-bottom:3px; }
        .product-card .price { font-size:.78rem; color:#a0714f; }
        .badge { position:absolute; top:8px; right:8px; background:#e05c00; color:#fff;
                 font-size:.62rem; font-weight:700; padding:2px 7px; border-radius:20px; pointer-events:none; }
        .out-card { opacity:.45; cursor:not-allowed; }

        /* ── Toolbar / Table shared ── */
        .toolbar { display:flex; gap:8px; margin-bottom:16px; align-items:center; flex-wrap:wrap; }
        .toolbar input { flex:1; min-width:140px; padding:8px 12px; border:1px solid #e8d5c0;
                         border-radius:8px; font:inherit; font-size:.85rem; }
        .btn { padding:7px 15px; border:none; border-radius:8px; font:inherit;
               font-size:.81rem; font-weight:600; cursor:pointer; transition:.15s; white-space:nowrap; }
        .btn-primary { background:#7b3f00; color:#fff; }
        .btn-primary:hover { background:#6a3600; }
        .btn-danger  { background:#e05c00; color:#fff; }
        .btn-danger:hover { background:#c04e00; }
        .btn-ghost   { background:transparent; border:1px solid #e8d5c0; color:#5c2d0a; }
        .btn-ghost:hover { background:#f4e4d4; }
        .btn-sm { padding:4px 10px; font-size:.76rem; }

        table { width:100%; border-collapse:collapse; font-size:.84rem; }
        thead th { text-align:left; padding:8px 12px; background:#f5e6d6;
                   color:#7b3f00; font-weight:600; border-bottom:2px solid #e8d5c0; }
        tbody tr { border-bottom:1px solid #f0e0cc; }
        tbody tr:hover { background:#fdf0e6; }
        td { padding:8px 12px; vertical-align:middle; }
        td.actions { display:flex; gap:6px; }
        .stock-badge { display:inline-block; padding:2px 8px; border-radius:12px;
                       font-size:.73rem; font-weight:700; }
        .stock-ok  { background:#d4edda; color:#155724; }
        .stock-low { background:#fff3cd; color:#856404; }
        .stock-out { background:#f8d7da; color:#721c24; }

        /* ── Reports ── */
        .kpi-row { display:grid; grid-template-columns:repeat(auto-fill,minmax(160px,1fr)); gap:14px; margin-bottom:24px; }
        .kpi { background:#fff; border:1px solid #e8d5c0; border-radius:14px; padding:18px 16px; }
        .kpi .kpi-label { font-size:.72rem; text-transform:uppercase; letter-spacing:.8px; color:#a0714f; margin-bottom:6px; }
        .kpi .kpi-value { font-size:1.5rem; font-weight:700; color:#5c2d0a; }
        .section-title { font-size:.78rem; font-weight:700; text-transform:uppercase;
                         letter-spacing:.8px; color:#a0714f; margin:0 0 10px; }
        .cat-sales { display:grid; grid-template-columns:1fr; gap:6px; }
        .cat-bar { display:grid; grid-template-columns:90px 1fr 50px; align-items:center; gap:8px; font-size:.82rem; }
        .bar-track { background:#f0e0cc; border-radius:6px; height:8px; overflow:hidden; }
        .bar-fill  { background:#7b3f00; height:100%; border-radius:6px; transition:width .4s; }

        /* ── Settings form ── */
        .settings-form { max-width:440px; }
        .settings-form .form-row { display:flex; flex-direction:column; gap:4px; margin-bottom:16px; }
        .settings-form label { font-size:.78rem; font-weight:600; color:#7b3f00; }
        .settings-form input { padding:8px 10px; border:1px solid #e8d5c0;
                                border-radius:8px; font:inherit; font-size:.85rem; }
        .settings-form input:focus { outline:none; border-color:#7b3f00;
                                      box-shadow:0 0 0 2px rgba(123,63,0,.15); }

        /* ── Modal ── */
        .modal-bg { display:none; position:fixed; inset:0; background:rgba(0,0,0,.35);
                    align-items:center; justify-content:center; z-index:100; }
        .modal-bg.open { display:flex; }
        .modal { background:#fff; border-radius:16px; padding:30px; width:440px;
                 box-shadow:0 24px 64px rgba(0,0,0,.2); }
        .modal h3 { font-size:1rem; font-weight:700; margin-bottom:18px; color:#5c2d0a; }
        .form-row { display:flex; flex-direction:column; gap:4px; margin-bottom:13px; }
        .form-row label { font-size:.78rem; font-weight:600; color:#7b3f00; }
        .form-row input, .form-row select {
            padding:8px 10px; border:1px solid #e8d5c0; border-radius:8px; font:inherit; font-size:.85rem; }
        .form-row input:focus, .form-row select:focus {
            outline:none; border-color:#7b3f00; box-shadow:0 0 0 2px rgba(123,63,0,.15); }
        .modal-actions { display:flex; justify-content:flex-end; gap:8px; margin-top:18px; }

        /* ── Order panel ── */
        .order-panel { background:#fff; border-left:1px solid #e8d5c0;
                       padding:22px 18px; display:flex; flex-direction:column; overflow-y:auto; }
        .order-panel h3 { font-size:1rem; font-weight:700; margin-bottom:14px; color:#5c2d0a; }
        #order-items { flex:1; overflow-y:auto; }
        .order-item { display:grid; grid-template-columns:1fr auto auto; align-items:center;
                      gap:8px; padding:7px 0; border-bottom:1px dashed #e8d5c0; font-size:.84rem; }
        .order-item-name { font-weight:500; }
        .qty-controls { display:flex; align-items:center; gap:4px; }
        .qty-btn { width:22px; height:22px; border:1px solid #e8d5c0; background:#fff;
                   border-radius:6px; font-size:.8rem; font-weight:700; cursor:pointer;
                   display:flex; align-items:center; justify-content:center; transition:.12s; }
        .qty-btn:hover { background:#f4e4d4; }
        .qty-num { min-width:18px; text-align:center; font-weight:700; font-size:.82rem; }
        .order-item-price { font-size:.82rem; color:#5c2d0a; text-align:right; white-space:nowrap; }
        .order-empty { color:#c0a080; font-size:.85rem; text-align:center; padding:24px 0; }
        .order-footer { margin-top:14px; padding-top:12px; border-top:2px solid #e8d5c0; }
        .tax-row, .total-row { display:flex; justify-content:space-between; font-size:.85rem; margin-bottom:5px; }
        .total-row { font-size:1.05rem; font-weight:700; margin-bottom:14px; }
        .checkout-btn { width:100%; padding:11px; background:#7b3f00; color:#fff;
                        border:none; border-radius:10px; font:inherit; font-size:.9rem;
                        font-weight:700; cursor:pointer; transition:.15s; }
        .checkout-btn:hover { background:#6a3600; }
        .checkout-btn:disabled { background:#c0a080; cursor:not-allowed; }
        .clear-btn { width:100%; margin-top:7px; padding:7px; background:transparent;
                     border:1px solid #e8d5c0; border-radius:10px; font:inherit;
                     font-size:.8rem; cursor:pointer; color:#a0714f; transition:.15s; }
        .clear-btn:hover { background:#fdf0e6; }

        /* ── Footer / toast ── */
        footer { background:#f5e6d6; border-top:1px solid #e8d5c0; text-align:center;
                 padding:9px; font-size:.7rem; color:#b08060; flex-shrink:0; }
        .toast { position:fixed; bottom:24px; right:24px; background:#2d6a3f; color:#fff;
                 padding:10px 18px; border-radius:10px; font-size:.82rem; font-weight:600;
                 opacity:0; transition:opacity .3s; pointer-events:none; z-index:300; }
        .toast.show { opacity:1; }
        .toast.error { background:#c0392b; }
      </style>
    </head>
    <body>
      <header>
        <div class="brand" id="brand-name"><span>🥐</span> Sweet Sales POS</div>
        <nav>
          <button class="active" data-tab="dashboard" onclick="showTab('dashboard',this)">Dashboard</button>
          <button data-tab="reports"   onclick="showTab('reports',this)">Reports</button>
          <button data-tab="inventory" onclick="showTab('inventory',this)">Inventory</button>
          <button data-tab="settings"  onclick="showTab('settings',this)">Settings</button>
        </nav>
        {{(string.IsNullOrEmpty(fullName) ? "" : $"<div class=\"user-pill\">👤 {fullName}</div>")}}
      </header>

      <main>
        <!-- ── Sidebar ──────────────────────────────────── -->
        <aside class="sidebar">
          <h3>Categories</h3>
          <div id="cat-list"></div>
        </aside>

        <!-- ── Dashboard ────────────────────────────────── -->
        <section class="panel" id="tab-dashboard">
          <h2 id="dash-heading">All Items</h2>
          <div class="product-grid" id="product-grid"></div>
        </section>

        <!-- ── Reports ──────────────────────────────────── -->
        <section class="panel" id="tab-reports" style="display:none">
          <h2>Reports</h2>
          <div class="kpi-row">
            <div class="kpi"><div class="kpi-label">Items in Inventory</div><div class="kpi-value" id="rpt-total-items">—</div></div>
            <div class="kpi"><div class="kpi-label">Total Stock Units</div><div class="kpi-value" id="rpt-total-stock">—</div></div>
            <div class="kpi"><div class="kpi-label">Low Stock Items</div><div class="kpi-value" id="rpt-low-stock">—</div></div>
            <div class="kpi"><div class="kpi-label">Out of Stock</div><div class="kpi-value" id="rpt-out-stock">—</div></div>
            <div class="kpi"><div class="kpi-label">Avg. Price</div><div class="kpi-value" id="rpt-avg-price">—</div></div>
            <div class="kpi"><div class="kpi-label">Inventory Value</div><div class="kpi-value" id="rpt-inv-value">—</div></div>
          </div>
          <p class="section-title">Stock by Category</p>
          <div class="cat-sales" id="rpt-cat-bars"></div>
        </section>

        <!-- ── Inventory ─────────────────────────────────── -->
        <section class="panel" id="tab-inventory" style="display:none">
          <h2>Inventory</h2>
          <div class="toolbar">
            <input id="search" placeholder="Search items…" oninput="filterTable()" />
            <button class="btn btn-primary" onclick="openAddModal()">+ Add Item</button>
          </div>
          <table>
            <thead><tr><th>Item</th><th>Category</th><th>Price</th><th>Stock</th><th>Actions</th></tr></thead>
            <tbody id="inv-tbody"></tbody>
          </table>
        </section>

        <!-- ── Settings ──────────────────────────────────── -->
        <section class="panel" id="tab-settings" style="display:none">
          <h2>Settings</h2>
          <div class="settings-form">
            <div class="form-row"><label>Store Name</label><input id="s-name" /></div>
            <div class="form-row"><label>Address</label><input id="s-address" /></div>
            <div class="form-row"><label>Currency Symbol</label><input id="s-currency" style="max-width:80px" /></div>
            <div class="form-row"><label>Tax Rate (%)</label><input id="s-tax" type="number" step="0.1" min="0" style="max-width:120px" /></div>
            <button class="btn btn-primary" onclick="saveSettings()">Save Settings</button>
          </div>
        </section>

        <!-- ── Order panel ────────────────────────────────── -->
        <aside class="order-panel">
          <h3>Current Order</h3>
          <div id="order-items"><p class="order-empty">No items yet.<br/>Tap a product to add.</p></div>
          <div class="order-footer">
            <div class="tax-row"><span>Subtotal</span><span id="order-subtotal">$0.00</span></div>
            <div class="tax-row"><span id="tax-label">Tax (8%)</span><span id="order-tax">$0.00</span></div>
            <div class="total-row"><span>Total</span><span id="order-total">$0.00</span></div>
            <button class="checkout-btn" id="checkout-btn" onclick="checkout()" disabled>Checkout</button>
            <button class="clear-btn" onclick="clearOrder()">Clear Order</button>
          </div>
        </aside>
      </main>

      <footer id="footer-bar">Sweet Sales POS v2.1 — Bakery Edition &nbsp;|&nbsp; © 2026 Crumb &amp; Co.</footer>

      <!-- Inventory add/edit modal -->
      <div class="modal-bg" id="modal-bg">
        <div class="modal">
          <h3 id="modal-title">Add Item</h3>
          <input type="hidden" id="edit-id" />
          <div class="form-row"><label>Name</label><input id="f-name" /></div>
          <div class="form-row"><label>Category</label><select id="f-cat"></select></div>
          <div class="form-row"><label>Emoji</label><input id="f-emoji" placeholder="🥐" /></div>
          <div class="form-row"><label>Price</label><input id="f-price" type="number" step="0.01" min="0" /></div>
          <div class="form-row"><label>Stock</label><input id="f-stock" type="number" min="0" /></div>
          <div class="modal-actions">
            <button class="btn btn-ghost" onclick="closeModal()">Cancel</button>
            <button class="btn btn-primary" onclick="saveItem()">Save</button>
          </div>
        </div>
      </div>

      <!-- Checkout confirmation modal -->
      <div class="modal-bg" id="checkout-modal">
        <div class="modal">
          <h3>Order Complete</h3>
          <p id="checkout-summary" style="font-size:.88rem;line-height:1.6;color:#5c2d0a;margin-bottom:20px;"></p>
          <div class="modal-actions">
            <button class="btn btn-primary" onclick="closeCheckout()">Done</button>
          </div>
        </div>
      </div>

      <div class="toast" id="toast"></div>

      <script>
        const TOKEN = '{{accessToken}}';

        // ── API helpers ────────────────────────────────────────────────────────
        async function apiFetch(url, opts = {}) {
          opts.headers = { ...(opts.headers||{}), Authorization:'Bearer '+TOKEN, 'Content-Type':'application/json' };
          const r = await fetch(url, opts);
          if (!r.ok) { const t = await r.text(); throw new Error(t||r.statusText); }
          if (r.status === 204) return null;
          return r.json();
        }

        // ── App state ──────────────────────────────────────────────────────────
        let allItems   = [];
        let settings   = { storeName:'Sweet Sales', address:'', currency:'$', taxRate:8 };
        let order      = {};          // { itemId: qty }
        let activeTab  = 'dashboard';
        let activeCat  = 'All';

        // ── Boot ───────────────────────────────────────────────────────────────
        async function init() {
          await Promise.all([loadInventory(), loadSettings()]);
          renderSidebar();
          renderDashboard();
          renderOrder();
          applySettings();
          showToast('Signed in successfully', false, 3000);
        }

        // ── Settings ───────────────────────────────────────────────────────────
        async function loadSettings() {
          try { settings = await apiFetch('/api/settings'); }
          catch(e) { /* use defaults */ }
        }

        async function saveSettings() {
          settings.storeName = document.getElementById('s-name').value.trim()     || settings.storeName;
          settings.address   = document.getElementById('s-address').value.trim();
          settings.currency  = document.getElementById('s-currency').value.trim() || '$';
          settings.taxRate   = parseFloat(document.getElementById('s-tax').value) || 0;
          try {
            settings = await apiFetch('/api/settings', { method:'PUT', body:JSON.stringify(settings) });
            applySettings();
            renderOrder();
            showToast('Settings saved');
          } catch(e) { showToast('Save failed: '+e.message, true); }
        }

        function applySettings() {
          document.getElementById('brand-name').innerHTML = '<span>🥐</span> ' + settings.storeName;
          document.getElementById('footer-bar').innerHTML =
            settings.storeName + ' POS v2.1' + (settings.address ? ' — '+settings.address : '') + ' &nbsp;|&nbsp; © 2026';
          document.getElementById('tax-label').textContent = 'Tax (' + settings.taxRate + '%)';
          // populate settings form
          document.getElementById('s-name').value     = settings.storeName;
          document.getElementById('s-address').value  = settings.address;
          document.getElementById('s-currency').value = settings.currency;
          document.getElementById('s-tax').value      = settings.taxRate;
        }

        // ── Inventory ──────────────────────────────────────────────────────────
        async function loadInventory() {
          allItems = await apiFetch('/api/inventory');
        }

        function renderSidebar() {
          const cats = ['All', ...new Set(allItems.map(i => i.category))];
          document.getElementById('cat-list').innerHTML = cats.map(c => `
            <div class="cat-item${c===activeCat?' active':''}" onclick="selectCat('${c}',this)">
              <span class="emoji">${catEmoji(c)}</span> ${c}
            </div>`).join('');
        }

        function catEmoji(c) {
          return {All:'🛒',Pastries:'🥐',Cakes:'🎂',Cookies:'🍪',Breads:'🥖',
                  Cupcakes:'🧁',Pies:'🥧',Drinks:'☕'}[c] ?? '📦';
        }

        function selectCat(cat, el) {
          activeCat = cat;
          document.querySelectorAll('.cat-item').forEach(e => e.classList.remove('active'));
          el.classList.add('active');
          if (activeTab === 'dashboard') renderDashboard();
        }

        function renderDashboard() {
          const items = activeCat==='All' ? allItems : allItems.filter(i => i.category===activeCat);
          document.getElementById('dash-heading').textContent =
            (activeCat==='All' ? 'All Items' : activeCat) + ' — Today\'s Selection';
          document.getElementById('product-grid').innerHTML = items.map(i => `
            <div class="product-card${i.stock===0?' out-card':''}" onclick="${i.stock>0?`addToOrder(${i.id})`:''}">
              ${i.stock===0?'<span class="badge">Out</span>':''}
              <span class="big-emoji">${i.emoji}</span>
              <div class="name">${i.name}</div>
              <div class="price">${settings.currency}${i.price.toFixed(2)}</div>
            </div>`).join('');
        }

        // ── Order ──────────────────────────────────────────────────────────────
        function addToOrder(id) {
          order[id] = (order[id]||0) + 1;
          renderOrder();
        }

        function changeQty(id, delta) {
          order[id] = (order[id]||0) + delta;
          if (order[id] <= 0) delete order[id];
          renderOrder();
        }

        function clearOrder() { order = {}; renderOrder(); }

        function renderOrder() {
          const ids = Object.keys(order);
          if (ids.length === 0) {
            document.getElementById('order-items').innerHTML =
              '<p class="order-empty">No items yet.<br/>Tap a product to add.</p>';
          } else {
            document.getElementById('order-items').innerHTML = ids.map(id => {
              const item = allItems.find(i => i.id == id);
              if (!item) return '';
              const lineTotal = item.price * order[id];
              return `<div class="order-item">
                <span class="order-item-name">${item.emoji} ${item.name}</span>
                <span class="qty-controls">
                  <button class="qty-btn" onclick="changeQty(${id},-1)">−</button>
                  <span class="qty-num">${order[id]}</span>
                  <button class="qty-btn" onclick="changeQty(${id},+1)">+</button>
                </span>
                <span class="order-item-price">${settings.currency}${lineTotal.toFixed(2)}</span>
              </div>`;
            }).join('');
          }
          const subtotal = Object.keys(order).reduce((s,id) => {
            const item = allItems.find(i => i.id == id);
            return s + (item ? item.price * order[id] : 0);
          }, 0);
          const tax   = subtotal * (settings.taxRate / 100);
          const total = subtotal + tax;
          document.getElementById('order-subtotal').textContent = settings.currency + subtotal.toFixed(2);
          document.getElementById('order-tax').textContent      = settings.currency + tax.toFixed(2);
          document.getElementById('order-total').textContent    = settings.currency + total.toFixed(2);
          document.getElementById('checkout-btn').disabled      = Object.keys(order).length === 0;
        }

        function checkout() {
          const subtotal = Object.keys(order).reduce((s,id) => {
            const item = allItems.find(i => i.id == id);
            return s + (item ? item.price * order[id] : 0);
          }, 0);
          const tax   = subtotal * (settings.taxRate / 100);
          const total = subtotal + tax;
          const lines = Object.keys(order).map(id => {
            const item = allItems.find(i => i.id == id);
            return item ? `${item.emoji} ${item.name} ×${order[id]} — ${settings.currency}${(item.price*order[id]).toFixed(2)}` : '';
          }).filter(Boolean).join('\n');
          document.getElementById('checkout-summary').innerText =
            lines + `\n\nSubtotal: ${settings.currency}${subtotal.toFixed(2)}\nTax: ${settings.currency}${tax.toFixed(2)}\nTotal: ${settings.currency}${total.toFixed(2)}`;
          document.getElementById('checkout-modal').classList.add('open');
        }

        function closeCheckout() {
          document.getElementById('checkout-modal').classList.remove('open');
          clearOrder();
        }

        // ── Reports ────────────────────────────────────────────────────────────
        function renderReports() {
          const cur = settings.currency;
          document.getElementById('rpt-total-items').textContent = allItems.length;
          document.getElementById('rpt-total-stock').textContent = allItems.reduce((s,i)=>s+i.stock,0);
          document.getElementById('rpt-low-stock').textContent   = allItems.filter(i=>i.stock>0&&i.stock<5).length;
          document.getElementById('rpt-out-stock').textContent   = allItems.filter(i=>i.stock===0).length;
          const avg = allItems.length ? allItems.reduce((s,i)=>s+i.price,0)/allItems.length : 0;
          document.getElementById('rpt-avg-price').textContent   = cur + avg.toFixed(2);
          const val = allItems.reduce((s,i)=>s+i.price*i.stock,0);
          document.getElementById('rpt-inv-value').textContent   = cur + val.toFixed(2);

          const cats = [...new Set(allItems.map(i=>i.category))];
          const maxStock = Math.max(...cats.map(c=>allItems.filter(i=>i.category===c).reduce((s,i)=>s+i.stock,0)),1);
          document.getElementById('rpt-cat-bars').innerHTML = cats.map(c => {
            const stock = allItems.filter(i=>i.category===c).reduce((s,i)=>s+i.stock,0);
            const pct   = Math.round(stock/maxStock*100);
            return `<div class="cat-bar">
              <span>${catEmoji(c)} ${c}</span>
              <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
              <span style="text-align:right">${stock}</span>
            </div>`;
          }).join('');
        }

        // ── Inventory CRUD ─────────────────────────────────────────────────────
        function renderTable(items) {
          document.getElementById('inv-tbody').innerHTML = items.map(i => `
            <tr>
              <td>${i.emoji} ${i.name}</td>
              <td>${i.category}</td>
              <td>${settings.currency}${i.price.toFixed(2)}</td>
              <td><span class="stock-badge ${i.stock===0?'stock-out':i.stock<5?'stock-low':'stock-ok'}">${i.stock}</span></td>
              <td class="actions">
                <button class="btn btn-ghost btn-sm" onclick='openEditModal(${JSON.stringify(i)})'>Edit</button>
                <button class="btn btn-danger btn-sm" onclick="deleteItem(${i.id})">Delete</button>
              </td>
            </tr>`).join('');
        }

        function filterTable() {
          const q = document.getElementById('search').value.toLowerCase();
          renderTable(allItems.filter(i =>
            i.name.toLowerCase().includes(q) || i.category.toLowerCase().includes(q)));
        }

        function buildCatOptions(selected) {
          const cats = [...new Set(allItems.map(i=>i.category))];
          if (!cats.includes(selected) && selected) cats.push(selected);
          document.getElementById('f-cat').innerHTML =
            cats.map(c=>`<option${c===selected?' selected':''}>${c}</option>`).join('');
        }

        function openAddModal() {
          document.getElementById('modal-title').textContent = 'Add Item';
          document.getElementById('edit-id').value = '';
          ['name','emoji','price','stock'].forEach(f => document.getElementById('f-'+f).value = '');
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
            renderTable(allItems);
            renderSidebar();
            showToast(id ? 'Item updated' : 'Item added');
          } catch(e) { showToast('Error: '+e.message, true); }
        }

        async function deleteItem(id) {
          if (!confirm('Delete this item?')) return;
          try {
            await apiFetch(`/api/inventory/${id}`, { method:'DELETE' });
            await loadInventory();
            renderTable(allItems);
            renderSidebar();
            showToast('Item deleted');
          } catch(e) { showToast('Error: '+e.message, true); }
        }

        // ── Tab navigation ─────────────────────────────────────────────────────
        const ALL_TABS = ['dashboard','reports','inventory','settings'];
        function showTab(tab, btn) {
          ALL_TABS.forEach(t =>
            document.getElementById('tab-'+t).style.display = t===tab ? '' : 'none');
          document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
          btn.classList.add('active');
          activeTab = tab;
          if (tab === 'inventory') renderTable(allItems);
          if (tab === 'reports')   renderReports();
          if (tab === 'settings')  applySettings();
        }

        // ── Toast ──────────────────────────────────────────────────────────────
        function showToast(msg, isError=false, ms=2200) {
          const t = document.getElementById('toast');
          t.textContent = msg;
          t.className   = 'toast show' + (isError ? ' error' : '');
          clearTimeout(t._timer);
          t._timer = setTimeout(() => t.classList.remove('show'), ms);
        }

        history.replaceState(null, '', '/');
        init();
      </script>
    </body>
    </html>
    """;
}

// ── Helpers ───────────────────────────────────────────────────────────────────
static async Task RespondWithHtml(HttpListenerContext ctx, string html)
{
    byte[] bytes = System.Text.Encoding.UTF8.GetBytes(html);
    ctx.Response.ContentType     = "text/html; charset=utf-8";
    ctx.Response.ContentLength64 = bytes.Length;
    await ctx.Response.OutputStream.WriteAsync(bytes);
    ctx.Response.Close();
}

void ShowTokenSummary(TokenResult result)
{
    string fullName = ExtractNameFromJwt(result.AccessToken);
    Console.ForegroundColor = ConsoleColor.Green;
    Console.Write("Successfully signed in");
    if (!string.IsNullOrEmpty(fullName))
        Console.Write($" — Welcome, {fullName}!");
    Console.WriteLine();
    Console.ResetColor();
    Console.WriteLine($"Account:        {result.Username}");
    Console.WriteLine($"Token expires:  {result.ExpiresOn.ToLocalTime():g}");
    Console.WriteLine($"Scopes granted: {string.Join(", ", result.Scopes)}");
}

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
        // ADFS uses Firstname/Lastname; Entra uses given_name/family_name
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

static string ExtractUpnFromJwt(string jwt)
{
    try
    {
        string[] parts = jwt.Split('.');
        if (parts.Length < 2) return "unknown";
        string payload = parts[1].Replace('-', '+').Replace('_', '/');
        int pad = (4 - payload.Length % 4) % 4;
        payload += new string('=', pad);
        using JsonDocument doc = JsonDocument.Parse(Convert.FromBase64String(payload));
        JsonElement root = doc.RootElement;
        foreach (string claim in new[] { "preferred_username", "upn", "unique_name", "sub" })
            if (root.TryGetProperty(claim, out JsonElement v) && v.ValueKind == JsonValueKind.String)
                return v.GetString()!;
    }
    catch { }
    return "unknown";
}

static string GeneratePkceVerifier()
{
    Span<byte> buf = stackalloc byte[32];
    System.Security.Cryptography.RandomNumberGenerator.Fill(buf);
    return Base64UrlEncode(buf.ToArray());
}

static string GeneratePkceChallenge(string verifier)
{
    byte[] hash = System.Security.Cryptography.SHA256.HashData(
        System.Text.Encoding.ASCII.GetBytes(verifier));
    return Base64UrlEncode(hash);
}

static string Base64UrlEncode(byte[] bytes)
    => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

static int GetFreePort()
{
    using var tmp = new TcpListener(System.Net.IPAddress.Loopback, 0);
    tmp.Start();
    int port = ((System.Net.IPEndPoint)tmp.LocalEndpoint).Port;
    tmp.Stop();
    return port;
}

static void OpenBrowser(string url)
{
    try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true }); }
    catch { Console.WriteLine($"Open this URL in your browser:\n{url}"); }
}

record TokenResult(string AccessToken, string? IdToken, DateTimeOffset ExpiresOn, IReadOnlyList<string> Scopes, string Username);

