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
    string? redirectUri  = cfg["EntraId:RedirectUri"];
    bool usePkce         = bool.TryParse(cfg["EntraId:UsePkce"], out bool ep) && ep;
    string[] scopes      = cfg.GetSection("EntraId:Scopes")
        .GetChildren()
        .Select(c => c.Value!)
        .Where(v => !string.IsNullOrEmpty(v))
        .DefaultIfEmpty("User.Read")
        .ToArray();

    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("══ Entra ID ══════════════════════════════════════════════");
    Console.ResetColor();

    TokenResult? result;

    if (IsConfigured(clientSecret))
    {
        string tokenEndpoint = $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token";
        var builder = ConfidentialClientApplicationBuilder
            .Create(clientId)
            .WithAuthority(AzureCloudInstance.AzurePublic, tenantId)
            .WithClientSecret(clientSecret!);
        result = await AcquireTokenConfidential(builder, scopes, tokenEndpoint, clientId, clientSecret!, redirectUri, usePkce);
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
    string? redirectUri  = cfg["Adfs:RedirectUri"];
    bool usePkce         = bool.TryParse(cfg["Adfs:UsePkce"], out bool ap) && ap;
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

    TokenResult? result;

    if (IsConfigured(clientSecret))
    {
        if (!IsConfigured(redirectUri))
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("ADFS confidential client requires a fixed RedirectUri in appsettings.json.");
            Console.WriteLine("ADFS does not support the localhost exception — register an exact URI (e.g. http://localhost:8400/) in AD FS and set it here.");
            Console.ResetColor();
            return;
        }
        string tokenEndpoint = authority.TrimEnd('/') + "/oauth2/token";
        var builder = ConfidentialClientApplicationBuilder
            .Create(clientId)
            .WithAdfsAuthority(authority)
            .WithClientSecret(clientSecret!);
        result = await AcquireTokenConfidential(builder, scopes, tokenEndpoint, clientId, clientSecret!, redirectUri!, usePkce);
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
async Task<TokenResult?> AcquireTokenPublic(IPublicClientApplication app, string[] scopes)
{
    Console.WriteLine("Opening browser for interactive sign-in...");
    Console.WriteLine();
    try
    {
        AuthenticationResult r = await app.AcquireTokenInteractive(scopes)
            .WithUseEmbeddedWebView(false)
            .ExecuteAsync();
        return new TokenResult(r.AccessToken, r.IdToken, r.ExpiresOn, r.Scopes.ToArray(), r.Account.Username);
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
// fixedRedirectUri: when set (required for ADFS), uses that exact URI;
// when null (Entra ID), picks a free port dynamically.
// usePkce: adds code_challenge to the auth URL; token exchange done via raw HTTP POST
//          so code_verifier lands in the POST body (WithExtraQueryParameters puts it in the URL).
async Task<TokenResult?> AcquireTokenConfidential(
    ConfidentialClientApplicationBuilder appBuilder, string[] scopes,
    string tokenEndpoint, string clientId, string clientSecret,
    string? fixedRedirectUri = null, bool usePkce = false)
{
    string redirectUri = IsConfigured(fixedRedirectUri)
        ? fixedRedirectUri!.TrimEnd('/') + "/"
        : $"http://localhost:{GetFreePort()}/";

    // Build the app with the redirect URI so MSAL includes it in the token exchange POST
    IConfidentialClientApplication app = appBuilder
        .WithRedirectUri(redirectUri)
        .Build();

    // Generate a random state value to protect against CSRF
    string state = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));

    Console.WriteLine($"Mode:         confidential client{(usePkce ? " + PKCE" : " (no PKCE)")}");

    // Build the authorization URL, optionally enabling PKCE.
    // WithPkce generates the code_verifier internally and adds code_challenge to the auth URL.
    string? codeVerifier = null;
    var pkceParams = new Dictionary<string, (string, bool)> { ["state"] = (state, false) };
    if (usePkce)
    {
        codeVerifier = GeneratePkceVerifier();
        pkceParams["code_challenge"]        = (GeneratePkceChallenge(codeVerifier), false);
        pkceParams["code_challenge_method"] = ("S256", false);
    }

    var authUrlBuilder = app.GetAuthorizationRequestUrl(scopes)
        .WithRedirectUri(redirectUri)
        .WithExtraQueryParameters(pkceParams);

    Uri authUri = await authUrlBuilder.ExecuteAsync();

    using var listener = new HttpListener();
    listener.Prefixes.Add(redirectUri);
    listener.Start();

    Console.WriteLine("Opening browser for interactive sign-in...");
    Console.WriteLine($"Redirect URI: {redirectUri}");
    Console.WriteLine();
    OpenBrowser(authUri.AbsoluteUri);

    HttpListenerContext ctx = await listener.GetContextAsync();

    // Respond to the browser immediately
    const string html = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1" />
          <title>Sweet Sales — Sign In</title>
          <style>
            *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

            body {
              min-height: 100vh;
              display: flex;
              flex-direction: column;
              font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
              background: #fdf6ee;
              color: #2c1a0e;
            }

            /* ── Top nav bar ── */
            header {
              background: #7b3f00;
              color: #fff;
              padding: 0 32px;
              height: 56px;
              display: flex;
              align-items: center;
              justify-content: space-between;
              box-shadow: 0 2px 6px rgba(0,0,0,0.25);
            }

            .brand {
              display: flex; align-items: center; gap: 10px;
              font-size: 1.15rem; font-weight: 700; letter-spacing: 0.2px;
            }
            .brand-icon { font-size: 1.5rem; }

            nav { display: flex; gap: 24px; font-size: 0.85rem; opacity: 0.75; }
            nav span { cursor: pointer; }
            nav span:hover { opacity: 1; }

            /* ── Main layout ── */
            main {
              flex: 1;
              display: grid;
              grid-template-columns: 260px 1fr 280px;
              gap: 0;
            }

            /* ── Left sidebar: categories ── */
            .sidebar {
              background: #fff8f0;
              border-right: 1px solid #e8d5c0;
              padding: 20px 16px;
            }
            .sidebar h3 {
              font-size: 0.7rem;
              text-transform: uppercase;
              letter-spacing: 1px;
              color: #a0714f;
              margin-bottom: 12px;
            }
            .cat-item {
              display: flex; align-items: center; gap: 10px;
              padding: 10px 12px;
              border-radius: 10px;
              cursor: pointer;
              font-size: 0.9rem;
              transition: background 0.15s;
              margin-bottom: 4px;
            }
            .cat-item:hover  { background: #f4e4d4; }
            .cat-item.active { background: #7b3f00; color: #fff; }
            .cat-item .emoji { font-size: 1.2rem; }

            /* ── Product grid ── */
            .products {
              padding: 24px;
              overflow-y: auto;
            }
            .products h2 {
              font-size: 1.1rem; font-weight: 600; margin-bottom: 18px; color: #5c2d0a;
            }
            .grid {
              display: grid;
              grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
              gap: 16px;
            }
            .product-card {
              background: #fff;
              border: 1px solid #e8d5c0;
              border-radius: 14px;
              padding: 16px 12px;
              text-align: center;
              cursor: pointer;
              transition: transform 0.15s, box-shadow 0.15s;
              position: relative;
            }
            .product-card:hover {
              transform: translateY(-3px);
              box-shadow: 0 8px 20px rgba(123,63,0,0.12);
            }
            .product-card .big-emoji { font-size: 2.4rem; display: block; margin-bottom: 8px; }
            .product-card .name      { font-size: 0.85rem; font-weight: 600; margin-bottom: 4px; }
            .product-card .price     { font-size: 0.8rem; color: #a0714f; }
            .badge {
              position: absolute; top: 8px; right: 8px;
              background: #e05c00; color: #fff;
              font-size: 0.65rem; font-weight: 700;
              padding: 2px 7px; border-radius: 20px;
            }

            /* ── Right: order summary / auth overlay ── */
            .order-panel {
              background: #fff;
              border-left: 1px solid #e8d5c0;
              display: flex;
              flex-direction: column;
              padding: 24px 20px;
            }
            .order-panel h3 { font-size: 1rem; font-weight: 700; margin-bottom: 16px; color: #5c2d0a; }

            .order-item {
              display: flex; justify-content: space-between; align-items: center;
              padding: 8px 0;
              border-bottom: 1px dashed #e8d5c0;
              font-size: 0.85rem;
            }
            .order-item .qty {
              background: #fde8d0; border-radius: 6px;
              padding: 2px 8px; font-weight: 700; font-size: 0.8rem;
            }

            .total-row {
              display: flex; justify-content: space-between;
              margin-top: 16px; font-weight: 700; font-size: 1rem;
            }

            /* ── Auth success overlay inside order panel ── */
            .auth-banner {
              margin-top: auto;
              background: linear-gradient(135deg, #d4edda, #c3f0d0);
              border: 1px solid #98d9ab;
              border-radius: 12px;
              padding: 16px;
              display: flex;
              align-items: center;
              gap: 12px;
              animation: slide-up 0.4s 0.1s cubic-bezier(0.22,1,0.36,1) both;
            }
            @keyframes slide-up {
              from { opacity:0; transform: translateY(12px); }
              to   { opacity:1; transform: translateY(0); }
            }
            .auth-icon {
              width: 40px; height: 40px; flex-shrink: 0;
              border-radius: 50%;
              background: #28a745;
              display: flex; align-items: center; justify-content: center;
            }
            .auth-icon svg {
              width: 20px; height: 20px;
              stroke: #fff; stroke-width: 2.5;
              stroke-linecap: round; stroke-linejoin: round; fill: none;
            }
            .checkmark { stroke-dasharray: 28; stroke-dashoffset: 28; animation: draw 0.35s 0.5s ease forwards; }
            @keyframes draw { to { stroke-dashoffset: 0; } }
            .auth-text .title { font-size: 0.85rem; font-weight: 700; color: #155724; }
            .auth-text .sub   { font-size: 0.75rem; color: #2d6a3f; margin-top: 2px; }

            footer {
              background: #f5e6d6;
              border-top: 1px solid #e8d5c0;
              text-align: center;
              padding: 10px;
              font-size: 0.72rem;
              color: #b08060;
            }
          </style>
        </head>
        <body>
          <header>
            <div class="brand">
              <span class="brand-icon">🥐</span>
              Sweet Sales POS
            </div>
            <nav>
              <span>Dashboard</span>
              <span>Reports</span>
              <span>Inventory</span>
              <span>Settings</span>
            </nav>
          </header>

          <main>
            <!-- Sidebar -->
            <aside class="sidebar">
              <h3>Categories</h3>
              <div class="cat-item active"><span class="emoji">🥐</span> Pastries</div>
              <div class="cat-item"><span class="emoji">🎂</span> Cakes</div>
              <div class="cat-item"><span class="emoji">🍪</span> Cookies</div>
              <div class="cat-item"><span class="emoji">🥖</span> Breads</div>
              <div class="cat-item"><span class="emoji">🧁</span> Cupcakes</div>
              <div class="cat-item"><span class="emoji">🥧</span> Pies</div>
              <div class="cat-item"><span class="emoji">☕</span> Drinks</div>
            </aside>

            <!-- Product grid -->
            <section class="products">
              <h2>Pastries — Today's Selection</h2>
              <div class="grid">
                <div class="product-card"><span class="big-emoji">🥐</span><div class="name">Butter Croissant</div><div class="price">$3.50</div></div>
                <div class="product-card"><span class="badge">Hot</span><span class="big-emoji">🥨</span><div class="name">Pretzel Twist</div><div class="price">$2.75</div></div>
                <div class="product-card"><span class="big-emoji">🍩</span><div class="name">Glazed Donut</div><div class="price">$2.25</div></div>
                <div class="product-card"><span class="badge">New</span><span class="big-emoji">🧇</span><div class="name">Belgian Waffle</div><div class="price">$5.00</div></div>
                <div class="product-card"><span class="big-emoji">🥯</span><div class="name">Everything Bagel</div><div class="price">$3.00</div></div>
                <div class="product-card"><span class="big-emoji">🍋</span><div class="name">Lemon Danish</div><div class="price">$4.25</div></div>
                <div class="product-card"><span class="big-emoji">🍫</span><div class="name">Pain au Chocolat</div><div class="price">$4.00</div></div>
                <div class="product-card"><span class="badge">Sale</span><span class="big-emoji">🥐</span><div class="name">Almond Croissant</div><div class="price">$3.75</div></div>
              </div>
            </section>

            <!-- Order panel -->
            <aside class="order-panel">
              <h3>Current Order</h3>
              <div class="order-item"><span>Butter Croissant</span><span class="qty">×2</span><span>$7.00</span></div>
              <div class="order-item"><span>Glazed Donut</span><span class="qty">×3</span><span>$6.75</span></div>
              <div class="order-item"><span>Pain au Chocolat</span><span class="qty">×1</span><span>$4.00</span></div>
              <div class="total-row"><span>Total</span><span>$17.75</span></div>

              <div class="auth-banner">
                <div class="auth-icon">
                  <svg viewBox="0 0 24 24"><polyline class="checkmark" points="4,13 9,18 20,7"/></svg>
                </div>
                <div class="auth-text">
                  <div class="title">Signed in successfully</div>
                  <div class="sub">You can close this tab and return to the app.</div>
                </div>
              </div>
            </aside>
          </main>

          <footer>Sweet Sales POS v2.1 — Bakery Edition &nbsp;|&nbsp; © 2026 Crumb & Co.</footer>
          <script>history.replaceState(null, '', location.pathname);</script>
        </body>
        </html>
        """;
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

    if (usePkce && codeVerifier is not null)
    {
        // WithExtraQueryParameters puts params in the URL query string, not the POST body.
        // Entra ID and ADFS require code_verifier in the POST body, so we use a raw HTTP POST.
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
        HttpResponseMessage tokenResp = await http.PostAsync(
            tokenEndpoint, new FormUrlEncodedContent(body));
        string tokenJson = await tokenResp.Content.ReadAsStringAsync();
        if (!tokenResp.IsSuccessStatusCode)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Token exchange failed: {tokenJson}");
            Console.ResetColor();
            return null;
        }
        using JsonDocument doc = JsonDocument.Parse(tokenJson);
        JsonElement root = doc.RootElement;
        string accessToken  = root.GetProperty("access_token").GetString()!;
        string? idToken     = root.TryGetProperty("id_token", out JsonElement idt) ? idt.GetString() : null;
        int expiresIn       = root.TryGetProperty("expires_in", out JsonElement exp) ? exp.GetInt32() : 3600;
        string[] grantedScopes = root.TryGetProperty("scope", out JsonElement sc)
            ? sc.GetString()!.Split(' ', StringSplitOptions.RemoveEmptyEntries)
            : scopes;
        // Extract preferred_username / upn from the id_token or access_token payload
        string username = ExtractUpnFromJwt(idToken ?? accessToken);
        return new TokenResult(accessToken, idToken, DateTimeOffset.UtcNow.AddSeconds(expiresIn), grantedScopes, username);
    }
    else
    {
        try
        {
            AuthenticationResult r = await app.AcquireTokenByAuthorizationCode(scopes, code).ExecuteAsync();
            return new TokenResult(r.AccessToken, r.IdToken, r.ExpiresOn, r.Scopes.ToArray(), r.Account.Username);
        }
        catch (MsalServiceException ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Token exchange failed: {ex.Message}");
            Console.ResetColor();
            return null;
        }
    }
}

// ── Extract UPN/username from a JWT payload (best-effort) ───────────────────
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

// ── PKCE helpers ─────────────────────────────────────────────────────────────
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
void ShowTokenSummary(TokenResult result)
{
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine($"Successfully signed in as: {result.Username}");
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

record TokenResult(string AccessToken, string? IdToken, DateTimeOffset ExpiresOn, IReadOnlyList<string> Scopes, string Username);
