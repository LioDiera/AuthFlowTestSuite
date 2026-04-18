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
    await RespondWithHtml(ctx, "<html><body><p>Signing in, please wait...</p></body></html>");
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

    Console.WriteLine();
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine($"Sweet Sales POS running at {listenOn}");
    Console.ResetColor();
    Console.WriteLine("Opening browser... Press Ctrl+C to stop.");

    OpenBrowser(listenOn);

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

// ── POS HTML — token injected server-side, Inventory tab calls /api/inventory ─
static string BuildPosHtml(string accessToken) => $$"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8"/>
      <meta name="viewport" content="width=device-width, initial-scale=1"/>
      <title>Sweet Sales POS</title>
      <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body { min-height:100vh; display:flex; flex-direction:column;
               font-family:"Segoe UI",system-ui,-apple-system,sans-serif;
               background:#fdf6ee; color:#2c1a0e; }

        header { background:#7b3f00; color:#fff; padding:0 32px; height:56px;
                 display:flex; align-items:center; justify-content:space-between;
                 box-shadow:0 2px 6px rgba(0,0,0,.25); }
        .brand { display:flex; align-items:center; gap:10px; font-size:1.15rem; font-weight:700; }
        nav { display:flex; gap:4px; font-size:.85rem; }
        nav button { background:transparent; border:none; color:rgba(255,255,255,.75);
                     font:inherit; padding:6px 14px; border-radius:8px; cursor:pointer; transition:.15s; }
        nav button:hover, nav button.active { background:rgba(255,255,255,.15); color:#fff; }

        main { flex:1; display:grid; grid-template-columns:220px 1fr 280px; }

        .sidebar { background:#fff8f0; border-right:1px solid #e8d5c0; padding:20px 16px; }
        .sidebar h3 { font-size:.7rem; text-transform:uppercase; letter-spacing:1px;
                      color:#a0714f; margin-bottom:12px; }
        .cat-item { display:flex; align-items:center; gap:10px; padding:10px 12px;
                    border-radius:10px; cursor:pointer; font-size:.9rem; transition:.15s; margin-bottom:4px; }
        .cat-item:hover  { background:#f4e4d4; }
        .cat-item.active { background:#7b3f00; color:#fff; }
        .cat-item .emoji { font-size:1.2rem; }

        .panel { padding:24px; overflow-y:auto; }
        .panel h2 { font-size:1.1rem; font-weight:600; margin-bottom:16px; color:#5c2d0a; }

        .grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(150px,1fr)); gap:16px; }
        .product-card { background:#fff; border:1px solid #e8d5c0; border-radius:14px;
                        padding:16px 12px; text-align:center; cursor:pointer; position:relative; transition:.15s; }
        .product-card:hover { transform:translateY(-3px); box-shadow:0 8px 20px rgba(123,63,0,.12); }
        .product-card .big-emoji { font-size:2.4rem; display:block; margin-bottom:8px; }
        .product-card .name  { font-size:.85rem; font-weight:600; margin-bottom:4px; }
        .product-card .price { font-size:.8rem; color:#a0714f; }
        .badge { position:absolute; top:8px; right:8px; background:#e05c00; color:#fff;
                 font-size:.65rem; font-weight:700; padding:2px 7px; border-radius:20px; }

        .toolbar { display:flex; gap:8px; margin-bottom:16px; align-items:center; }
        .toolbar input { flex:1; padding:8px 12px; border:1px solid #e8d5c0;
                         border-radius:8px; font:inherit; font-size:.85rem; }
        .btn { padding:8px 16px; border:none; border-radius:8px; font:inherit;
               font-size:.82rem; font-weight:600; cursor:pointer; transition:.15s; }
        .btn-primary { background:#7b3f00; color:#fff; }
        .btn-primary:hover { background:#6a3600; }
        .btn-danger  { background:#e05c00; color:#fff; }
        .btn-danger:hover { background:#c04e00; }
        .btn-ghost   { background:transparent; border:1px solid #e8d5c0; color:#5c2d0a; }
        .btn-ghost:hover { background:#f4e4d4; }

        table { width:100%; border-collapse:collapse; font-size:.85rem; }
        thead th { text-align:left; padding:8px 12px; background:#f5e6d6;
                   color:#7b3f00; font-weight:600; border-bottom:2px solid #e8d5c0; }
        tbody tr { border-bottom:1px solid #f0e0cc; }
        tbody tr:hover { background:#fdf0e6; }
        td { padding:8px 12px; vertical-align:middle; }
        td.actions { display:flex; gap:6px; }
        .stock-badge { display:inline-block; padding:2px 8px; border-radius:12px;
                       font-size:.75rem; font-weight:700; }
        .stock-ok  { background:#d4edda; color:#155724; }
        .stock-low { background:#fff3cd; color:#856404; }
        .stock-out { background:#f8d7da; color:#721c24; }

        .modal-bg { display:none; position:fixed; inset:0; background:rgba(0,0,0,.35);
                    align-items:center; justify-content:center; z-index:100; }
        .modal-bg.open { display:flex; }
        .modal { background:#fff; border-radius:16px; padding:32px; width:440px;
                 box-shadow:0 24px 64px rgba(0,0,0,.2); }
        .modal h3 { font-size:1rem; font-weight:700; margin-bottom:20px; color:#5c2d0a; }
        .form-row { display:flex; flex-direction:column; gap:4px; margin-bottom:14px; }
        .form-row label { font-size:.78rem; font-weight:600; color:#7b3f00; }
        .form-row input, .form-row select {
            padding:8px 10px; border:1px solid #e8d5c0; border-radius:8px; font:inherit; font-size:.85rem; }
        .form-row input:focus, .form-row select:focus {
            outline:none; border-color:#7b3f00; box-shadow:0 0 0 2px rgba(123,63,0,.15); }
        .modal-actions { display:flex; justify-content:flex-end; gap:8px; margin-top:20px; }

        .order-panel { background:#fff; border-left:1px solid #e8d5c0; padding:24px 20px;
                       display:flex; flex-direction:column; }
        .order-panel h3 { font-size:1rem; font-weight:700; margin-bottom:16px; color:#5c2d0a; }
        .order-item { display:flex; justify-content:space-between; align-items:center;
                      padding:8px 0; border-bottom:1px dashed #e8d5c0; font-size:.85rem; }
        .order-item .qty { background:#fde8d0; border-radius:6px; padding:2px 8px; font-weight:700; font-size:.8rem; }
        .total-row { display:flex; justify-content:space-between; margin-top:16px; font-weight:700; font-size:1rem; }

        footer { background:#f5e6d6; border-top:1px solid #e8d5c0; text-align:center;
                 padding:10px; font-size:.72rem; color:#b08060; }

        .toast { position:fixed; bottom:24px; right:24px; background:#2d6a3f; color:#fff;
                 padding:10px 18px; border-radius:10px; font-size:.82rem; font-weight:600;
                 opacity:0; transition:opacity .3s; pointer-events:none; z-index:200; }
        .toast.show { opacity:1; }
      </style>
    </head>
    <body>
      <header>
        <div class="brand"><span>🥐</span> Sweet Sales POS</div>
        <nav>
          <button class="active" onclick="showTab('pastries',this)">Dashboard</button>
          <button onclick="showTab('inventory',this)">Inventory</button>
          <button>Reports</button>
          <button>Settings</button>
        </nav>
      </header>

      <main>
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

        <section class="panel" id="pastries-view">
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

        <section class="panel" id="inv-view" style="display:none">
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

        <aside class="order-panel">
          <h3>Current Order</h3>
          <div class="order-item"><span>Butter Croissant</span><span class="qty">×2</span><span>$7.00</span></div>
          <div class="order-item"><span>Glazed Donut</span><span class="qty">×3</span><span>$6.75</span></div>
          <div class="order-item"><span>Pain au Chocolat</span><span class="qty">×1</span><span>$4.00</span></div>
          <div class="total-row"><span>Total</span><span>$17.75</span></div>
        </aside>
      </main>

      <footer>Sweet Sales POS v2.1 — Bakery Edition &nbsp;|&nbsp; © 2026 Crumb & Co.</footer>

      <div class="modal-bg" id="modal-bg">
        <div class="modal">
          <h3 id="modal-title">Add Item</h3>
          <input type="hidden" id="edit-id" />
          <div class="form-row"><label>Name</label><input id="f-name" /></div>
          <div class="form-row"><label>Category</label>
            <select id="f-cat">
              <option>Pastries</option><option>Cakes</option><option>Cookies</option>
              <option>Breads</option><option>Cupcakes</option><option>Pies</option><option>Drinks</option>
            </select>
          </div>
          <div class="form-row"><label>Emoji</label><input id="f-emoji" placeholder="🥐" /></div>
          <div class="form-row"><label>Price ($)</label><input id="f-price" type="number" step="0.01" min="0" /></div>
          <div class="form-row"><label>Stock</label><input id="f-stock" type="number" min="0" /></div>
          <div class="modal-actions">
            <button class="btn btn-ghost" onclick="closeModal()">Cancel</button>
            <button class="btn btn-primary" onclick="saveItem()">Save</button>
          </div>
        </div>
      </div>

      <div class="toast" id="toast"></div>

      <script>
        const TOKEN = '{{accessToken}}';
        const API   = '/api/inventory';
        let allItems = [];

        async function apiFetch(url, opts = {}) {
          opts.headers = { ...(opts.headers||{}), Authorization:'Bearer '+TOKEN, 'Content-Type':'application/json' };
          const r = await fetch(url, opts);
          if (!r.ok) throw new Error(await r.text());
          if (r.status === 204) return null;
          return r.json();
        }

        async function loadInventory() {
          allItems = await apiFetch(API);
          renderTable(allItems);
        }

        function renderTable(items) {
          document.getElementById('inv-tbody').innerHTML = items.map(i => `
            <tr>
              <td>${i.emoji} ${i.name}</td>
              <td>${i.category}</td>
              <td>$${i.price.toFixed(2)}</td>
              <td><span class="stock-badge ${i.stock===0?'stock-out':i.stock<5?'stock-low':'stock-ok'}">${i.stock}</span></td>
              <td class="actions">
                <button class="btn btn-ghost" onclick='openEditModal(${JSON.stringify(i)})'>Edit</button>
                <button class="btn btn-danger" onclick="deleteItem(${i.id})">Delete</button>
              </td>
            </tr>`).join('');
        }

        function filterTable() {
          const q = document.getElementById('search').value.toLowerCase();
          renderTable(allItems.filter(i => i.name.toLowerCase().includes(q) || i.category.toLowerCase().includes(q)));
        }

        function showTab(tab, btn) {
          document.getElementById('pastries-view').style.display = tab==='pastries' ? '' : 'none';
          document.getElementById('inv-view').style.display      = tab==='inventory' ? '' : 'none';
          document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
          btn.classList.add('active');
          if (tab === 'inventory') loadInventory();
        }

        function openAddModal() {
          document.getElementById('modal-title').textContent = 'Add Item';
          document.getElementById('edit-id').value = '';
          ['name','emoji','price','stock'].forEach(f => document.getElementById('f-'+f).value = '');
          document.getElementById('f-cat').value = 'Pastries';
          document.getElementById('modal-bg').classList.add('open');
        }

        function openEditModal(item) {
          document.getElementById('modal-title').textContent = 'Edit Item';
          document.getElementById('edit-id').value  = item.id;
          document.getElementById('f-name').value   = item.name;
          document.getElementById('f-cat').value    = item.category;
          document.getElementById('f-emoji').value  = item.emoji;
          document.getElementById('f-price').value  = item.price;
          document.getElementById('f-stock').value  = item.stock;
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
            if (id) await apiFetch(`${API}/${id}`, { method:'PUT', body });
            else    await apiFetch(API, { method:'POST', body });
            closeModal();
            showToast(id ? 'Item updated' : 'Item added');
            await loadInventory();
          } catch(e) { alert('Error: ' + e.message); }
        }

        async function deleteItem(id) {
          if (!confirm('Delete this item?')) return;
          try {
            await apiFetch(`${API}/${id}`, { method:'DELETE' });
            showToast('Item deleted');
            await loadInventory();
          } catch(e) { alert('Error: ' + e.message); }
        }

        function showToast(msg) {
          const t = document.getElementById('toast');
          t.textContent = msg;
          t.classList.add('show');
          setTimeout(() => t.classList.remove('show'), 2500);
        }

        history.replaceState(null, '', '/');
      </script>
    </body>
    </html>
    """;

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
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine($"Successfully signed in as: {result.Username}");
    Console.ResetColor();
    Console.WriteLine($"Token expires:  {result.ExpiresOn.ToLocalTime():g}");
    Console.WriteLine($"Scopes granted: {string.Join(", ", result.Scopes)}");
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

