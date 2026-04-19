using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);

// ── JWT Bearer authentication — supports both Entra ID and ADFS ───────────
// We need to accept tokens from two different issuers (Entra ID and ADFS)
// with a single API. ASP.NET Core's policy scheme is the standard way to do
// this: a lightweight "router" scheme is set as the default, and its
// ForwardDefaultSelector inspects each incoming token to decide which real
// JwtBearer handler should validate it. The two handlers run independently
// with their own Authority / Audience settings.
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme         = "MultiIssuer";
    options.DefaultChallengeScheme = "MultiIssuer";
})
.AddPolicyScheme("MultiIssuer", "Entra ID or ADFS", options =>
{
    options.ForwardDefaultSelector = ctx =>
    {
        // Decode the JWT payload (header.payload.signature) without verifying
        // the signature — we only need to read the 'iss' claim to pick the
        // right handler. Signature verification is done by the selected handler.
        var authHeader = ctx.Request.Headers.Authorization.FirstOrDefault();
        if (authHeader?.StartsWith("Bearer ") == true)
        {
            var parts = authHeader["Bearer ".Length..].Split('.');
            if (parts.Length >= 2)
            {
                // JWT uses base64url encoding (no padding); restore padding before decoding.
                var padded = parts[1].PadRight(parts[1].Length + (4 - parts[1].Length % 4) % 4, '=');
                try
                {
                    var payload = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(padded));
                    // Entra ID tokens have an 'iss' containing login.windows.net or
                    // login.microsoftonline.com; ADFS tokens contain the on-prem ADFS authority.
                    if (payload.Contains("windows.net") || payload.Contains("microsoftonline"))
                        return "EntraId";
                }
                catch { /* malformed token — fall through to ADFS */ }
            }
        }
        return "Adfs";
    };
})
.AddJwtBearer("EntraId", options =>
{
    options.Authority = builder.Configuration["EntraId:Authority"];
    options.Audience  = builder.Configuration["EntraId:Audience"];
    // Issuer validation is disabled because Entra ID v2.0 tokens can come from
    // multiple tenant-specific issuers (e.g. per-tenant GUIDs). Audience validation
    // is enabled only when an explicit audience is configured in appsettings.json.
    options.TokenValidationParameters.ValidateIssuer   = false;
    options.TokenValidationParameters.ValidateAudience =
        !string.IsNullOrWhiteSpace(builder.Configuration["EntraId:Audience"]);
})
.AddJwtBearer("Adfs", options =>
{
    options.Authority = builder.Configuration["Adfs:Authority"];
    options.Audience  = builder.Configuration["Adfs:Audience"];
    options.TokenValidationParameters.ValidateIssuer   = false;
    options.TokenValidationParameters.ValidateAudience =
        !string.IsNullOrWhiteSpace(builder.Configuration["Adfs:Audience"]);
    // ADFS metadata is at /adfs/.well-known/openid-configuration
    options.MetadataAddress = builder.Configuration["Adfs:Authority"]?.TrimEnd('/') + "/.well-known/openid-configuration";
    // Allow HTTP in dev/lab environments where ADFS isn't behind TLS.
    options.RequireHttpsMetadata = builder.Configuration["Adfs:Authority"]?.StartsWith("https") == true;
});

builder.Services.AddAuthorization();
builder.Services.AddControllers();

// ── CORS: allow the console app's local listener origin ───────────────────
// The SPA is served from http://localhost:8400/ (by the console app's
// HttpListener). For browser fetch() calls to /api/* the proxy in the console
// app rewrites them to http://localhost:7001/, so CORS headers must permit
// that origin. 127.0.0.1 is included in case the browser resolves localhost
// to the IPv4 loopback instead of the IPv6 one.
builder.Services.AddCors(o => o.AddPolicy("LocalhostOnly", p =>
    p.WithOrigins("http://localhost:8400", "http://127.0.0.1:8400")
     .AllowAnyMethod()
     .AllowAnyHeader()));

var app = builder.Build();

// Middleware order matters: CORS must run before authentication so pre-flight
// OPTIONS requests are answered before the auth middleware rejects them.
app.UseCors("LocalhostOnly");
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
