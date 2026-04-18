using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);

// ── JWT Bearer authentication — supports both Entra ID and ADFS ───────────
// A policy scheme peeks at the token's issuer and forwards to the right handler.
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme         = "MultiIssuer";
    options.DefaultChallengeScheme = "MultiIssuer";
})
.AddPolicyScheme("MultiIssuer", "Entra ID or ADFS", options =>
{
    options.ForwardDefaultSelector = ctx =>
    {
        var authHeader = ctx.Request.Headers.Authorization.FirstOrDefault();
        if (authHeader?.StartsWith("Bearer ") == true)
        {
            var parts = authHeader["Bearer ".Length..].Split('.');
            if (parts.Length >= 2)
            {
                var padded = parts[1].PadRight(parts[1].Length + (4 - parts[1].Length % 4) % 4, '=');
                try
                {
                    var payload = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(padded));
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
    options.RequireHttpsMetadata = builder.Configuration["Adfs:Authority"]?.StartsWith("https") == true;
});

builder.Services.AddAuthorization();
builder.Services.AddControllers();

// ── CORS: allow the console app's local listener origin ───────────────────
builder.Services.AddCors(o => o.AddPolicy("LocalhostOnly", p =>
    p.WithOrigins("http://localhost:8400", "http://127.0.0.1:8400")
     .AllowAnyMethod()
     .AllowAnyHeader()));

var app = builder.Build();

app.UseCors("LocalhostOnly");
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
