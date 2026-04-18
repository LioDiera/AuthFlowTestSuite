using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);

// ── JWT Bearer authentication ──────────────────────────────────────────────
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        // Accepts tokens from both Entra ID and ADFS — configured in appsettings.json.
        // Authority is used for OIDC metadata discovery (.well-known/openid-configuration).
        options.Authority = builder.Configuration["Auth:Authority"];
        options.Audience  = builder.Configuration["Auth:Audience"];

        options.TokenValidationParameters.ValidateIssuer   = false; // multi-issuer (Entra + ADFS)
        options.TokenValidationParameters.ValidateAudience =
            !string.IsNullOrWhiteSpace(builder.Configuration["Auth:Audience"]);
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
