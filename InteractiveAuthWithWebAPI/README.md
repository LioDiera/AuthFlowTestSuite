# InteractiveAuthWithWebAPI

A .NET 10 solution that combines **Authorization Code + PKCE** sign-in with a live **protected Web API**. It contains two runnable projects:

| Project | Role |
|---|---|
| **InteractiveAuthWithWebAPI** | Console app — handles sign-in, then serves the Sweet Sales POS SPA and proxies API requests |
| **SweetSalesAPI** | ASP.NET Core Web API — exposes a JWT-protected `/api/inventory` CRUD endpoint |

After sign-in the console app opens `http://localhost:8400/` in your default browser. The **Inventory** tab calls `/api/inventory` live through the proxy — full create, edit, and delete operations are supported.

## Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download)
- [VS Code](https://code.visualstudio.com/) with the [C# Dev Kit](https://marketplace.visualstudio.com/items?itemName=ms-dotnettools.csdevkit) extension
- A **Microsoft Entra ID** tenant or an **ADFS 2019+** deployment (or both)
- nuget.org configured as a package source. If you haven't done this before, run:
  ```
  dotnet nuget add source https://api.nuget.org/v3/index.json --name nuget.org
  ```

## 1. Configure the App Registration

### Entra ID

In the [Azure portal](https://portal.azure.com):

1. Go to **Microsoft Entra ID → App registrations → New registration**
2. Give it a name, select **Web** as the platform, set the redirect URI to `http://localhost:8400`, and click **Register**
3. On the **Certificates & secrets** tab, create a new **client secret** and copy its value
4. On the **API permissions** tab, add a delegated permission from your API (or `User.Read` for a basic test), then grant admin consent
5. If you created a separate API app registration (for `SweetSalesAPI`):
   - Register it too, then **Expose an API → Add a scope** (e.g. `access_as_user`)
   - Grant your client app permission to that scope
   - Note the **Application ID URI** — that becomes the base of your `Scopes` value

### ADFS

On your ADFS server (requires ADFS 2019 or later):

1. Open **AD FS Management** and go to **Application Groups → Add Application Group**
2. Select **Server application accessing a web API** and give it a name
3. Copy the **Client Identifier** and provide the redirect URI `http://localhost:8400`
4. On the **Configure Application Credentials** screen, choose **Generate a shared secret** and copy the value
5. On the **Configure Web API** screen, set the **Identifier** to the resource URI your client will request tokens for
6. On the **Apply Access Control Policy** screen, choose an appropriate policy (e.g. **Permit everyone**)
7. On the **Configure Application Permissions** screen, ensure the server app is permitted to request the required scopes
8. Click **Next** and **Close** to finish

## 2. Configure appsettings.json

### Console app — `InteractiveAuthWithWebAPI/appsettings.json`

Open this file and fill in the values for the provider(s) you want to use. Leave the other section as-is — the app will ignore any unconfigured provider.

**Entra ID**
```json
"EntraId": {
  "TenantId": "YOUR_TENANT_ID",
  "ClientId": "YOUR_CLIENT_ID",
  "ClientSecret": "YOUR_CLIENT_SECRET",
  "RedirectUri": "http://localhost:8400",
  "UsePkce": true,
  "Scopes": [ "api://YOUR_API_CLIENT_ID/access_as_user" ],
  "ApiBaseUrl": "http://localhost:7001"
}
```

| Value | Where to find it |
|---|---|
| `TenantId` | Entra ID → Overview → **Directory (tenant) ID** |
| `ClientId` | App registration → Overview → **Application (client) ID** |
| `ClientSecret` | App registration → Certificates & secrets |
| `Scopes` | API app registration → Expose an API → full scope URI |

> `UsePkce: true` enables PKCE on top of the confidential client flow. Set to `false` to use a plain authorization code exchange instead.

**ADFS**
```json
"Adfs": {
  "Authority": "https://adfs.contoso.com/adfs/",
  "ClientId": "YOUR_CLIENT_ID",
  "ClientSecret": "YOUR_CLIENT_SECRET",
  "RedirectUri": "http://localhost:8400",
  "UsePkce": true,
  "Scopes": [ "https://your-resource-uri/" ],
  "ApiBaseUrl": "http://localhost:7001"
}
```

| Value | Where to find it |
|---|---|
| `Authority` | Your ADFS federation service URL |
| `ClientId` | Application ID registered in ADFS |
| `ClientSecret` | Shared secret generated during registration |
| `Scopes` | Resource URI of the web API registered in ADFS |

### API — `InteractiveAuthWithWebAPI/SweetSalesAPI/appsettings.json`

```json
"Auth": {
  "Authority": "https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0",
  "Audience": "YOUR_API_CLIENT_ID"
}
```

| Value | Where to find it |
|---|---|
| `Authority` | Entra ID issuer URL — replace `YOUR_TENANT_ID` with your Directory ID |
| `Audience` | The **Application (client) ID** of the API's app registration |

> For ADFS, change `Authority` to your ADFS metadata endpoint (e.g. `https://adfs.contoso.com/adfs`). Set `Audience` to the resource URI configured in ADFS.

## 3. Run in VS Code

> **Note:** You do not need to run `dotnet restore` manually. Both `dotnet build` and `dotnet run` restore NuGet packages automatically before executing.

### Step 1 — Start the API

Open a terminal in `InteractiveAuthWithWebAPI/SweetSalesAPI/` and run:

```
dotnet run
```

Leave this terminal running. The API listens on `http://localhost:7001`.

### Step 2 — Run the console app

Open a second terminal in `InteractiveAuthWithWebAPI/` and run:

```
dotnet run
```

If both providers are configured, you will be prompted to choose:

```
Both providers are configured. Which would you like to use?
  [1] Entra ID
  [2] ADFS
Enter choice:
```

## 4. Sign In and Use the POS

After you choose a provider, your browser opens to the sign-in page. Complete authentication normally. The console will print the token summary:

```
Successfully signed in as: user@contoso.com
Token expires:  18/04/2026 14:32
Scopes granted: api://...access_as_user
Sweet Sales POS running at http://localhost:8400/
Opening browser... Press Ctrl+C to stop.
```

Your browser then opens the Sweet Sales POS at `http://localhost:8400/`.

- **Dashboard** — browse today's pastry selection
- **Inventory** — click this tab to load live data from the API. You can add, edit, and delete items.

The console app:
1. Injects the access token server-side into the HTML — the browser never stores or exposes it
2. Proxies every `/api/*` request from the browser to `SweetSalesAPI` with `Authorization: Bearer <token>` added automatically

## Project Structure

```
InteractiveAuthWithWebAPI/
├── InteractiveAuthWithWebAPI.csproj   # Console app — targets net10.0
├── appsettings.json                   # Auth config for Entra ID and ADFS
├── Program.cs                         # Sign-in flow, SPA server, API proxy
└── SweetSalesAPI/
    ├── SweetSalesAPI.csproj           # Web API — targets net10.0
    ├── appsettings.json               # JWT bearer config, listen URL
    └── Controllers/
        └── InventoryController.cs     # GET / POST / PUT / DELETE /api/inventory
```

## Key Dependencies

| Package | Purpose |
|---|---|
| `Microsoft.Identity.Client` | MSAL.NET — builds the auth URL, handles token cache |
| `Microsoft.Extensions.Configuration.Json` | Reads `appsettings.json` |
| `Microsoft.AspNetCore.Authentication.JwtBearer` | Validates JWT bearer tokens in the Web API |
