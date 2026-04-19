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

## 1. Configure App Registrations

This solution requires **two separate app registrations** — one for the API that exposes protected scopes, and one for the client that signs users in and requests tokens for the API.

---

### Entra ID

#### Step A — Register the API (`SweetSalesAPI`)

In the [Azure portal](https://portal.azure.com):

1. Go to **Microsoft Entra ID → App registrations → New registration**
2. Name it (e.g. `SweetSalesAPI`) and click **Register** — no redirect URI needed
3. *(Optional)* On the **Branding & properties** tab, add a description such as *"Protected inventory API — part of the InteractiveAuthWithWebAPI test deployment"*
4. On the **Expose an API** tab:
   - Click **Add** next to *Application ID URI* — accept the default `api://<client-id>` and click **Save**
   - Click **Add a scope**, name it `access_as_user`, set **Who can consent** to *Admins and users*, fill in the display name and description, and click **Add scope**
5. Note the **Application (client) ID** — this is `YOUR_API_CLIENT_ID`

#### Step B — Register the Client (console app)

1. Go to **App registrations → New registration**
2. Name it (e.g. `InteractiveAuthWithWebAPI`), select **Web** as the platform, set the redirect URI to `http://localhost:8400`, and click **Register**
3. On the **Certificates & secrets** tab, click **New client secret**, copy the generated value — this is `YOUR_CLIENT_SECRET`
4. On the **API permissions** tab:
   - Click **Add a permission → My APIs** and select `SweetSalesAPI`
   - Select the `access_as_user` delegated scope and click **Add permissions**
   - Click **Grant admin consent for \<your tenant\>**
5. Note the **Application (client) ID** — this is `YOUR_CLIENT_ID`
6. Note the **Directory (tenant) ID** from the Overview page — this is `YOUR_TENANT_ID`

> **Optional claims / custom claims mapping — AADSTS50146**  
> If you configure optional or mapped claims on the client app registration (e.g. via the **Token configuration** tab), Entra ID will reject the token exchange with `AADSTS50146` unless the app is configured to accept claims signed with the shared key. Fix this in the app manifest:  
> 1. Go to the **client** app registration → **Manifest**  
> 2. Set `"acceptMappedClaims": true`  
> 3. Click **Save**  
>
> If you need tenant-wide claims mapping via a PowerShell `ClaimsMappingPolicy` instead, you must upload a dedicated signing certificate — `acceptMappedClaims` only covers app-registration-level optional claims.

> **Bypass the logout account-picker prompt (Entra ID)**  
> By default, Entra ID shows an account-picker when the user signs out. To skip it, add the `login_hint` optional claim to the ID token and the app will automatically pass it as `logout_hint` in the logout request:  
> 1. Go to the **client** app registration → **Token configuration**  
> 2. Click **Add optional claim** → token type **ID** → tick `login_hint` → **Add**  
> 3. When prompted, click **Turn on** to also enable the `profile` scope  
>
> Reference: [Sign out without user selection prompt](https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/app-integration/sign-out-of-openid-connect-oauth2-applications-without-user-selection-prompt)

---

### ADFS

On your ADFS server (requires ADFS 2019 or later):

1. Open **AD FS Management** and go to **Application Groups → Add Application Group**
2. Select **Server application accessing a web API** and give it a name (e.g. `InteractiveAuthWithWebAPI`)
3. On the **Server application** screen:
   - Copy the generated **Client Identifier** — this is `YOUR_CLIENT_ID`
   - Add the redirect URI `http://localhost:8400`
4. On the **Configure Application Credentials** screen, choose **Generate a shared secret** and copy the value — this is `YOUR_CLIENT_SECRET`
5. On the **Configure Web API** screen:
   - Set the **Identifier** to a URI for your API (e.g. `https://sweetsalesapi/`) — this becomes `YOUR_API_RESOURCE_URI` and the base of your `Scopes` value
6. On the **Apply Access Control Policy** screen, choose an appropriate policy (e.g. **Permit everyone**)
7. On the **Configure Application Permissions** screen, ensure the server app is permitted to request the scopes your API needs (e.g. `openid`, `profile`, `allatclaims`)
8. Click **Next** and **Close** to finish

## 2. Configure appsettings.json

### Console app — `InteractiveAuthWithWebAPI/appsettings.json`

Open this file and fill in the values for the provider(s) you want to use. Leave the other section with its placeholder values — the app will ignore any unconfigured provider.

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
| `TenantId` | Client app registration → Overview → **Directory (tenant) ID** |
| `ClientId` | Client app registration → Overview → **Application (client) ID** |
| `ClientSecret` | Client app registration → Certificates & secrets |
| `Scopes` | API app registration → Expose an API → copy the full scope URI (e.g. `api://<api-client-id>/access_as_user`) |

> `UsePkce: true` enables PKCE on top of the confidential client flow. Set to `false` to use a plain authorization code exchange instead.

**ADFS**
```json
"Adfs": {
  "Authority": "https://adfs.contoso.com/adfs/",
  "ClientId": "YOUR_CLIENT_ID",
  "ClientSecret": "YOUR_CLIENT_SECRET",
  "RedirectUri": "http://localhost:8400",
  "UsePkce": true,
  "Scopes": [ "YOUR_API_RESOURCE_URI" ],
  "ApiBaseUrl": "http://localhost:7001"
}
```

| Value | Where to find it |
|---|---|
| `Authority` | Your ADFS federation service URL |
| `ClientId` | Client Identifier from the Application Group registration |
| `ClientSecret` | Shared secret generated during registration |
| `Scopes` | The Web API Identifier set in step 5 of the ADFS registration above |

> **ADFS logout redirect**: ADFS requires the `LogoutUri` to be registered via PowerShell before `post_logout_redirect_uri` will be honoured. Run this on the ADFS server (replace the identifier with your client's):
> ```powershell
 > Set-AdfsServerApplication -TargetIdentifier <YOUR_CLIENT_ID> -LogoutUri http://localhost:8400/?signed_out=1
> ```
> Reference: [AD FS OpenID Connect Logout](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/development/ad-fs-logout-openid-connect)

### API — `InteractiveAuthWithWebAPI/SweetSalesAPI/appsettings.json`

```json
"EntraId": {
  "Authority": "https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0",
  "Audience": "api://YOUR_API_CLIENT_ID"
},
"Adfs": {
  "Authority": "https://YOUR_ADFS_HOST/adfs/",
  "Audience": "YOUR_API_RESOURCE_URI"
}
```

| Value | Where to find it |
|---|---|
| `EntraId.Authority` | Entra ID token issuer — replace `YOUR_TENANT_ID` with your Directory (tenant) ID |
| `EntraId.Audience` | **API** app registration → Overview → **Application (client) ID** (with `api://` prefix) |
| `Adfs.Authority` | Your ADFS federation service URL (e.g. `https://adfs.contoso.com/adfs/`) |
| `Adfs.Audience` | The Web API Identifier (resource URI) configured in the ADFS Application Group |

The API accepts tokens from either provider — it peeks at the issuer claim in the JWT and routes to the correct validator automatically.

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
