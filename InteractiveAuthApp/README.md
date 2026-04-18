# Interactive Auth App

A .NET 10 console app that tests the [OAuth 2.0 Authorization Code flow with PKCE](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow) with **Microsoft Entra ID** or **ADFS**. Configure one or both providers in `appsettings.json` — the app will prompt you to choose if both are populated. Sign-in opens in your default browser. After authenticating with Entra ID it also calls the Microsoft Graph `/me` endpoint and displays your profile.

The app supports two client types, detected automatically from `appsettings.json`:

| | Public client | Confidential client |
|---|---|---|
| `ClientSecret` in appsettings | not set | set |
| App registration type | Mobile/desktop | Web |
| PKCE | MSAL-managed (automatic) | Controlled by `UsePkce` in appsettings |
| Auth code redirect | MSAL's loopback listener | App's local `HttpListener` |
| Redirect URI registered | `http://localhost:8400` | `http://localhost:8400` |

> The docs recommend public client + PKCE for native/desktop apps. The confidential client path is provided to allow testing when the app registration requires a secret (e.g. `AADSTS7000218`).

## Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download)
- [VS Code](https://code.visualstudio.com/) with the [C# Dev Kit](https://marketplace.visualstudio.com/items?itemName=ms-dotnettools.csdevkit) extension
- A **Microsoft Entra ID** tenant, an **ADFS 2019+** deployment, or both
- nuget.org configured as a package source. If you haven't done this before, run:
  ```
  dotnet nuget add source https://api.nuget.org/v3/index.json --name nuget.org
  ```

## 1. Configure the App Registration

### Entra ID — Public client (no secret)

In the [Azure portal](https://portal.azure.com):

1. Go to **Microsoft Entra ID → App registrations → New registration**
2. Give it a name and click **Register**
3. On the **Authentication** tab:
   - Click **Add a platform → Mobile and desktop applications**
   - Add **http://localhost:8400** as a redirect URI
   - Under **Advanced settings**, set **Allow public client flows** to **Yes**
   - Click **Save**
4. On the **API permissions** tab:
   - Ensure **Microsoft Graph → User.Read** (delegated) is present
   - Click **Grant admin consent** if required by your tenant

### Entra ID — Confidential client (with secret)

1. Go to **Microsoft Entra ID → App registrations → New registration**
2. Give it a name and click **Register**
3. On the **Authentication** tab:
   - Click **Add a platform → Web**
   - Set the **Redirect URI** to `http://localhost:8400`
   - Click **Configure**

   > **Important:** You must use the **Web** platform here, not Mobile/desktop.

4. On the **Certificates & secrets** tab:
   - Click **New client secret**, give it a description and expiry, and click **Add**
   - Copy the secret **Value** immediately (it's only shown once)
5. On the **API permissions** tab:
   - Ensure **Microsoft Graph → User.Read** (delegated) is present
   - Click **Grant admin consent** if required by your tenant

> Set `"RedirectUri": "http://localhost:8400"` in appsettings.json to match.

### ADFS

On your ADFS server (requires ADFS 2016 or later):

1. Open **AD FS Management** and go to **Application Groups → Add Application Group**
2. Select **Native application accessing a web API** and give it a name
3. Copy the generated **Client Identifier** — this is your `ClientId`
4. Add **http://localhost:8400** as a redirect URI
5. On the **Configure Web API** screen:
   - Set the **Identifier** to the resource URI your client will request a token for (e.g. `https://your-resource-uri/`)
   - This becomes the base of your `Scopes` value
6. On the **Apply Access Control Policy** screen, choose an appropriate policy (e.g. **Permit everyone**)
7. On the **Configure Application Permissions** screen, ensure the native app is permitted to request the `openid` and `profile` scopes
8. Click **Next** and **Close** to finish

## 2. Configure appsettings.json

Open `appsettings.json` and fill in the values for the provider(s) you want to use. Leave the other section as-is with placeholders — the app will ignore any unconfigured provider.

**Entra ID — public client**
```json
"EntraId": {
  "TenantId": "YOUR_TENANT_ID",
  "ClientId": "YOUR_CLIENT_ID",
  "ClientSecret": "",
  "Scopes": [ "User.Read" ]
}
```

**Entra ID — confidential client**
```json
"EntraId": {
  "TenantId": "YOUR_TENANT_ID",
  "ClientId": "YOUR_CLIENT_ID",
  "ClientSecret": "YOUR_CLIENT_SECRET",
  "RedirectUri": "",
  "UsePkce": true,
  "Scopes": [ "User.Read" ]
}
```

| Value | Where to find it |
|---|---|
| `TenantId` | Entra ID → Overview → **Directory (tenant) ID** |
| `ClientId` | App registration → Overview → **Application (client) ID** |
| `ClientSecret` | App registration → Certificates & secrets → **Value** (leave blank for public client) |
| `RedirectUri` | Redirect URI registered in the app registration. Use `http://localhost:8400` for both Entra ID and ADFS to keep it consistent. |
| `UsePkce` | `true` — adds `code_challenge` to the authorization request and `code_verifier` to the token exchange. `false` — client secret only (no PKCE). |

**ADFS**
```json
"Adfs": {
  "Authority": "https://adfs.contoso.com/adfs/",
  "ClientId": "YOUR_CLIENT_ID",
  "ClientSecret": "",
  "RedirectUri": "",
  "Scopes": [ "https://your-resource-uri/" ]
}
```

| Value | Where to find it |
|---|---|
| `Authority` | Your ADFS federation service URL |
| `ClientId` | Application ID registered in ADFS |
| `ClientSecret` | Client secret registered in ADFS (leave blank for public client) |
| `RedirectUri` | Required for confidential client only — must exactly match the URI registered in ADFS (e.g. `http://localhost:8400/`). ADFS does not support the localhost port exception, so a fixed port is required. Leave blank for public client. |
| `UsePkce` | `true` — adds `code_challenge` to the authorization request and `code_verifier` to the token exchange. `false` — client secret only (no PKCE). |
| `Scopes` | Resource URI of the application you're accessing |

## 3. Run in VS Code

> **Note:** You do not need to run `dotnet restore` manually. Both `dotnet build` and `dotnet run` restore NuGet packages automatically before executing.

### Option A: Terminal

1. Open the integrated terminal (`Ctrl+\``)
2. Run:
   ```
   dotnet run
   ```

## 4. Sign In

If both providers are configured, the app will prompt you to choose:

```
Both providers are configured. Which would you like to use?
  [1] Entra ID
  [2] ADFS
  [3] Both
Enter choice:
```

After choosing, the app opens your default browser to the sign-in page. Once you sign in, the browser redirects back to `http://localhost:8400` and the app continues automatically.

```
══ Entra ID ══════════════════════════════════════════════
Opening browser for interactive sign-in...

Successfully signed in as: user@contoso.com
Token expires:  17/04/2026 15:30
Scopes granted: User.Read, profile, openid, ...

Calling Microsoft Graph /me ...

── /me response ─────────────────────────────────────────
  displayName          Jane Smith
  userPrincipalName    user@contoso.com
  ...
```
