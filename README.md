# Device Code Flow App

A .NET 10 console app that tests the [OAuth 2.0 device code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code) with **Microsoft Entra ID** or **ADFS**. Configure one or both providers in `appsettings.json` — the app will prompt you to choose if both are populated. After authenticating with Entra ID it also calls the Microsoft Graph `/me` endpoint and displays your profile.

## Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download)
- [VS Code](https://code.visualstudio.com/) with the [C# Dev Kit](https://marketplace.visualstudio.com/items?itemName=ms-dotnettools.csdevkit) extension
- A **Microsoft Entra ID** tenant, an **ADFS 2019+** deployment, or both
- nuget.org configured as a package source. If you haven't done this before, run:
  ```
  dotnet nuget add source https://api.nuget.org/v3/index.json --name nuget.org
  ```

## 1. Configure the App Registration

### Entra ID

In the [Azure portal](https://portal.azure.com):

1. Go to **Microsoft Entra ID → App registrations → New registration**
2. Give it a name and click **Register**
3. On the **Authentication** tab:
   - Click **Add a platform → Mobile and desktop applications**
   - Under **Advanced settings**, set **Allow public client flows** to **Yes**
   - Click **Save**
4. On the **API permissions** tab:
   - Ensure **Microsoft Graph → User.Read** (delegated) is present
   - Click **Grant admin consent** if required by your tenant

### ADFS

On your ADFS server (requires ADFS 2019 or later):

1. Open **AD FS Management** and go to **Application Groups → Add Application Group**
2. Select **Native application accessing a web API** and give it a name
3. Copy the generated **Client Identifier** — this is your `ClientId`
4. For the redirect URI enter **urn:ietf:wg:oauth:2.0:oob** — this is a standard redirect URI
5. On the **Configure Web API** screen:
   - Set the **Identifier** to the resource URI your client will request a token for (e.g. `https://your-app/`)
   - This becomes the base of your `Scopes` value
6. On the **Apply Access Control Policy** screen, choose an appropriate policy (e.g. **Permit everyone**)
7. On the **Configure Application Permissions** screen, ensure the native app is permitted to request the openid and profile scopes.
8. Click **Next** and **Close** to finish

> To enable device code flow, run the following on the ADFS server:
> ```powershell
> Grant-AdfsApplicationPermission -ClientRoleIdentifier "<your-client-id>" -ServerRoleIdentifier "<your-resource-uri>" -ScopeNames "openid"
> Set-AdfsApplicationPermission -TargetClientRoleIdentifier "<your-client-id>" -AddScopeNames "openid"
> ```

## 2. Configure appsettings.json

Open `appsettings.json` and fill in the values for the provider(s) you want to use. Leave the other section as-is with placeholders — the app will ignore any unconfigured provider.

**Entra ID**
```json
"EntraId": {
  "TenantId": "YOUR_TENANT_ID",
  "ClientId": "YOUR_CLIENT_ID",
  "Scopes": [ "User.Read" ]
}
```

| Value | Where to find it |
|---|---|
| `TenantId` | Entra ID → Overview → **Directory (tenant) ID** |
| `ClientId` | App registration → Overview → **Application (client) ID** |

**ADFS**
```json
"Adfs": {
  "Authority": "https://adfs.contoso.com/adfs/",
  "ClientId": "YOUR_CLIENT_ID",
  "Scopes": [ "https://your-resource-uri/" ]
}
```

| Value | Where to find it |
|---|---|
| `Authority` | Your ADFS federation service URL |
| `ClientId` | Application ID registered in ADFS |
| `Scopes` | Resource URI of the application you're accessing |

> Device code flow requires **ADFS 2019 or later**.

## 3. Run in VS Code

> **Note:** You do not need to run `dotnet restore` manually. Both `dotnet build` and `dotnet run` restore NuGet packages automatically before executing.

### Option A: Terminal

1. Open the integrated terminal (`Ctrl+\``)
2. Run:
   ```
   dotnet run
   ```

### Option B: Debugger

1. Open the **Run and Debug** panel (`Ctrl+Shift+D`)
2. Click **Run and Debug** and select **.NET 9+ / C#**
3. VS Code will build and launch the app

## 4. Sign In

If both providers are configured, the app will prompt you to choose:

```
Both providers are configured. Which would you like to use?
  [1] Entra ID
  [2] ADFS
  [3] Both
Enter choice:
```

For each selected provider the console will print a device code prompt:

```
To sign in, use a web browser to open the page https://microsoft.com/devicelogin
and enter the code ABCD12345 to authenticate.
```

**Entra ID** — go to `https://microsoft.com/devicelogin`, enter the code, and complete sign-in. The app will then display your profile data from Microsoft Graph.

**ADFS** — go to your ADFS device code endpoint (e.g. `https://adfs.contoso.com/adfs/oauth2/deviceauth`), enter the code, and complete sign-in. The app will display the token summary (account, expiry, scopes) — it does not call Graph for ADFS flows.

## Project Structure

```
DeviceCodeFlowApp/
├── DeviceCodeFlowApp.csproj       # Project file — targets net10.0, MSAL NuGet reference is here
├── appsettings.json               # Tenant ID, Client ID, and scopes
└── Program.cs                     # Device code flow logic and Graph call
```

## Key Dependencies

| Package | Purpose |
|---|---|
| `Microsoft.Identity.Client` | MSAL.NET — handles the device code flow and token acquisition |
| `Microsoft.Extensions.Configuration.Json` | Reads `appsettings.json` |
