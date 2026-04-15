# Device Code Flow App

A .NET 8 console app that tests the [OAuth 2.0 device code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code) with Microsoft Entra ID. After authenticating, it calls the Microsoft Graph `/me` endpoint and displays your profile.

## Prerequisites

- [.NET 8 SDK](https://dotnet.microsoft.com/download)
- [VS Code](https://code.visualstudio.com/) with the [C# Dev Kit](https://marketplace.visualstudio.com/items?itemName=ms-dotnettools.csdevkit) extension
- A Microsoft Entra ID (Azure AD) tenant

## 1. Configure the App Registration

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

## 2. Configure appsettings.json

Open `appsettings.json` and replace the placeholder values with your app registration details:

```json
{
  "AzureAd": {
    "TenantId": "YOUR_TENANT_ID",
    "ClientId": "YOUR_CLIENT_ID",
    "Scopes": [ "User.Read" ]
  }
}
```

| Value | Where to find it |
|---|---|
| `TenantId` | Entra ID → Overview → **Directory (tenant) ID** |
| `ClientId` | App registration → Overview → **Application (client) ID** |

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
2. Click **Run and Debug** and select **.NET 8+ / C#**
3. VS Code will build and launch the app

## 4. Sign In

The console will print something like:

```
To sign in, use a web browser to open the page https://microsoft.com/devicelogin
and enter the code ABCD12345 to authenticate.
```

1. Open a browser and go to `https://microsoft.com/devicelogin`
2. Enter the code shown in the console
3. Complete the sign-in (including MFA if required)
4. Return to the console — the app will display your profile data from Microsoft Graph

## Project Structure

```
DeviceCodeFlowApp/
├── DeviceCodeFlowApp.csproj       # Project file — MSAL NuGet reference is here
├── appsettings.json               # Tenant ID, Client ID, and scopes
└── Program.cs                     # Device code flow logic and Graph call
```

## Key Dependencies

| Package | Purpose |
|---|---|
| `Microsoft.Identity.Client` | MSAL.NET — handles the device code flow and token acquisition |
| `Microsoft.Extensions.Configuration.Json` | Reads `appsettings.json` |
