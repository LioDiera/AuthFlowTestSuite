# Auth Flow Test Suite

A collection of .NET 10 console apps for testing OAuth 2.0 / OpenID Connect authentication flows against **Microsoft Entra ID** and **ADFS 2019+**.

## Apps

| App | Flow | Entra ID | ADFS | Status |
|---|---|---|---|---|
| [DeviceCodeFlowApp](DeviceCodeFlowApp/README.md) | Device Code | ✅ | ✅ | Ready |
| [InteractiveAuthApp](InteractiveAuthApp/README.md) | Authorization Code + PKCE (browser pop-up) | ✅ | ✅ | Ready |
| [WindowsAuthApp](WindowsAuthApp/README.md) | Integrated Windows Authentication | ✅ | ✅ | Ready |
| [InteractiveAuthWithWebAPI](InteractiveAuthWithWebAPI/README.md) | Authorization Code + PKCE → protected Web API call | ✅ | ✅ | Ready |
| [ClientCredentialsApp](ClientCredentialsApp/) | Client Credentials (daemon / service) | ✅ | ❌ | Stub |
| [OBOApp](OBOApp/) | On-Behalf-Of | ✅ | ❌ | Stub |
| [ROPCApp](ROPCApp/) | Resource Owner Password Credentials | ✅ | ✅ | Stub |

## Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download)
- [VS Code](https://code.visualstudio.com/) with the [C# Dev Kit](https://marketplace.visualstudio.com/items?itemName=ms-dotnettools.csdevkit) extension
- A **Microsoft Entra ID** tenant, an **ADFS 2019+** deployment, or both
- nuget.org configured as a package source. If you haven't done this before, run:
  ```
  dotnet nuget add source https://api.nuget.org/v3/index.json --name nuget.org
  ```

## Configure

- Each app has an `appsettings.json` with `<placeholder>` values.
- Put your real values in `appsettings.Development.json` in the same folder. It overrides the template and must not be committed.
- An app skips a provider (Entra ID or ADFS) that still has placeholder values.

## Running an App

Each app is self-contained. Navigate into its folder and run:

```
dotnet run
```

Or open the solution `AuthFlowTestSuite.slnx` in VS Code and run/debug any project from there.

See each app's own README for configuration details.
