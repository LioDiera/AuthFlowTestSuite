# Auth Flow Test Suite

A collection of .NET 10 console apps for testing OAuth 2.0 / OpenID Connect authentication flows against **Microsoft Entra ID** and **ADFS 2019+**.

## Apps

| App | Flow | Entra ID | ADFS |
|---|---|---|---|
| [DeviceCodeFlowApp](DeviceCodeFlowApp/README.md) | Device Code | ✅ | ✅ |
| [InteractiveAuthApp](InteractiveAuthApp/) | Authorization Code + PKCE (browser pop-up) | ✅ | ✅ |
| [IWAApp](IWAApp/) | Integrated Windows Authentication | ✅ | ✅ |
| [ROPCApp](ROPCApp/) | Resource Owner Password Credentials | ✅ | ✅ |
| [ClientCredentialsApp](ClientCredentialsApp/) | Client Credentials (daemon / service) | ✅ | ❌ |
| [OBOApp](OBOApp/) | On-Behalf-Of | ✅ | ❌ |

## Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download)
- [VS Code](https://code.visualstudio.com/) with the [C# Dev Kit](https://marketplace.visualstudio.com/items?itemName=ms-dotnettools.csdevkit) extension
- A **Microsoft Entra ID** tenant, an **ADFS 2019+** deployment, or both
- nuget.org configured as a package source. If you haven't done this before, run:
  ```
  dotnet nuget add source https://api.nuget.org/v3/index.json --name nuget.org
  ```

## Running an App

Each app is self-contained. Navigate into its folder and run:

```
dotnet run
```

Or open the solution `AuthFlowTestSuite.slnx` in VS Code and run/debug any project from there.

See each app's own README for configuration details.
