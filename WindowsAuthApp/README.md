# WindowsAuthApp — Windows Silent Authentication (WAM + IWA)

Demonstrates **silent Windows authentication** against **Entra ID** (via WAM — Web Account Manager) and **ADFS** (via IWA — Integrated Windows Authentication / Kerberos).

The app acquires a token silently using the current Windows identity — no browser, no redirect URI, no credentials in code — then opens a browser-based **Stockroom Manager** SPA that calls the same **SweetSalesAPI** backend used by the `InteractiveAuthWithWebAPI` POS app.

---

## How it works

### Entra ID — WAM (Web Account Manager)

```
Windows account (Entra-joined or hybrid-joined)
       │
       ▼
MSAL AcquireTokenSilent(..., OperatingSystemAccount)
  → delegates to Windows broker (wam.dll / AccountsControl)
       │
       ▼
Entra ID token endpoint
       │
       ▼
JWT access token  ──►  SweetSalesAPI (Bearer header, server-side proxy)
                               ▲
                        Browser SPA (cookie-gated, token never in browser)
```

WAM is the modern Windows authentication broker. MSAL delegates to the Windows account subsystem, which uses the account already signed into Windows — no Kerberos ticket negotiation, no domain controller round-trip. The resulting JWT is identical in structure to a token acquired via Auth Code + PKCE; SweetSalesAPI validates it the same way.

### ADFS — WS-Trust Windows Transport

```
Windows session (Kerberos/NTLM)
       │
       ▼
POST /adfs/services/trust/13/windowstransport  (WS-Trust 1.3)
  or /adfs/services/trust/2005/windowstransport (WS-Trust 2005 fallback)
  → HttpClientHandler.UseDefaultCredentials = true
    .NET attaches the current Windows Kerberos/NTLM ticket automatically
       │
       ▼
ADFS returns a SAML assertion (SAML 2.0 preferred, 1.1 fallback)
       │
       ▼
POST /adfs/oauth2/token
  grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer
  (or saml1_1-bearer for SAML 1.1 tokens)
       │
       ▼
JWT access token  ──►  SweetSalesAPI
```

MSAL's `AcquireTokenByIntegratedWindowsAuth` is blocked by MSAL itself for any authority URL that contains `/adfs/` — MSAL classifies it as `AuthorityType.Adfs` and `IsWsTrustFlowSupported` returns false. WAM is also Entra-ID/MSA-only.

Instead, the app implements the same two-step exchange MSAL uses internally for federated Entra ID users, but calls ADFS directly:

1. **WS-Trust Windows Transport** — a SOAP `RequestSecurityToken` is posted to the Windows Transport endpoint. .NET's `HttpClientHandler.UseDefaultCredentials = true` attaches the current Kerberos (or NTLM) credential from the Windows session automatically. ADFS validates it and returns a SAML assertion.
2. **OAuth SAML bearer grant (RFC 7522)** — the SAML assertion is base64url-encoded and posted to `/adfs/oauth2/token` with `grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer`. ADFS exchanges it for a standard JWT access token.

---

## Prerequisites

### 1. Complete the InteractiveAuthWithWebAPI setup first

WindowsAuthApp reuses the **SweetSalesAPI** backend from `InteractiveAuthWithWebAPI`. That project must be configured before running WindowsAuthApp:

- `InteractiveAuthWithWebAPI/appsettings.json` — POS client config
- `InteractiveAuthWithWebAPI/SweetSalesAPI/appsettings.json` — API JWT validation config

Follow the setup guide in `InteractiveAuthWithWebAPI/` before continuing here.

### 2. Machine requirements

**Entra ID (WAM)** works when:
- The machine is **Entra-joined** or **hybrid-joined** (or at minimum, the organisational account is registered with the Windows account subsystem)
- The signed-in Windows account is an **organisational account** (not a personal Microsoft account)
- If a **Conditional Access policy** requires MFA: the user must have signed into Windows with a strong credential such as **Windows Hello for Business (WHfB)** or a **FIDO2 key** — WAM presents the MFA claim from that credential to Entra ID silently. If Windows was unlocked with a password only, CA MFA will cause a `MsalUiRequiredException` because there is nowhere to show a prompt.

**ADFS (WS-Trust Windows Transport)** works when:
- The machine is **domain-joined** (on-prem AD)
- The signed-in Windows account is an **organisational account**
- The **ADFS Windows Transport endpoints are enabled** (`/adfs/services/trust/13/windowstransport` or `/2005/windowstransport`)
- No **Conditional Access policy** on the account requires MFA — this is a silent flow with no mechanism to satisfy an MFA challenge

If authentication fails, the app exits with a clear explanation before the browser opens. Use `InteractiveAuthWithWebAPI` if you need an interactive fallback.

---

## App registration (Entra ID)

Create a **separate app registration** for WindowsAuthApp (do not reuse `InteractiveAuthWithWebAPI`'s registration).

| Setting | Value |
|---|---|
| Platform | **Mobile and desktop applications** |
| Redirect URI | `ms-appx-web://microsoft.aad.brokerplugin/{client_id}` |
| Allow public client flows | **Yes** (under Authentication → Advanced settings) |
| API permissions | Delegated permission on SweetSalesAPI — e.g. `access_as_user` |

No client secret is required — WAM is a **public client** flow.

### Step-by-step: Entra ID

1. **[Entra portal](https://entra.microsoft.com) → Identity → Applications → App registrations → New registration**
2. Name: `WindowsAuthApp` (or similar)
3. Supported account types: *Accounts in this organizational directory only*
4. Redirect URI: leave blank for now — click **Register**
5. Copy the **Application (client) ID** and **Directory (tenant) ID** — you will need these in `appsettings.json`
6. Go to **Authentication → Add a Redirect URI → Select a platform → Mobile and desktop applications**
7. In the custom redirect URI box enter: `ms-appx-web://microsoft.aad.brokerplugin/<your-client-id>` (replace with the ID from step 5)
8. Under **Settings**, set *Allow public client flows* to **Yes** — click **Save**
9. Go to **API permissions → Add a permission → APIs my organization uses**
10. Search for `SweetSalesAPI`, select it, choose the `access_as_user` delegated permission → **Add permissions**
11. Click **Grant admin consent for \<your tenant\>** → **Yes**. 

---

## App registration (ADFS)

If you are testing against ADFS rather than Entra ID, register a **Native Client Application** in AD FS Management.

| Setting | Value |
|---|---|
| Application type | Native application |
| Client Identifier | Pre-generated GUID — copy it (or replace with your own) for `appsettings.json` |
| Redirect URI | `urn:ietf:wg:oauth:2.0:oob` (the standard "out-of-band" URI for native clients that don't host a redirect server) |
| Web API to access | The SweetSalesAPI relying party trust (configured in `InteractiveAuthWithWebAPI`) |

### Step-by-step: ADFS

> These steps assume SweetSalesAPI is already registered as a Web API in ADFS (done as part of `InteractiveAuthWithWebAPI` setup).

1. Open **AD FS Management** on your ADFS server
2. Navigate to **Application Groups → Add Application Group**
3. Template: *Native application accessing a web API* → **Next**
4. **Native application** screen:
   - Name: `WindowsAuthApp`
   - Client Identifier: a GUID is pre-generated — copy it, or replace it with your own
   - Redirect URI: `urn:ietf:wg:oauth:2.0:oob` (standard out-of-band URI for native clients) → **Add** → **Next**
5. **Configure Web API** screen:
   - Identifier: enter the **resource URI** of your SweetSalesAPI relying party trust (e.g. `https://sweetsalesapi.contoso.com` or the URI you set when registering the API)
   - Click **Add** → **Next**
6. **Apply Access Control Policy**: choose *Permit everyone* (or your organisation's policy) → **Next**
7. **Configure Application Permissions**: ensure `openid` and your API scope (e.g. `access_as_user` or the scope defined on the Web API) are ticked → **Next** → **Close**
8. Copy the **Client Identifier** GUID into `appsettings.json` under `Adfs:ClientId`

---

## Configuration

Open `appsettings.json` and fill in the values for the provider(s) you want to use. Leave the other section with its placeholder values — the app will ignore any unconfigured provider.

### Entra ID

```json
"EntraId": {
  "TenantId": "YOUR_TENANT_ID",
  "ClientId": "YOUR_CLIENT_ID",
  "Scopes": [ "api://YOUR_API_CLIENT_ID/access_as_user" ],
  "ApiBaseUrl": "http://localhost:7001"
}
```

| Value | Where to find it |
|---|---|
| `TenantId` | App registration → Overview → **Directory (tenant) ID** |
| `ClientId` | App registration → Overview → **Application (client) ID** |
| `Scopes` | API app registration → Expose an API → copy the full scope URI (e.g. `api://<api-client-id>/access_as_user`) |

### ADFS

```json
"Adfs": {
  "Authority": "https://adfs.contoso.com/adfs/",
  "ClientId": "YOUR_CLIENT_IDENTIFIER_GUID",
  "Scopes": [ "YOUR_API_RESOURCE_URI" ],
  "ApiBaseUrl": "http://localhost:7001"
}
```

| Value | Where to find it |
|---|---|
| `Authority` | Your ADFS federation service URL — must end with `/adfs/` |
| `ClientId` | The Client Identifier GUID from step 4 of the ADFS registration above |
| `Scopes` | The Web API Identifier (resource URI) set in step 5 of the ADFS registration above |

---

## Running

```
dotnet run
```

The app will:
1. Authenticate silently via WAM (Entra ID) or IWA (ADFS) — no browser opens for sign-in
2. Print a token summary to the console
3. Auto-launch SweetSalesAPI if it is not already running on port 7001
4. Open the browser to `http://localhost:8401` — you are already authenticated

If authentication fails (e.g. Conditional Access MFA on Entra ID when signed in with a password rather than WHfB/FIDO2, or MFA policy on ADFS, or not domain-/Entra-joined), the app exits with a clear explanation before the browser opens.

---

## What the browser app does

The **Stockroom Manager** SPA provides:

- **Summary cards** — total items, total units, low-stock count, inventory value
- **Inventory table** — full CRUD (add, edit, delete) with stock badges
- **Restock modal** — focused stock-level adjustment workflow for warehouse staff
- **Sign out** — IdP logout with `id_token_hint` + `logout_hint`

It calls the same `/api/inventory` and `/api/settings` endpoints as the POS app. Changes made here are immediately visible in the POS and vice versa — both apps share the same in-memory store via SweetSalesAPI.


