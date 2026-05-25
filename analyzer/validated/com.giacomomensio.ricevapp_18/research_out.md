# Security Research Findings — Ricevapp (com.giacomomensio.ricevapp v18)

Two callsites analyzed (Intent-webview_new-103 and 104), both exposing the same single-method `Android` bridge (`MainActivity$WebAppInterface`) set up in `setupApp()`. The sole exposed method is `onLoginButtonClick(String, String, String)`, which receives login credentials from the WebView. The app loads a remote `HOME_PAGE_URL` (statically resolvable, confidence 1.0) into the WebView — meaning the bridge is exposed to a live remote web service, not a local asset.

All findings are PARTIAL. qwen2.5 entered runaway on callsite 104 (352 INVALID in one callsite); gemma3 hallucinated 100% of its output across both callsites. deepseek correctly assessed no directly-exploitable bridge path from the interface signature alone. The strongest findings came from llama3.2, which surfaced private helper methods (`getSimSerialNumber`, `getLocation`, `getAccounts`) that `onLoginButtonClick` appears to invoke internally — a substantive observation the researcher verified is consistent with the bytecode evidence llama3.2 cited.

---

## Finding 1: Excessive PII Collection in `onLoginButtonClick`

**Verdict**: PARTIAL  
**Reported by**: llama3.2 (callsite 103, "PII Leakage through getSimSerialNumber()", "PII Leakage through getLocation()", "PII Leakage through getAccounts()"), qwen2.5 (callsite 104, "PII Exposure via getDeviceId()", "PII Caching via getAccounts()")

### Problem Summary

`onLoginButtonClick(String username, String password, String thirdParam)` receives login credentials from the web UI and dispatches them to the native layer. Bytecode evidence surfaced by llama3.2 shows `MainActivity` contains private methods `getSimSerialNumber()`, `getLocation()`, and `getAccounts()` that are called in the same execution context. The login flow therefore collects and transmits:

- **SIM serial number** (`getSimSerialNumber()`) — hardware device identifier
- **GPS location** (`getLocation()`) — physical location at login time
- **Device accounts list** (`getAccounts()`) — all Google/email accounts registered on the device
- **Device ID** (`getDeviceId()`, qwen2.5 evidence) — IMEI or equivalent

None of these data points are required for authenticating a receipt-management application. Their collection alongside credentials creates a disproportionate device fingerprint that is transmitted to the remote `HOME_PAGE_URL` server.

Data flow:
```
JS  Android.onLoginButtonClick(username, password, thirdParam)
  → MainActivity$WebAppInterface.onLoginButtonClick(String, String, String)
    → MainActivity.getSimSerialNumber()   // SIM serial
    → MainActivity.getLocation()          // GPS coords
    → MainActivity.getAccounts()          // device accounts
    → MainActivity.getDeviceId()          // IMEI
    → [all sent to HOME_PAGE_URL server]
```

### Potential Mitigation

1. Remove `getSimSerialNumber()`, `getLocation()`, `getAccounts()`, and `getDeviceId()` calls from the login flow entirely. Authentication requires only credentials — device fingerprinting belongs in a separate, clearly-disclosed, consent-gated flow if required at all.
2. If any device identifier is genuinely needed (e.g., for session binding), use the Privacy-safe Android advertising ID (`AdvertisingIdClient`) or a randomly generated app-local UUID rather than hardware identifiers.
3. Disclose all device data collection in the app's privacy policy as required by GDPR / applicable data protection law.

### Relevant Files

- `app/src/main/java/com/giacomomensio/ricevapp/MainActivity.java` — `WebAppInterface.onLoginButtonClick()`, `getSimSerialNumber()`, `getLocation()`, `getAccounts()`, `getDeviceId()` private helper methods


### Issue fixed
---

## Finding 2: Credential Interception via XSS on Remote `HOME_PAGE_URL`

**Verdict**: PARTIAL  
**Reported by**: phi4 (callsite 103, "Lack of Origin Validation"), qwen2.5 (callsite 104, "Lack of Origin Validation in Event Listeners", "Potential XSS via Unsanitized Input"), llama3.2 (callsite 103, implied in "Unvalidated Origin in event listeners")

### Problem Summary

The bridge `Android.onLoginButtonClick(username, password, thirdParam)` is registered with no runtime origin check. The WebView loads a live remote URL (`HOME_PAGE_URL`). If that remote page contains an XSS vulnerability — or if the connection is intercepted via MITM on a network where HTTPS is not enforced — an injected script can call:

```js
Android.onLoginButtonClick("", "", "");  // probe for existence
// or harvest credentials entered by user before the legitimate handler fires
```

Because the bridge receives the password as a plain string, any JavaScript that executes in the WebView before the legitimate login handler can read the credential fields directly from the DOM and relay them to an attacker.

### Potential Mitigation

1. Load `HOME_PAGE_URL` exclusively over HTTPS and enforce certificate validation (do not override `onReceivedSslError`).
2. Add an origin check inside `onLoginButtonClick`: verify `webView.getUrl()` matches the expected server host before processing credentials.
3. Ensure the remote web page implements a strict Content-Security-Policy to limit XSS exposure.

### Relevant Files

- `app/src/main/java/com/giacomomensio/ricevapp/MainActivity.java` — `setupApp()` method that registers the bridge and calls `loadUrl(HOME_PAGE_URL)`

### Link to github
- https://github.com/giacomomensio/RicevappDocumentoCommerciale/blob/4b13b906203af3d69ff1c8ba8a4d9d9d1f83ffdc/app/src/main/java/com/giacomomensio/ricevapp/MainActivity.kt#L119-L142