# Security Research Findings — OuterTune v71

Only PARTIAL findings are listed. No VALID (exploitable) threats were confirmed. INVALID findings were hallucinated or speculative with no grounding in the actual source code.

---

## Finding 1: JavaScript Interface Exposed Without Origin Validation (LoginScreen WebView)

**Title**: Unvalidated Origin Access to WebView JavaScript Bridge

**Problem Summary**:
`LoginScreen.kt` attaches a JavaScript interface named `"Android"` to a WebView that navigates external origins (`accounts.google.com` → `music.youtube.com`). The interface is accessible to every page the WebView loads — there is no origin check at the bridge level. Additionally, `onPageFinished` unconditionally injects JavaScript (`Android.onRetrieveVisitorData(...)` and `Android.onRetrieveDataSyncId(...)`) on every page load regardless of the current URL.

Any JavaScript executing in the WebView — including from intermediate redirect pages or subframes — can call these bridge methods with attacker-controlled strings. An adversary who achieves JavaScript execution in the WebView (e.g., via an open redirect on Google's login flow, or a compromised page loaded during navigation) could overwrite the stored `visitorData` and `dataSyncId` values in the app's DataStore preferences. This could corrupt the app's YouTube session state.

Impact is **limited**: the bridge methods only write strings to DataStore preferences. There are no dangerous sinks (no SQL queries, no file I/O, no Intent creation, no reflection). A successful attack corrupts session tokens rather than achieving code execution or data exfiltration.

**Potential Mitigation**:
- Add an origin check in `onPageFinished` before injecting JavaScript: only inject when `url?.startsWith("https://music.youtube.com") == true` or equivalent allowlist.
- Consider removing `addJavascriptInterface` entirely and instead using `evaluateJavascript` with a `WebViewClient.onPageFinished` check restricted to known-good origins, communicating results via `WebView.evaluateJavascript` callbacks rather than a persistent bridge.

**Relevant Files**:
- `app/src/main/java/com/dd3boh/outertune/ui/screens/LoginScreen.kt:63–100`

---

## Notes on Dismissed Findings

### llama3.2:3b — SQL Injection, Path Traversal, Intent Redirection, Reflective Execution, Permission Leakage, PII Transmission, Content Loading (Intent-webview_new-13)
All INVALID. The model fabricated sink function names (`executeSQLQuery`, `openFile`, `reflect`, `getAccounts`, `transmitPiiToExternalService`, `loadContent`) that do not exist anywhere in the bridge implementation or any code it calls. The bridge methods solely write strings to DataStore preferences.

### gemma3:12b — PII Leakage via `onRetrieveVisitorData`
INVALID. `VISITOR_DATA` is a YouTube analytics/session identifier, not personally identifiable information (name, email, phone, etc.). The app intentionally retrieves and stores it for YouTube API authentication.

### gemma3:12b — Arbitrary Object Instantiation (Intent-webview_new-15 / PoTokenWebView)
INVALID. The `PoTokenWebView` constructor parameters (`Context`, `Continuation<PoTokenWebView>`) are fully controlled by Kotlin coroutine infrastructure, not reachable from JavaScript. The WebView has `blockNetworkLoads = true` and loads only a local HTML asset.

### All "Unvalidated Data → XSS/RCE" findings on bridge methods
INVALID. The bridge methods do not render, eval, or re-inject their string inputs back into a WebView. They call `DataStore` write operations only. No XSS or RCE path exists through these sinks.
