# Security Research Findings — DuckDuckGo Android WebView Bridge Interfaces

All findings sourced from `csv/com.duckduckgo.mobile.android_52660000.csv`.
Only PARTIAL findings are included (no fully VALID findings confirmed). The two distinct root causes below account for all PARTIAL rows (rows 7, 15, 26, 33, 37).

---

## Finding 1: BlobConverter Interface Has No Origin Restriction

**CSV rows:** 7 (Intent-webview_new-33, phi4:14b — "Origin Validation Missing")

**Problem Summary**

`BlobConverterJavascriptInterface` is registered via `WebView.addJavascriptInterface()` with no URL or origin restriction — it is accessible to every web page loaded in the browser WebView. The interface exposes one method:

```kotlin
@JavascriptInterface
fun convertBlobToDataUri(dataUrl: String, contentType: String) {
    onBlobConverted(dataUrl, contentType)  // triggers requestFileDownload
}
```

The callback resolves to `viewModel.requestFileDownload(webView, url, null, mimeType)` in `BrowserTabFragment`. This means **any web page** — including malicious ones — can call `window.BlobConverter.convertBlobToDataUri(dataUri, mimeType)` with attacker-controlled arguments and trigger a file download with arbitrary content and MIME type, without the user having initiated a download. The intended use is only for pages where the user explicitly clicked a blob: download link and DDG's own JS ran `convertBlobIntoDataUriAndDownload`.

The risk is limited by whether `requestFileDownload` shows a user confirmation dialog before writing, but the bridge itself has no gate.

**Potential Mitigation**

- Migrate to `WebViewCompat.addDocumentStartJavaScript` with a restricted origin allowlist (already used in the feature-flag-enabled path for newer Android versions — apply same approach when falling back to `addJavascriptInterface`)
- Or: validate that `dataUrl` begins with `data:` scheme and that the content matches a safe MIME type before dispatching the download

**Relevant Files**

- `app/src/main/java/com/duckduckgo/app/browser/downloader/BlobConverterJavascriptInterface.kt`
- `app/src/main/java/com/duckduckgo/app/browser/downloader/BlobConverterInjector.kt`
- `app/src/main/java/com/duckduckgo/app/browser/BrowserTabFragment.kt:4228`
- `app/src/main/java/com/duckduckgo/app/browser/BrowserTabViewModel.kt:3786`

---

## Finding 2: loginDetected() Spoofable by Any Web Page

**CSV rows:** 15 (Intent-webview_new-35, deepseek-r1:8b — "Login Simulation"), 26 (Intent-webview_new-36, qwen2.5-coder:7b — "No Protocol & Origin Security"), 33 (Intent-webview_new-36, phi4:14b — "Missing Origin Validation in Message Event Listeners"), 37 (Intent-webview_new-36, gemma3:12b — "Missing Origin Validation in WebView Bridging")

**Problem Summary**

`LoginDetectionJavascriptInterface` is registered globally (no URL allowlist) for all WebView pages:

```kotlin
@JavascriptInterface
fun loginDetected() {
    onLoginDetected()  // → viewModel.loginDetected() → NavigationEvent.LoginAttempt
}
```

`viewModel.loginDetected()` fires `navigationAwareLoginDetector.onEvent(NavigationEvent.LoginAttempt(currentUrl))`, which triggers the automatic fireproofing flow — a dialog asking the user if they want to fireproof the current site (preserving its cookies across Fire/data-clear events).

**Any web page** can call `window.LoginDetection.loginDetected()` at any time, causing the fireproofing prompt to appear for that page. A malicious or tracking-heavy site could exploit this to socially engineer the user into fireproofing it, which would permanently preserve that site's cookies even when the user uses Fire to clear browsing data — directly undermining DDG's core privacy feature.

The `log(message)` method on the same interface is harmless: it only calls `logcat(INFO)`, which is inaccessible to other apps on Android 4.1+ without `READ_LOGS` permission.

**Potential Mitigation**

- Apply the same URL-path heuristic already present in `DOMLoginDetector.evaluateIfLoginPostRequest()` (checks for `login|sign-in|signin|session` in the path) before accepting a `loginDetected()` signal from the bridge — i.e., cross-validate against the current URL before dispatching `LoginAttempt`
- Or: only register the interface after a POST request to a login-path URL has been intercepted (current flow already detects this in `onEvent(ShouldInterceptRequest)` before calling `scanForPasswordFields`)

**Relevant Files**

- `app/src/main/java/com/duckduckgo/app/browser/logindetection/LoginDetectionJavascriptInterface.kt`
- `app/src/main/java/com/duckduckgo/app/browser/logindetection/DOMLoginDetector.kt`
- `app/src/main/java/com/duckduckgo/app/browser/BrowserTabFragment.kt:4047`
- `app/src/main/java/com/duckduckgo/app/browser/BrowserTabViewModel.kt:3781`
