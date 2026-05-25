# Unvalidated Origin Access to WebView JavaScript Bridge in `LoginScreen`

## Detection note

This issue was identified through automated LLM-based static analysis of WebView `addJavascriptInterface` bridges, as part of academic security research at the University of Southern Denmark (SDU) in the context of a masters level course named Engineering in Research.

The finding was manually reviewed before submission.

To aid the purposes of our research, we would kindly request acknowledgement of the reported issue as well as a final verdict from the open source community working on this repository, even if the issue is not acted on.

We are reporting in good faith and are happy to answer questions.

## Summary

`LoginScreen.kt` attaches a JavaScript interface named `"Android"` to a WebView that navigates external origins (`accounts.google.com` → `music.youtube.com`) with no origin check at the bridge level. Additionally, `onPageFinished` unconditionally injects JavaScript on every page load regardless of the current URL. Any JavaScript executing in the WebView during the OAuth flow — including from intermediate redirect pages — can invoke bridge methods with attacker-controlled strings, potentially corrupting the app's stored YouTube session tokens (`visitorData`, `dataSyncId`).

**Severity:** Medium
**Affected version(s):** v71 (latest at time of analysis)

---

## Affected file(s)

- `app/src/main/java/com/dd3boh/outertune/ui/screens/LoginScreen.kt` — bridge registration and `onPageFinished` injection (line 63–100)

---

## Vulnerable code

```kotlin
// LoginScreen.kt:63-100 — bridge accessible to all pages during OAuth navigation
webView.addJavascriptInterface(object : Any() {
    @JavascriptInterface
    fun onRetrieveVisitorData(data: String) {
        // Stores attacker-controlled string to DataStore with no origin check
        coroutineScope.launch { dataStore.edit { it[VISITOR_DATA] = data } }
    }

    @JavascriptInterface
    fun onRetrieveDataSyncId(data: String) {
        // Stores attacker-controlled string to DataStore with no origin check
        coroutineScope.launch { dataStore.edit { it[DATA_SYNC_ID] = data } }
    }
}, "Android")
```

---

## Proof of concept

```js
// From any page loaded during OAuth navigation (e.g., via open redirect):
Android.onRetrieveVisitorData("attacker-controlled-value");
Android.onRetrieveDataSyncId("attacker-controlled-value");
```

An open redirect on Google's OAuth flow, or a compromised intermediate redirect page, could deliver this payload.

---

## Impact

An attacker who achieves JavaScript execution during the OAuth navigation (for example, via an open redirect on the Google login flow or a compromised page in the redirect chain) can overwrite the app's stored YouTube session identifiers (`VISITOR_DATA`, `DATA_SYNC_ID`). This corrupts the app's YouTube session state. The bridge methods write only to DataStore preferences — there are no dangerous sinks (no SQL, no file I/O, no reflection), so impact is limited to session corruption rather than code execution or data exfiltration.

---

## Suggested mitigation

Add an origin check in `onPageFinished` before injecting JavaScript — only inject when the current URL matches a trusted origin:

```kotlin
override fun onPageFinished(view: WebView, url: String?) {
    if (url?.startsWith("https://music.youtube.com") == true) {
        view.evaluateJavascript("...injection script...", null)
    }
}
```

Alternatively, remove `addJavascriptInterface` entirely and communicate results via `evaluateJavascript` callbacks restricted to known-good origins, eliminating the persistent bridge.
