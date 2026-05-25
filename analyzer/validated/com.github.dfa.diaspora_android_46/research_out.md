# Security Research Findings — Diaspora Android (com.github.dfa.diaspora_android v46)

One callsite analyzed (Intent-webview_new-105) in `DiasporaStreamFragment`. The bridge `AndroidBridge` (`DiasporaStreamFragment$JavaScriptInterface`) exposes two methods: `contentHasBeenShared()` and `setUserProfile(String)`. No JavaScript snippets were available to inspectors.

All findings below are PARTIAL. The interface structure confirms the attack surface exists, but exploitability of `setUserProfile` depends on the downstream implementation which was not directly inspected. AI model evidence was predominantly fabricated: deepseek-r1 generated nine specific attack paths (SQL injection, path traversal, intent redirection, reflection-based RCE, XSS, IDOR, DoS — all INVALID) with no basis in the available data; gemma3 similarly hallucinated reflection and information-disclosure chains. Only phi4 produced structurally correct, non-hallucinated findings covering both real concerns. starcoder2 and llama3.2 produced no output.

---

## Finding 1: Unvalidated Input in `setUserProfile(String)`

**Verdict**: PARTIAL  
**Reported by**: deepseek-r1 (row 10, as "Missing Input Validation"), phi4 (row 12, as "Insecure Data Handling")

### Problem Summary

The `setUserProfile` method, part of `DiasporaStreamFragment$JavaScriptInterface` registered under the name `AndroidBridge`, accepts a caller-controlled `String` from JavaScript with no input validation at the bridge layer. In the Diaspora Android context, this string is expected to carry a JSON payload from the trusted Diaspora pod describing the authenticated user's profile (name, GUID, avatar URL). Because no origin check gates the call (see Finding 2), any JavaScript executing in the WebView can supply an arbitrary string.

Data flow:
```
JS  AndroidBridge.setUserProfile(profileStr)
  → DiasporaStreamFragment$JavaScriptInterface.setUserProfile(String)   // run()V context
    → JSON parsing → local profile storage (SharedPreferences / DiasporaUserProfile)
```

The risk level depends on the `setUserProfile` implementation: if all JSON fields are stored through parameterised APIs (Android's `SharedPreferences.Editor`, `SQLiteDatabase` bound arguments), severity is low. If any field is directly concatenated into a query, key, or URI, the risk rises.

Note: deepseek-r1 fabricated specific sink implementations (SQL queries, file path construction, reflection calls, HTTP response concatenation). None of these were confirmed in the available interface data. The only confirmed fact is that the bridge accepts an unconstrained string.

### Potential Mitigation

1. Validate and cap the JSON string before parsing: reject inputs exceeding a reasonable size threshold and enforce a strict schema (only expected top-level keys accepted).
2. Ensure all SQLite operations that touch profile fields use parameterised queries via `SQLiteDatabase.insert()` / `ContentValues`, never string concatenation.
3. Treat any URL field extracted from the JSON (avatar, pod URL) as untrusted; validate scheme and host before passing to `Intent`, `WebView.loadUrl`, or image-loading libraries.

### Relevant Files

- `app/src/main/java/com/github/dfa/diaspora_android/activity/DiasporaStreamFragment.java` — `setUserProfile()` `@JavascriptInterface` method and bridge registration
- `app/src/main/java/com/github/dfa/diaspora_android/data/DiasporaUserProfile.java` — profile model that `setUserProfile` likely populates

---

## Finding 2: No Origin Validation on `AndroidBridge`

**Verdict**: PARTIAL  
**Reported by**: phi4 (row 13, as "Potential Origin Validation Lapse")

### Problem Summary

The `AndroidBridge` JavaScript interface is registered with `webView.addJavascriptInterface(...)` with no runtime check on the origin of JavaScript invocations. Both `contentHasBeenShared()` and `setUserProfile(String)` will execute for any JavaScript running in the WebView — regardless of whether it originated from the configured Diaspora pod, a third-party iframe embedded by the pod, an HTTP redirect, or an XSS payload injected into pod-served content. In a federated network like Diaspora, where pod operators vary in security posture, a compromised or malicious pod can invoke bridge methods silently.

```java
// Typical registration (no domain restriction possible at API level)
webView.addJavascriptInterface(new JavaScriptInterface(this), "AndroidBridge");
```

Android's `@JavascriptInterface` mechanism provides no built-in origin restriction; enforcement must be implemented by the application.

### Potential Mitigation

Before processing any bridge call, verify the WebView's current URL against the user's stored pod address:

```java
@JavascriptInterface
public void setUserProfile(String profileJson) {
    if (!isTrustedOrigin()) return;
    // process profile
}

private boolean isTrustedOrigin() {
    String url = webView.getUrl();
    return url != null && Uri.parse(url).getHost()
           .equals(Uri.parse(storedPodUrl).getHost());
}
```

Where `storedPodUrl` is read from SharedPreferences at the time of the check, not cached at bridge-registration time.

### Relevant Files

- `app/src/main/java/com/github/dfa/diaspora_android/activity/DiasporaStreamFragment.java` — `addJavascriptInterface` call and all `@JavascriptInterface` method declarations
