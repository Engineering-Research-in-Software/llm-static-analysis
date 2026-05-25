# Security Research Findings — com.degeder.yam (PARTIAL Verdicts)

The following findings were classified as **PARTIAL** across callsites
`Intent-webview_new-19` and `Intent-webview_new-20`. They represent real
exposure surface that does not constitute a fully exploitable vulnerability
in this app's current configuration, but warrants developer attention.

No findings were classified as **VALID**. The majority of findings are AI
hallucinations — fabricated code examples and speculative attack chains that
have no basis in the actual application code.

---

## _cordovaNative Bridge Exposed Without Origin Validation

**Problem:** `_cordovaNative.exec()`, `retrieveJsMessages()`, and
`setNativeToJsBridgeMode()` are `@JavascriptInterface` methods accessible to
any JavaScript executing inside the WebView. The Cordova bridge layer contains
no explicit per-call origin validation — any page loaded in the WebView can
invoke these methods regardless of its origin.

**Potential Mitigation:** Capacitor 7+ serves content exclusively from
`http://localhost` and validates origin inside its own bridge layer. Ensure
no external URLs are navigated to by the WebView. Audit `allowNavigation`
entries in `config.xml` — the setting must not permit wildcard or external
origins. Verify no `loadUrl()` calls exist in native code.

**Relevant Files:**
- `android/app/src/main/res/xml/config.xml`
- `android/app/src/main/java/com/degeder/yam/MainActivity.java`

---

## setNativeToJsBridgeMode Exposed to JavaScript

**Problem:** `setNativeToJsBridgeMode(int, int)` is a `@JavascriptInterface`
method that allows JavaScript to control how native-to-JavaScript message
delivery works (polling mode vs. online/push mode). Exposing this control to
arbitrary JavaScript is unnecessary and broadens the bridge attack surface.

**Potential Mitigation:** This is a Cordova framework method in the compiled
engine class (`org.apache.cordova.engine.b`) — no app-level fix is available
without patching or replacing the Cordova engine. Impact for this specific app
is low: content is served from `localhost` and no external navigation is
configured. Track the upstream Cordova engine version for security patches.

**Relevant Files:**
- Android compiled Cordova engine class `org.apache.cordova.engine.b` (not in source tree — present in compiled APK via `@capacitor/android` dependency)

---

## Cordova config.xml Wildcard `<access origin="*" />`

**Problem:** The Cordova `config.xml` contains `<access origin="*" />`,
configuring a wildcard origin access policy. Combined with the `_cordovaNative`
bridge being exposed to all WebView JavaScript, any URL that the WebView
navigates to could invoke bridge methods directly.

**Potential Mitigation:** Restrict the access policy to
`<access origin="capacitor://localhost" />`, or use Capacitor's
`allowNavigation` configuration to explicitly block external URL navigation.
This eliminates the risk of an injected or redirected page reaching the
native bridge. Since YAM never navigates to external URLs in practice, this
is a hardening measure rather than an active vulnerability fix.

**Relevant Files:**
- `android/app/src/main/res/xml/config.xml`
