# Security Research Findings — Subz (com.flasskamp.subz v4)

Three callsites analyzed (Intent-webview_new-82 through 84). The app is a dual-framework hybrid: callsite 82 is the Capacitor `androidBridge` (`MessageHandler`), and callsites 83–84 are the Apache Cordova `_cordovaNative` (`SystemExposedJsApi`). Both frameworks are registered in the same app, indicating a Capacitor migration from Cordova that left both bridges active. No JavaScript snippets were available to inspectors.

All findings are PARTIAL. Models consistently hallucinated specific attack paths through `exec()` (SQL injection, RCE, file access via plugin names — all INVALID); the real concerns are at the framework level. gemma3 produced the highest-quality analysis, identifying bridge-mode manipulation and plugin-manager exposure in addition to origin validation. deepseek correctly classified callsites 82 and 83 as having no directly exploitable paths from the Java layer alone.

---

## Finding 1: No Origin Validation on Both Bridges

**Verdict**: PARTIAL  
**Reported by**: qwen2.5 (callsites 82, 84, "Lack of Origin Validation" / "Protocol & Origin Security"), phi4 (callsites 82–83, "Lack of Origin Validation"), deepseek-r1 (callsite 84, "Lack of Origin Security"), gemma3 (callsite 83, "Lack of Origin Validation"), llama3.2 (callsite 84, "Potential Protocol & Origin Security")

### Problem Summary

Both `androidBridge` (Capacitor) and `_cordovaNative` (Cordova) are registered with `addJavascriptInterface` with no runtime origin check. Any JavaScript executing in the WebView — including scripts from the app's remote back-end, third-party CDN resources, or content injected via XSS — can call either bridge.

```java
// Capacitor: MessageHandler registered as "androidBridge"
webView.addJavascriptInterface(messageHandler, "androidBridge");

// Cordova: SystemExposedJsApi registered as "_cordovaNative"
SystemWebViewEngine.exposeJsInterface(webView, cordovaBridge);
```

For Cordova the risk is compounded because `exec()` routes to all registered plugins (see Finding 2). For Capacitor the same applies to registered Capacitor plugins. A language-learning app like Subz likely registers plugins for network access, local storage, and possibly file I/O — all reachable from any injected script.

### Potential Mitigation

Both Capacitor and Cordova support allow-listing origins. For Cordova, set `<allow-navigation>` and `<content-security-policy>` in `config.xml`. For Capacitor, configure `server.allowNavigation` in `capacitor.config.json`. At the Java level each bridge callback can additionally check `WebView.getUrl()` against expected origins before dispatching.

### Relevant Files

- `node_modules/@capacitor/android/capacitor/src/main/java/com/getcapacitor/MessageHandler.java` — Capacitor bridge handler (plugin-provided)
- `node_modules/cordova-android/framework/src/org/apache/cordova/engine/SystemWebViewEngine.java` — `exposeJsInterface()` registration
- `config.xml` / `capacitor.config.json` — origin and navigation allow-lists

---

## Finding 2: Unrestricted Plugin Dispatch via Cordova `exec()`

**Verdict**: PARTIAL  
**Reported by**: gemma3 (callsite 82, "Potential PluginManager Influence")

### Problem Summary

The Cordova `exec(int callbackId, String service, String action, String rawArgs, String callbackContext)` method routes directly to any Cordova plugin registered under `service` with the given `action` and `rawArgs` (a JSON string). Any JavaScript that can reach `_cordovaNative.exec(...)` can invoke any plugin the app has registered:

```js
// From JavaScript in the WebView
_cordovaNative.exec(1, "File", "readAsText",
    '[{"uri":"/data/data/com.flasskamp.subz_4/shared_prefs/default.xml"}]', '');
```

The plugin name and action are caller-controlled strings with no allowlist enforced in the Java bridge layer itself; enforcement is done per-plugin in Cordova's plugin execution pipeline, which varies by plugin quality. The app's registered plugin set (visible only at runtime) determines the full impact.

### Potential Mitigation

1. Audit all registered Cordova plugins and remove those not actively used.
2. Apply Cordova's built-in `ContentSecurityPolicy` and `AllowedNavigation` to restrict which origins can issue `exec()` calls.
3. For the most sensitive plugins (File, Camera, Contacts), add explicit origin validation at the plugin `execute()` entry point.

### Relevant Files

- `node_modules/cordova-android/framework/src/org/apache/cordova/engine/SystemExposedJsApi.java` — `exec()` implementation
- `node_modules/cordova-android/framework/src/org/apache/cordova/PluginManager.java` — plugin dispatch
- `config.xml` — registered plugin list (`<plugin>` declarations)

---

## Finding 3: Bridge Mode Manipulation via `setNativeToJsBridgeMode(int, int)`

**Verdict**: PARTIAL (low severity)  
**Reported by**: gemma3 (callsites 83–84, "setNativeToJsBridgeMode - Potential for Bridge Manipulation" / "Untrusted Input to setNativeToJsBridgeMode")

### Problem Summary

`setNativeToJsBridgeMode(int bridgeMode, int webViewType)` configures how the Cordova native layer pushes messages back to JavaScript (polling vs. online bridging). If malicious JavaScript calls this with unexpected integer values, it could switch the bridge to polling mode, interrupt the native-to-JS message queue, or trigger undefined behavior in the bridge state machine — effectively disrupting all subsequent native-to-JS communication for the session.

```js
// Disable native→JS push messaging, forcing a broken polling mode
_cordovaNative.setNativeToJsBridgeMode(99, 0);
```

This is a denial-of-service within the current session rather than a data-extraction primitive, but it can break the app's functionality for the user.

### Potential Mitigation

Validate that `bridgeMode` and `webViewType` are within the expected enumerated values before applying the mode change, and add origin validation before processing this call.

Android’s security guidance states that addJavascriptInterface exposes the Java object to all frames in the WebView and that there is no built-in mechanism to verify the origin of the calling frame. It also recommends validating loaded content and removing interfaces before loading untrusted content. Link:https://developer.android.com/privacy-and-security/risks/insecure-webview-native-bridges 



### Links 
- https://gitlab.com/fdroid/fdroiddata/-/raw/master/metadata/com.flasskamp.subz.yml
- https://codeberg.org/epinez/Subz/src/tag/v1.3
- https://github.com/ionic-team/capacitor/blob/main/android/capacitor/src/main/java/com/getcapacitor/MessageHandler.java
