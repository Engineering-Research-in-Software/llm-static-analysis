# Security Audit Report: Hybrid Bridge Data Flows
**Target:** `com.github.samotari.paynoway_20100`

---

## 1. EXECUTIVE SUMMARY
*   **Total Exposed Methods:** 7 distinct signature entries identified across three interface objects (`_cordovaNative`, `cordova_iab`, and an anonymous object).
*   **Risk Posture:** **CRITICAL**. The application relies heavily on the Cordova framework's `exec` bridge. The presence of `_cordovaNative` combined with `InAppBrowser`'s `postMessage` interfaces suggests a high probability of cross-context pollution. The primary risk is that a compromised remote origin (if loaded via `InAppBrowser` or a primary WebView) can trigger arbitrary native actions by invoking the `exec` method, effectively bypassing the Android Sandbox.

---

## 2. CRITICAL VULNERABILITY FINDINGS

### Vulnerability 1: Arbitrary Native Command Execution via `_cordovaNative.exec`
*   **Risk Level:** **CRITICAL**
*   **Data Flow Path:** [Web Context/Injected JS] -> `_cordovaNative.exec(int, String, String, String, String)` -> `org.apache.cordova.engine.SystemExposedJsApi` -> `CordovaPlugin.execute()`
*   **Technical Description:** The `exec` method is the core of the Cordova bridge. It takes four strings: `service`, `action`, `callbackId`, and `args`. If the WebView's origin is not strictly locked down, any injected JavaScript (via XSS or a malicious `InAppBrowser` URL) can call `_cordovaNative.exec` to trigger *any* registered Cordova plugin. This allows an attacker to execute system-level operations, such as reading contacts, accessing the camera, or manipulating the file system, provided the app holds those permissions.
*   **Evidence:** Interface `_cordovaNative` exposing `exec(ILjava/lang/String;...)`.

### Vulnerability 2: Insecure `postMessage` Sink in `cordova_iab`
*   **Risk Level:** **HIGH**
*   **Data Flow Path:** [Malicious JS in InAppBrowser] -> `window.cordova_iab.postMessage(String)` -> `org.apache.cordova.inappbrowser.InAppBrowser`
*   **Technical Description:** The `cordova_iab` object exposes `postMessage`. If the native Java handler for this bridge does not strictly validate the `origin` of the incoming message, an attacker who manages to load a malicious page in the `InAppBrowser` can spoof messages to the parent application. If the parent application listens for these messages to perform sensitive actions (e.g., updating user tokens or changing app state), this leads to **Confused Deputy** attacks.
*   **Evidence:** Interface `cordova_iab` exposing `postMessage(String)`.

---

## 3. REMEDIATION STEPS

1.  **Strict Origin Whitelisting:**
    *   Do not allow `InAppBrowser` or the main WebView to load arbitrary URLs. Implement a strict whitelist of trusted domains in `res/xml/config.xml` (Cordova `access` tags).
    *   For `postMessage` handlers, explicitly check `event.origin` in the JavaScript and the Java `InAppBrowser` callback handler. If the origin is not `file:///android_asset/...` or a trusted HTTPS domain, reject the payload.

2.  **Plugin Minimization (Bridge Hardening):**
    *   Review all installed Cordova plugins. Remove unused plugins that expose `exec` capabilities.
    *   If using modern Android (API 17+), ensure all Java methods exposed to JS are annotated with `@JavascriptInterface`.

3.  **Bridge Validation:**
    *   In the Java layer, implement a "Request Interceptor" for the `exec` method. Before passing parameters to the plugin, validate that the requested `service` and `action` match an internal whitelist of permitted functionality.

4.  **Content Security Policy (CSP):**
    *   Enforce a robust CSP in the HTML headers:
        `Content-Security-Policy: default-src 'self'; script-src 'self'; connect-src 'self' https://api.trusted-server.com;`
    *   This prevents unauthorized third-party scripts from executing `window.cordovaNative.exec`.

---

## 4. CONFIDENCE SCORE: 9/10
*   **Rationale:** The identified interface signatures are standard for Cordova/InAppBrowser implementations. The security implications of exposing `exec` and `postMessage` in a hybrid environment are well-documented and represent a classic architectural vulnerability in mobile applications. The assessment is limited only by the absence of the compiled APK's specific plugin configuration (which would define *which* services `exec` can actually trigger).