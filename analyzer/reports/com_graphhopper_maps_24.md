# Security Audit Report: com.graphhopper.maps_24

## 1. EXECUTIVE SUMMARY
*   **Total Attack Surface**: 3 primary Interface Objects (`androidBridge`, `Capacitor*`, `_cordovaNative`).
*   **Risk Posture**: **CRITICAL**. The presence of the `_cordovaNative` interface (Apache Cordova bridge) in a modern mapping application indicates a high risk of "Bridge-to-Native" escalation. Cordova’s `exec()` mechanism is a well-documented conduit for Arbitrary Code Execution (ACE) and sandbox escape if the WebView is configured to load untrusted or intercepted remote content.

---

## 2. CRITICAL VULNERABILITY FINDINGS

### **Title**: Arbitrary Code Execution (ACE) via Cordova Bridge Injection
*   **Risk Level**: **CRITICAL**
*   **Data Flow Path**: `JS (eval/XSS)` -> `_cordovaNative.exec()` -> `Lorg/apache/cordova/engine/SystemExposedJsApi` -> `Native Plugin Registry`
*   **Technical Description**: The `_cordovaNative` interface acts as a reflection-based dispatcher. By calling `exec()`, an attacker can reach any registered Cordova plugin. If the application environment is compromised via XSS or a Man-in-the-Middle (MitM) attack, the attacker can invoke sensitive plugins (e.g., `File`, `Camera`, `Contacts`, `InAppBrowser`). Because `exec()` takes four strings as arguments, the attacker can craft arbitrary payloads to invoke native methods, potentially leading to local file system access, data theft, or device control without the user's explicit consent.
*   **Evidence**: Interface `_cordovaNative` exposes `exec(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)`. This is the core engine for all Cordova plugins.

### **Title**: Unauthorized System State Manipulation via `CapacitorSystemBarsAndroidInterface`
*   **Risk Level**: **MEDIUM**
*   **Data Flow Path**: `JS` -> `CapacitorSystemBarsAndroidInterface` -> `WindowInsetsController/SystemUI`
*   **Technical Description**: Interfaces exposed via Capacitor often allow for UI-level manipulation (e.g., hiding status bars, forcing full-screen). An attacker could exploit this to overlay transparent WebViews over system dialogs, a technique used in **Tapjacking** attacks to gain unauthorized permissions or trick users into clicking buttons they believe are part of the host application.
*   **Evidence**: Interface `CapacitorSystemBarsAndroidInterface` is exposed without observable restrictions on which origins can invoke these methods.

### **Title**: Potential PIl/Sensitive Cookie Leakage
*   **Risk Level**: **HIGH**
*   **Data Flow Path**: `CapacitorCookiesAndroidInterface` -> `WebView CookieManager` -> `JS`
*   **Technical Description**: The `CapacitorCookiesAndroidInterface` allows the JS layer to interact directly with the app's `CookieManager`. If the app uses persistent login sessions, an attacker injecting malicious JS can retrieve session cookies via `getCookies()` and exfiltrate them to an attacker-controlled server.
*   **Evidence**: Exposed `CapacitorCookiesAndroidInterface` implies a bidirectional sync between native cookie storage and the JS context.

---

## 3. REMEDIATION STEPS

1.  **Restrict `addJavascriptInterface`**: 
    *   Do not expose the entire `_cordovaNative` or `Capacitor` bridges to the global `window` object unless strictly required for specific features. 
    *   If possible, migrate to a `WebMessageListener` (Android API 27+) which provides origin-based validation, effectively preventing XSS-based bridge exploitation.

2.  **Origin Validation**: 
    *   In the `WebViewClient.shouldInterceptRequest` or `onPageStarted` methods, verify that the origin of the content is strictly limited to the local file system (`file:///android_asset/`) or a trusted domain (e.g., `https://graphhopper.com/`). Reject all `http://` traffic.

3.  **Input Sanitization**: 
    *   Every string passed into `exec()` or any Java method must be validated against a strict allow-list. Do not pass untrusted strings into constructors or reflection-based execution flows.

4.  **Interface Bloat Removal**: 
    *   Audit the `Capacitor` and `Cordova` plugins. If the app does not use the `File` or `Contacts` plugin, remove the native JAR/module entirely. **Unused interfaces are the primary source of escalation.**

---

## 4. CONFIDENCE SCORE: 9/10
*   *Rationale*: The exposure of the `_cordovaNative` interface is standard but inherently dangerous. The structure of the interface is highly predictable, and the attack surface is well-documented in security research regarding hybrid framework vulnerabilities.