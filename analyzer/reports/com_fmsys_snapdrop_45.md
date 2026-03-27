# Security Audit Report: com.fmsys.snapdrop_45

## 1. EXECUTIVE SUMMARY
*   **Total Attack Surface**: 14 exposed methods via the `SnapdropAndroid` JavaScriptInterface.
*   **High-Level Risk Posture**: **Moderate to High**. The application bridges a web-based file-transfer protocol to native system capabilities. The primary risk vectors involve **Path Traversal via File I/O** and **Clipboard Manipulation**. Because `Snapdrop` relies on WebRTC/WebSockets, if the remote origin is compromised (e.g., via MITM or DNS hijacking), the native bridge provides an immediate execution context for malicious payloads.

---

## 2. CRITICAL VULNERABILITY FINDINGS

### A. Path Traversal & Arbitrary File Access
*   **Title**: Potential Arbitrary File Write/Path Traversal
*   **Risk Level**: **High**
*   **Data Flow Path**: `JS` -> `SnapdropAndroid.newFile(String, String, String)` -> `Java File System Operations`
*   **Technical Description**: The method `newFile(String, String, String)` likely handles incoming file metadata (name, mime-type, data). If the Java implementation does not validate the `String` arguments representing file names/paths against directory traversal sequences (e.g., `../../`), an attacker can force the application to overwrite sensitive application-private data or configuration files in the app's internal storage.
*   **Evidence**: `newFile(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V`

### B. Insecure Clipboard Interaction
*   **Title**: Unauthorized Clipboard Injection / Exfiltration
*   **Risk Level**: **Medium**
*   **Data Flow Path**: `JS` -> `SnapdropAndroid.copyToClipboard(String)` -> `java.content.ClipboardManager`
*   **Technical Description**: The bridge allows JS to push arbitrary strings into the system clipboard. While this is a common feature, in a hybrid app, if the WebView is compromised via XSS, an attacker can modify the user's clipboard to replace intended URLs or sensitive data with malicious links, leading to social engineering (e.g., prompting the user to visit a malicious site).
*   **Evidence**: `copyToClipboard(Ljava/lang/String;)V`

### C. Unsafe Intent Handling
*   **Title**: Potential Intent Redirection via Intent Retrieval
*   **Risk Level**: **Medium**
*   **Data Flow Path**: `Java (Intent)` -> `SnapdropAndroid.getTextFromUploadIntent()` -> `JS Context`
*   **Technical Description**: The method `getTextFromUploadIntent()` retrieves data from the app's launch intent. If this data is passed directly into the WebView's DOM without strict encoding/sanitization, it could lead to **DOM-based XSS**. If the intent data is maliciously crafted by another app on the device, it acts as a secondary injection point into the WebView.
*   **Evidence**: `getTextFromUploadIntent()Ljava/lang/String;`

---

## 3. REMEDIATION STEPS

1.  **Input Sanitization (Mandatory)**: 
    *   For `newFile(String path, ...)`: Implement strict validation in the Java layer using `java.io.File.getCanonicalPath()`. Ensure the path is explicitly restricted to the application's dedicated `/files/` directory. Disallow all `..` sequences.
2.  **Origin Validation**: 
    *   Ensure that the `WebView` loading the Snapdrop content enforces a strict Content Security Policy (CSP). 
    *   Override `shouldOverrideUrlLoading` in the `WebViewClient` to prevent navigation to external or non-whitelisted domains.
3.  **Interface Hardening**: 
    *   Only expose the absolute minimum set of methods. If `vibrate()` or `dialogHidden()` are not required to be public, remove them from the Interface object.
    *   Annotate all exposed methods with `@JavascriptInterface` (required for API 17+).
4.  **Data Encoding**: 
    *   When returning strings from `getTextFromUploadIntent()` to the JS context, ensure the data is JSON-escaped or base64 encoded before injection into the DOM to prevent breaking out of HTML attributes.

---

## 4. CONFIDENCE SCORE: 8/10
*Reasoning*: The methodology is clear, and the interface mapping is explicit. The risk assessment assumes standard Java implementation practices for these methods (which typically involve File I/O or Android system service calls), which are historically vulnerable in hybrid configurations.