# Security Research Findings — Snapdrop (com.fmsys.snapdrop v45)

Two callsites analyzed (Intent-webview_new-87 and 88), both exposing the same 14-method `SnapdropAndroid` bridge in `MainActivity`. Snapdrop is an open-source P2P file/text sharing app that runs its web UI in a WebView and uses the bridge to pass received files and clipboard operations back to Android. No JavaScript snippets were available to inspectors.

All four findings below are PARTIAL: the bridge method signatures confirm the attack surface and the open-source implementation (github.com/fm-sys/snapdrop-android) corroborates the data flows, but exact exploitability for path traversal depends on the MediaStore vs. direct-file-path code path in the current build. deepseek-r1 and phi4 achieved the best coverage, identifying all four concerns. gemma3 covered the same surface with slightly more hallucination. qwen2.5 and llama3.2 were partially effective; starcoder2 produced no output.

---

## Finding 1: Path Traversal via `newFile(String, String, String)` and `saveDownloadFileName(String, String)`

**Verdict**: PARTIAL  
**Reported by**: deepseek-r1 (callsite 87, "File Creation with Path Traversal Risk" and "Unsanitized Data in File Operations"), phi4 (callsites 87–88, "File Path Traversal Vulnerability" and "Path Traversal via newFile and saveDownloadFileName"), gemma3 (callsites 87–88, "Potential Path Traversal in newFile" and "Unvalidated File Name in newFile"), llama3.2 (callsite 87, "Potential Path Traversal Vulnerability"), qwen2.5 (callsite 88, "Potential Path Traversal Risk")

### Problem Summary

`newFile(String name, String mime, String message)` is called from JavaScript when a peer transmits a file. The `name` parameter is the filename provided by the remote peer; `mime` is the MIME type; `message` is the content (typically base64-encoded). The typical implementation creates a file entry via Android's `DownloadManager` or `MediaStore`:

```java
@JavascriptInterface
public void newFile(String name, String mime, String message) {
    // name and mime come directly from the remote peer via WebView JS
    ContentValues values = new ContentValues();
    values.put(MediaStore.Downloads.DISPLAY_NAME, name);
    values.put(MediaStore.Downloads.MIME_TYPE, mime);
    Uri uri = getContentResolver().insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values);
    // write message bytes to uri ...
}
```

On Android 10+ using `MediaStore.Downloads`, the `DISPLAY_NAME` is sanitized by the system and path traversal is not possible. However, if any fallback code path constructs a `File` from `name` directly (e.g., `new File(Environment.getExternalStorageDirectory(), name)`), a peer-supplied name like `../../Download/evil.apk` can write outside the intended directory.

`saveDownloadFileName(String name, String mime)` stores the download filename for later use and is subject to the same concern if the stored value is later passed to a `File` constructor without canonicalization.

Data flow:
```
Peer JS  SnapdropAndroid.newFile(name, mime, data)
  → MainActivity$SnapdropInterface.newFile(String, String, String)
    → MediaStore.insert() with DISPLAY_NAME=name   // safe path
    OR → new File(baseDir, name)                    // unsafe path if present
```

### Potential Mitigation

1. Use only `MediaStore.Downloads` on API 29+ and `getExternalFilesDir()` on earlier versions — never construct `File` from the peer-supplied name.
2. Before any `File` construction, strip all path separators from `name`: `name = new File(name).getName();`
3. Reject MIME types that map to executable formats (`.apk`, `.dex`, `.sh`).

### Relevant Files

- `app/src/main/java/com/fmsys/snapdrop/MainActivity.java` — `newFile()` and `saveDownloadFileName()` `@JavascriptInterface` methods

---

## Finding 2: Clipboard Poisoning via `copyToClipboard(String)`

**Verdict**: PARTIAL  
**Reported by**: deepseek-r1 (callsite 87, "Clipboard Access with Sensitive Data"), phi4 (callsites 87–88, "Clipboard Injection Vulnerability" and "Clipboard Manipulation via copyToClipboard"), gemma3 (callsite 87, "Uncontrolled Data in copyToClipboard")

### Problem Summary

`copyToClipboard(String text)` writes arbitrary JavaScript-supplied text to the system clipboard. In the Snapdrop use case, a remote peer sends text and the web UI calls this method to place the received text in the clipboard for the user. Because no origin check is present, any JavaScript executing in the WebView (including a malicious page loaded via a manipulated deep-link intent — see jsdetails: `Intent.getDataString()` used as URL) can call this method with attacker-chosen content.

Practical impacts: replacement of clipboard contents with a malicious URL, payment address substitution, poisoning clipboard-based password workflows.

```java
@JavascriptInterface
public void copyToClipboard(String text) {
    ClipboardManager clipboard = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
    clipboard.setPrimaryClip(ClipData.newPlainText("Snapdrop", text));
}
```

### Potential Mitigation

1. Add origin validation (see Finding 4) before executing clipboard writes.
2. Show a persistent notification or toast when the bridge writes to the clipboard, so users know their clipboard was changed.

### Relevant Files

- `app/src/main/java/com/fmsys/snapdrop/MainActivity.java` — `copyToClipboard()` bridge method

---

## Finding 3: Share-Intent Data Exfiltration via `getTextFromUploadIntent()`

**Verdict**: PARTIAL  
**Reported by**: phi4 (callsite 87, "PII Leakage via Upload Intent" and callsite 88, "Intent Redirection Vulnerability via getTextFromUploadIntent"), gemma3 (callsite 87, "Possible Information Leakage via getTextFromUploadIntent" and callsite 88, "getTextFromUploadIntent – Potential Intent Redirection")

### Problem Summary

`getTextFromUploadIntent()` returns the text payload from the Android `ACTION_SEND` / `ACTION_PROCESS_TEXT` intent that launched Snapdrop. A user opening Snapdrop via the system share sheet (e.g., sharing a password, a bank account number, or private note from another app) causes that text to be held in the activity's intent. Any JavaScript in the WebView can call `getTextFromUploadIntent()` and read this text before the user has consented to share it.

Data flow:
```
User shares text from App A → ACTION_SEND intent → Snapdrop MainActivity
  Malicious JS:  var secret = SnapdropAndroid.getTextFromUploadIntent();
  → returns the user's shared text to attacker-controlled JS
```

If Snapdrop loads any third-party content in its WebView (e.g., via a deep-link that passes a URL), that content can silently read whatever text the user intended to share.

### Potential Mitigation

1. Clear the intent text (`getIntent().removeExtra(Intent.EXTRA_TEXT)`) immediately after the WebView loads and the legitimate Snapdrop page has consumed it.
2. Gate `getTextFromUploadIntent()` behind origin validation so only the Snapdrop web UI origin can call it.
3. Return a non-null value only once: set the intent extra to null after the first call.

### Relevant Files

- `app/src/main/java/com/fmsys/snapdrop/MainActivity.java` — `getTextFromUploadIntent()` and `resetUploadIntent()` bridge methods

---

## Finding 4: No Origin Validation on `SnapdropAndroid` Bridge

**Verdict**: PARTIAL  
**Reported by**: deepseek-r1 (callsite 87, "Exposed Methods Enable Cross-Domain Attacks"), phi4 (callsite 88, "Origin Validation Missing in Event Listeners"), gemma3 (callsite 88, "Lack of Origin Validation – Cross-Site Scripting")

### Problem Summary

`SnapdropAndroid` is registered with no origin restriction. The jsdetails table shows that `MainActivity` can load a URL derived from `Intent.getDataString()` — meaning a crafted deep-link intent can cause the WebView to load an attacker-chosen URL that immediately has full access to all 14 bridge methods, including `newFile`, `copyToClipboard`, and `getTextFromUploadIntent`.

```java
// Likely registration
webView.addJavascriptInterface(new SnapdropInterface(this), "SnapdropAndroid");
// MainActivity also processes: intent.getDataString() → webView.loadUrl(...)
```

### Potential Mitigation

1. Before any bridge method executes, verify `webView.getUrl()` is the expected Snapdrop origin (local asset or `snapdrop.net`/`pairdrop.net`).
2. Validate and sanitize the URL from `getDataString()` before passing it to `loadUrl()` — restrict to `https://` and expected hosts only.

### Relevant Files

- `app/src/main/java/com/fmsys/snapdrop/MainActivity.java` — `addJavascriptInterface` call and intent-URL loading logic
# Security Finding Verification — com.fmsys.snapdrop (v45)

**App**: Snapdrop/Pairdrop Android client  
**Bridge**: `SnapdropAndroid` (`com.fmsys.snapdrop.JavaScriptInterface`)  
**Methods**: `copyToClipboard(String)`, `newFile(String, String, String)`, `onBytes(String)`, `saveDownloadFileName(String, String)`, `getTextFromUploadIntent()`, `vibrate()`, `shouldOpenSendTextDialog()`, `getYouAreKnownAsTranslationString(String)`  
**WebView loads**: `https://pairdrop.net` or user-configured URL (external!)  
**Verdict summary**: 0 VALID · 27 PARTIAL · 18 INVALID

---

## PARTIAL Findings

### 1. Path Traversal via `newFile` (Older Android)

**Finding title**: Path Traversal Vulnerability in `newFile` / Unvalidated File Name in `newFile`

**Problem summary**: On Android API 28 and below, `newFile(fileName, mimeType, fileSize)` creates a temp file in `context.getCacheDir()` using `File.createTempFile(nameSplit[0], "." + extension, cacheDir)`. The `fileName` parameter is split on `"\\."` to extract the name and extension but is not sanitized for path traversal sequences (`../`). On API 29+, the `DocumentFile` scoped storage API mitigates this. On older devices, a malicious server page (or compromised pairdrop.net) could craft a filename like `../../shared_prefs/malicious` to write outside the cache directory.

**Potential mitigation**: Sanitize `fileName` to strip path separators before use; on all API levels, use only the base filename (no directory components).

**Relevant files**:
- `app/src/main/java/com/fmsys/snapdrop/JavaScriptInterface.java` — `newFile()`, `createFileWrapper()`

---

### 2. Clipboard Overwrite via `copyToClipboard`

**Finding title**: Clipboard Manipulation via `copyToClipboard` / Clipboard Injection Vulnerability

**Problem summary**: `copyToClipboard(text)` unconditionally copies the provided string to the system clipboard. The WebView loads from an external server (`pairdrop.net` or a user-configured URL). A compromised server page can call `SnapdropAndroid.copyToClipboard("attacker text")` to overwrite the user's clipboard silently.

**Potential mitigation**: Restrict clipboard writes to user-initiated transfers (the app should already only call this on receiving a file/text, but the bridge method has no such guard).

**Relevant files**:
- `app/src/main/java/com/fmsys/snapdrop/JavaScriptInterface.java` — `copyToClipboard()`

---

### 3. Intent Data Exposure via `getTextFromUploadIntent`

**Finding title**: Intent Redirection Vulnerability via `getTextFromUploadIntent`

**Problem summary**: `getTextFromUploadIntent()` returns text from the app's current upload Intent (clipboard data and `EXTRA_PROCESS_TEXT`). This data can include whatever the user last shared into Snapdrop from another app. A compromised server page can call this method to silently read the user's in-progress upload text.

**Potential mitigation**: Ensure this method is only called in response to an explicit user action (e.g., after confirming the send dialog), not automatically when a page loads.

**Relevant files**:
- `app/src/main/java/com/fmsys/snapdrop/JavaScriptInterface.java` — `getTextFromUploadIntent()`
- `app/src/main/java/com/fmsys/snapdrop/MainActivity.java` — `getTextFromUploadIntent()`

---

### 4. User-Configurable WebView URL

**Finding title**: Origin Validation Missing in Event Listeners

**Problem summary**: The app allows users to configure a custom server URL. If a user sets a malicious URL, all bridge methods become callable by that server's JavaScript. The default `pairdrop.net` is trusted, but the custom URL feature has no allowlist or validation.

**Potential mitigation**: Validate custom URLs (HTTPS only, no IP addresses unless explicitly allowed); warn users about the security implications of custom server URLs.

**Relevant files**:
- `app/src/main/java/com/fmsys/snapdrop/OnboardingFragment2.java` — URL configuration
### Links to github 
- https://github.com/fm-sys/pairdrop-android/tree/v2.3.1

### The issues have been partilly mitigated. 