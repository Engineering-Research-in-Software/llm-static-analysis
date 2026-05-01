# Security Research Findings — LMS Material App (com.craigd.lmsmaterial.app v0.9.2)

All findings below are PARTIAL: real code paths confirmed, but exploitability requires a compromised or malicious local LMS server (trusted boundary). Evidence provided by AI models was fabricated; actual code was located and verified manually.

---

## Finding 1: Insufficient Path Sanitization in Download Service

**Problem Summary**
The `download()` @JavascriptInterface method accepts a JSON array from the LMS web page and constructs file system paths from track metadata (artist, album, filename). Path sanitization is handled by `fatSafe()`, which strips `[?<>\\:*|"/]` but does **not** strip or normalize `..` sequences. A path component like `../../sdcard/evil` would pass through unmodified and be used directly in `new File(baseDir, folder)`, potentially writing outside the intended music directory.

Data flow:
```
JS NativeReceiver.download(jsonStr)
  → DownloadItem(JSONObject)   // artist, album, filename from LMS JSON
  → getFolder() → fatSafe()   // strips special chars but not ".."
  → new File(DIRECTORY_MUSIC, folder)  // path traversal possible
```

**Potential Mitigation**
After calling `fatSafe()`, verify the resolved canonical path stays within the intended base directory:
```java
File resolved = new File(baseDir, folder).getCanonicalFile();
if (!resolved.getPath().startsWith(baseDir.getCanonicalPath())) {
    throw new SecurityException("Path traversal detected");
}
```
Alternatively, reject any path component that contains `..`.

**Relevant Files**
- `lms-material/src/main/java/com/craigd/lmsmaterial/app/DownloadService.java:87-89` — `fatSafe()` implementation
- `lms-material/src/main/java/com/craigd/lmsmaterial/app/DownloadService.java:143-155` — `getFolder()` path construction
- `lms-material/src/main/java/com/craigd/lmsmaterial/app/DownloadService.java:458-465` — `File` construction using folder path
- `lms-material/src/main/java/com/craigd/lmsmaterial/app/MainActivity.java:920-928` — `download()` @JavascriptInterface entry point

---

## Finding 2: WebView URL-to-Intent Without Scheme Restriction

**Problem Summary**
`shouldOverrideUrlLoading` intercepts all URLs not matching internal constants (`SETTINGS_URL`, `QUIT_URL`, `STARTPLAYER_URL`) and creates an `Intent.ACTION_VIEW` for any URI passed in. There is no scheme whitelist. A malicious page loaded in the WebView (e.g., via XSS in the LMS web UI) could navigate to `tel://`, `sms://`, `intent://`, or `android-app://` URIs, causing the device to dial numbers, send SMS, or launch arbitrary installed applications.

```java
// MainActivity.java:675 — no scheme check before this line
Intent intent = new Intent(Intent.ACTION_VIEW, uri);
startActivity(intent);  // fires for any URI the WebView navigates to
```

**Potential Mitigation**
Whitelist accepted schemes before creating the intent:
```java
String scheme = uri.getScheme();
if (scheme == null || (!scheme.equals("http") && !scheme.equals("https"))) {
    return true; // block and ignore
}
```
Explicitly deny `intent://` and `android-app://` schemes regardless of whitelist logic.

**Relevant Files**
- `lms-material/src/main/java/com/craigd/lmsmaterial/app/MainActivity.java:644-698` — `shouldOverrideUrlLoading` full implementation

---

## Finding 3: No Origin Validation on JavaScript Bridge

**Problem Summary**
All `@JavascriptInterface` methods on the `NativeReceiver` bridge accept calls from any JavaScript executing in the WebView with no check against the expected LMS server origin. If the LMS web page contains an XSS vulnerability, an attacker could invoke bridge methods including:

- `download(String)` — triggers file downloads to external storage
- `controlLocalPlayerPower(String, String, int)` — sends broadcast intents to control local audio players
- `updateTextColor(String)` / `updateTheme(String)` — UI manipulation

No CSRF tokens, message signing, or origin checks are present on any exposed method.

```java
// MainActivity.java:577 — bridge registered with no domain restriction
webView.addJavascriptInterface(this, "NativeReceiver");

// Example exposed method — no origin check
@JavascriptInterface
public void download(String str) { ... }
```

**Potential Mitigation**
Before processing any bridge call, validate the WebView's current URL against the configured LMS server:
```java
@JavascriptInterface
public void download(String str) {
    if (!isTrustedOrigin(webView.getUrl())) return;
    doDownload(...);
}
```
Where `isTrustedOrigin()` compares host/port against the stored LMS server address from SharedPreferences.

**Relevant Files**
- `lms-material/src/main/java/com/craigd/lmsmaterial/app/MainActivity.java:577` — bridge registration
- `lms-material/src/main/java/com/craigd/lmsmaterial/app/MainActivity.java:774-928` — all `@JavascriptInterface` method implementations
