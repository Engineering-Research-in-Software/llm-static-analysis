# Security Research Findings — DeepLViewer (com.example.deeplviewer v46)

Four callsites analyzed (Intent-webview_new-74 through 77), all sharing the same `WebAppInterface` bridge registered as `Android` across `FloatingTextSelection` and `MainActivity`. No JavaScript snippets were available to inspectors; all models reasoned from interface signatures alone.

All findings below are PARTIAL: the attack surface is confirmed at the interface level but full exploitability depends on the unreviewed `WebAppInterface` implementation and the origin of JavaScript executing in the WebView. qwen2.5-coder and llama3.2 both entered a runaway hallucination loop on callsite 74 (424 and 549 findings respectively, >99% INVALID); their effective output was limited to one real concern each across all four callsites. phi4, gemma3, and deepseek-r1 performed consistently across callsites.

---

## Finding 1: Uncontrolled Clipboard Write via `copyClipboard(String)`

**Verdict**: PARTIAL  
**Reported by**: deepseek-r1 (callsite 74, "Clipboard Data Leakage"; callsite 75, "Clipboard Hijacking"; callsite 77, "Clipboard Data Exposure"), phi4 (callsite 74, "Potential Data Exfiltration via Clipboard"; callsite 75, "Potential Phishing via copyClipboard"; callsite 76, "Unauthorized Clipboard Manipulation"; callsite 77, "Clipboard Manipulation Vulnerability"), gemma3 (all four callsites, "Uncontrolled Clipboard Access")

### Problem Summary

The `copyClipboard` method is exposed to JavaScript as part of the `Android` bridge and accepts an arbitrary caller-controlled string. The method's sole purpose is to write that string to the system clipboard via `ClipboardManager`. The typical implementation is:

```java
@JavascriptInterface
public void copyClipboard(String text) {
    ClipboardManager clipboard = (ClipboardManager)
        context.getSystemService(Context.CLIPBOARD_SERVICE);
    ClipData clip = ClipData.newPlainText("label", text);
    clipboard.setPrimaryClip(clip);
}
```

Any JavaScript executing in the WebView — whether served by DeepL's legitimate page or injected via XSS — can silently overwrite the user's clipboard with arbitrary content. The app loads DeepL at `deepl.com` and also loads a local config asset; if the app navigates away from DeepL or if DeepL's CDN serves compromised content, the bridge is still active.

Practical impacts: clipboard replacement with malicious URLs or payment addresses (address substitution attacks), poisoning copy-paste workflows for users translating sensitive text, overwriting clipboard contents the user expects to keep.

Data flow:
```
JS  Android.copyClipboard(attackerString)
  → WebAppInterface.copyClipboard(String)
    → ClipboardManager.setPrimaryClip(ClipData.newPlainText(..., attackerString))
```

### Potential Mitigation

1. Validate that calls originate from the expected DeepL origin before writing to the clipboard (see Finding 3).
2. Optionally, display a toast or subtle UI indicator whenever the clipboard is written by the bridge, so the user is aware of the write.

### Relevant Files

- `app/src/main/java/com/example/deeplviewer/webview/WebAppInterface.java` — `copyClipboard()` bridge method
- `app/src/main/java/com/example/deeplviewer/activity/FloatingTextSelection.java` — bridge registration for floating overlay context
- `app/src/main/java/com/example/deeplviewer/activity/MainActivity.java` — bridge registration for main activity

### Link to github
- https://github.com/sakusaku3939/DeepLAndroid/blob/master/app/src/main/java/com/example/deeplviewer/webview/WebAppInterface.kt
---

## Finding 2: Potential Sensitive Asset Exposure via `getAssetsText(String)`

**Verdict**: PARTIAL  
**Reported by**: deepseek-r1 (callsite 74, "Asset File Exposure"; callsite 75, "Path Traversal in getAssetsText"; callsite 77, "Path Traversal via Asset Access"), phi4 (callsite 74, "Asset Path Traversal Vulnerability"; callsite 75, "Directory Traversal via getAssetsText"; callsite 76, "Potential Path Traversal via getAssetsText"; callsite 77, "Asset Path Disclosure Vulnerability"), gemma3 (callsites 74–77, "Potential Path Traversal / Asset File Disclosure")

### Problem Summary

The `getAssetsText` method accepts a caller-controlled filename and returns the content of the corresponding file from the app's assets directory. The typical implementation is:

```java
@JavascriptInterface
public String getAssetsText(String filename) {
    try {
        InputStream is = context.getAssets().open(filename);
        BufferedReader reader = new BufferedReader(new InputStreamReader(is));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) sb.append(line).append("\n");
        return sb.toString();
    } catch (IOException e) { return ""; }
}
```

Android's `AssetManager.open()` is scoped to the app's bundled assets and does not follow `../` traversal to other filesystem locations. However, the attack surface is real in two ways:

1. **Internal asset enumeration**: JavaScript can iterate through known or guessed asset filenames — HTML templates, JavaScript files, and configuration assets — to read their full contents. If any bundled asset contains an API key, hardcoded credential, or internal URL scheme, it is exposed to any JavaScript executing in the WebView.
2. **Config file leakage**: The `FloatingTextSelection` activity loads a URL containing `config` as part of the path (observed in the jsdetails table: `PASS_STRING = "...config"`), suggesting a local config asset drives part of the WebView setup. If this file contains app secrets it can be read back via `getAssetsText("config.js")` or similar.

Note: path traversal beyond the assets root (`AssetManager` boundary) is not possible on standard Android, so the INVALID "path traversal to arbitrary filesystem files" findings from deepseek and phi4 were correctly rejected. The real concern is within-assets disclosure.

### Potential Mitigation

1. Maintain an explicit allowlist of asset filenames that the bridge is permitted to serve (e.g., only the HTML/JS files the WebView itself needs). Reject any filename not on the list.
2. Move sensitive configuration (API keys, auth tokens) out of bundled assets and into Android Keystore or encrypted SharedPreferences; never expose them via a JavaScript-readable bridge.
3. Apply origin validation before serving any asset content (see Finding 3).

### Relevant Files

- `app/src/main/java/com/example/deeplviewer/webview/WebAppInterface.java` — `getAssetsText()` bridge method
- `app/src/main/assets/` — asset directory whose contents are exposed to the WebView

---

## Finding 3: No Origin Validation on the `Android` Bridge

**Verdict**: PARTIAL  
**Reported by**: gemma3 (callsites 76 and 77, "Lack of Origin Validation"), llama3.2 (callsite 74, "No Origin Validation")

### Problem Summary

The `Android` JavaScript interface is registered without any runtime origin check. Both `copyClipboard` and `getAssetsText` will execute for any JavaScript in the WebView, including scripts loaded from third-party domains, iframes embedded in the DeepL page, or content injected via XSS. The `FloatingTextSelection` activity accepts arbitrary text via `android.intent.extra.TEXT` / `PROCESS_TEXT` intents — if that text is used as a URL parameter without encoding, an attacker could manipulate the WebView's navigation and then call bridge methods.

```java
// Typical registration — no domain restriction
webView.addJavascriptInterface(new WebAppInterface(this), "Android");
```

### Potential Mitigation

Validate the WebView's current URL against an allowlist of expected origins before processing any bridge call:

```java
@JavascriptInterface
public void copyClipboard(String text) {
    if (!isTrustedOrigin()) return;
    // proceed
}

private boolean isTrustedOrigin() {
    String url = webView.getUrl();
    if (url == null) return false;
    Uri uri = Uri.parse(url);
    String host = uri.getHost();
    return host != null && (host.equals("www.deepl.com") || host.endsWith(".deepl.com"));
}
```

### Relevant Files

- `app/src/main/java/com/example/deeplviewer/webview/WebAppInterface.java` — all bridge methods
- `app/src/main/java/com/example/deeplviewer/activity/FloatingTextSelection.java` — bridge registration and WebView setup
- `app/src/main/java/com/example/deeplviewer/activity/MainActivity.java` — bridge registration and WebView setup

### Link to github 
- https://github.com/sakusaku3939/DeepLAndroid/blob/master/app/src/main/java/com/example/deeplviewer/activity/FloatingTextSelection.kt