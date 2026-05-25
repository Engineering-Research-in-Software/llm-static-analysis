# Security Research Findings — Gh4a / Octodroid (com.gh4a v78)

Eight callsites analyzed (Intent-webview_new-95 through 102) across `WebViewerActivity` and `MarkdownPreviewWebView`, using three distinct bridge types. The app is an open-source GitHub client that renders repository content (README, code, blame, diffs) by calling `loadDataWithBaseURL(file:///android_asset/, generateHtml(), ...)` — i.e., dynamically-generated HTML from GitHub API responses, loaded with a `file://` base URL. No JavaScript snippets were available to inspectors.

All findings below are PARTIAL: bridge method signatures are confirmed and the open-source codebase (github.com/slapperwan/gh4a) corroborates the data flows. Exploitability depends on whether a malicious GitHub repository's content can reach the bridge parameters — which is plausible given that `generateHtml()` processes attacker-controlled repo content. qwen2.5 ran away on callsite 102 (314 INVALID findings); starcoder2 hallucinated 100% across 3 findings. phi4 and gemma3 covered the widest real attack surface.

---

## Finding 1: Script URL Injection via `rewriteRelativeUrls(String, String, String, String, String)`

**Verdict**: PARTIAL  
**Reported by**: gemma3 (callsites 96–97, "Uncontrolled URL Rewrite", "Potential Script Inclusion Vulnerability", "rewriteRelativeUrls XSS via Unvalidated Input"), phi4 (callsite 96, "Potential URL Manipulation Vulnerability"), llama3.2 (callsites 96–97, "Unvalidated URL Handling", "Missing Input Validation for rewriteRelativeUrls")

### Problem Summary

`HtmlUtilsJavascriptInterface.rewriteRelativeUrls(baseUrl, basePath, relativePath, targetUrl, scriptUrl)` is exposed to JavaScript and rewrites relative URLs in HTML content displayed by the WebView. The five parameters include a `scriptUrl` argument that is used to inject a `<script>` tag into the rendered output.

The typical implementation pattern:

```java
@JavascriptInterface
public String rewriteRelativeUrls(String baseUrl, String basePath,
        String relativePath, String targetUrl, String scriptUrl) {
    // Rewrites <img src="relative"> to absolute, etc.
    // Also injects: <script src="scriptUrl"></script>
    return processedHtml;
}
```

Since `WebViewerActivity` renders content from GitHub repositories via `generateHtml()`, a repository owner who controls the README or source files can craft content such that one of the five parameters passed to `rewriteRelativeUrls` contains an attacker-controlled script URL. The returned string is then re-injected into the WebView DOM.

Data flow:
```
GitHub content → generateHtml() → WebView loadDataWithBaseURL(file:///android_asset/)
  JS  HtmlUtils.rewriteRelativeUrls(b1, b2, rel, target, scriptUrl)
    → Java rewrites URLs including injecting <script src=scriptUrl>
    → returned HTML injected back into DOM
```

### Potential Mitigation

1. Validate each of the five string parameters against an expected URL pattern (scheme + allowed hosts) before constructing `<script>` or `<img>` tags.
2. Enforce a strict `Content-Security-Policy` in the loaded HTML that disallows external `<script>` sources not on an allowlist.
3. If `scriptUrl` must be dynamic, restrict it to `file:///android_asset/` origins only.

### Relevant Files

- `app/src/main/java/com/gh4a/activities/WebViewerActivity.java` — `HtmlUtilsJavascriptInterface` inner class; `rewriteRelativeUrls()` and `addCommonJavascriptInterfaces()` call
- `app/src/main/java/com/gh4a/utils/HtmlUtils.java` — URL-rewriting logic

---

## Finding 2: Base64-Obfuscated Content Injection via `decode(String)`

**Verdict**: PARTIAL  
**Reported by**: gemma3 (callsites 95, 102, "Base64.decode() - Potential for Arbitrary Data Interpretation", "Potential XSS via Malformed Base64"), phi4 (callsite 102, "Potential JavaScript Injection via Base64 Decoding"), qwen2.5 (callsite 102, "Lack of Origin Validation")

### Problem Summary

`Base64JavascriptInterface.decode(String encodedString)` accepts a base64-encoded string from JavaScript, decodes it in Java, and returns the plaintext string to the WebView. This round-trip creates a bypass path for HTML/JS sanitization: a sanitizer that strips `<script>` tags from raw HTML content cannot block a payload that arrives base64-encoded and is decoded just before DOM injection.

```java
@JavascriptInterface
public String decode(String base64) {
    return new String(android.util.Base64.decode(base64, android.util.Base64.DEFAULT));
}
```

If the caller does `document.body.innerHTML += Base64.decode(attackerBase64)`, and the decoded string contains `<script>` or `<img onerror=...>` payloads, XSS executes inside the `file:///android_asset/` origin. On Android pre-4.4 this `file://` origin can read arbitrary local files; on modern Android it is sandboxed to assets.

The attack is realistic in Gh4a's context because repository `README.md` files or source code comments are rendered in the WebView — a malicious repo owner can include base64-encoded payloads in their content.

### Potential Mitigation

1. After decoding, run the output through an HTML sanitizer (e.g., Android's `Html.fromHtml()` in escaping mode, or a dedicated library) before returning it to JavaScript.
2. Restrict use of `decode()` to known-safe contexts; remove the bridge if JavaScript-side decoding (`atob()`) suffices.

### Relevant Files

- `app/src/main/java/com/gh4a/activities/WebViewerActivity.java` — `Base64JavascriptInterface` inner class (callsites 95)
- `app/src/main/java/com/gh4a/widget/MarkdownPreviewWebView.java` — second `Base64JavascriptInterface` registration (callsite 102)

---

## Finding 3: Unvalidated Integer Dispatch via `onLineTouched(int)` → Intent Creation

**Verdict**: PARTIAL  
**Reported by**: deepseek-r1 (callsite 101, "Intent Redirection via onLineTouched()"), gemma3 (callsites 98, 100, "Untrusted Data in onLineTouched Parameter", "Uncontrolled Input to onLineTouched"), phi4 (callsite 101, "Potential Arbitrary Input Vulnerability"), llama3.2 (callsite 100, "Intent Creation Vulnerability")

### Problem Summary

`NativeClientJavascriptInterface.onLineTouched(int lineNumber)` is called from JavaScript when the user taps a line number in a blame or code view. The implementation creates an Android intent to navigate to a specific commit or diff for that line — the `lineNumber` integer drives the intent construction.

```java
@JavascriptInterface
public void onLineTouched(int line) {
    // Constructs an Intent to open blame/commit for 'line'
    Intent intent = CommitActivity.makeIntent(context, sha, path, line);
    startActivity(intent);
}
```

If JavaScript can call `NativeClient.onLineTouched(line)` with an arbitrary integer (e.g., a negative value, `Integer.MAX_VALUE`, or a value that indexes into an array out of bounds), the intent construction or the downstream activity may behave unexpectedly — ranging from crashes to navigating to unintended content entries.

### Potential Mitigation

1. Validate `lineNumber` is within `[1, totalLines]` before constructing the intent.
2. If `onLineTouched` must accept arbitrary integers, ensure all downstream array accesses use bounds-checked APIs.

### Relevant Files

- `app/src/main/java/com/gh4a/activities/WebViewerActivity.java` — `NativeClientJavascriptInterface` inner class; `onLineTouched()` implementation

---

## Finding 4: Forced Print Trigger via `onRenderingDone()` → `doPrint()`

**Verdict**: PARTIAL (low severity)  
**Reported by**: gemma3 (callsite 100, "`onRenderingDone` and `doPrint` - Potential for Code Execution through indirect call")

### Problem Summary

In some `NativeClient` implementations in `WebViewerActivity`, `onRenderingDone()` calls an internal `doPrint()` method that invokes the Android print framework. Any JavaScript in the WebView can call `NativeClient.onRenderingDone()` to silently trigger the system print dialog, bypassing user intent.

```java
@JavascriptInterface
public void onRenderingDone() {
    doPrint();   // triggers PrintManager
}
```

The impact is limited (user still controls the print dialog), but the call can be used to disrupt the rendering lifecycle or as a social-engineering mechanism (surprise print dialog when viewing a file).

### Potential Mitigation

Gate `doPrint()` on an internal boolean flag that is set only via the expected UI flow, and do not expose the flag-setting path through the JavaScript bridge.

### Relevant Files

- `app/src/main/java/com/gh4a/activities/WebViewerActivity.java` — `NativeClientJavascriptInterface.onRenderingDone()` and `doPrint()` methods


### Links 
- https://github.com/slapperwan/gh4a/blob/master/app/src/main/java/com/gh4a/activities/WebViewerActivity.java