# Security Research Findings — Librera PDF Reader (com.foobnix.pro.pdf.reader v6978)

Four callsites analyzed (Intent-webview_new-89 through 92) across two separate bridge registrations. Callsites 89–90 expose `finish()` via `WebViewUtils$WebAppInterface` inside a PNG-rendering lambda (`renterToPng$1`). Callsites 91–92 expose `showToast(String)` via `SvgActivity$1WebAppInterface`, registered in `SvgActivity.onCreate()`.

The jsdetails table contains the actual JavaScript loaded by `SvgActivity`: an inline HTML snippet that imports MathJax from an external CDN (`https://cdnjs.cloudflare.com/...`) and calls `android.showToast("finish")` via a MathJax completion hook. This confirms the concrete attack surface for Finding 2.

All findings are PARTIAL. deepseek-r1 correctly assessed both bridge types as having limited directly exploitable paths from the Java interface alone (marked PARTIAL rather than VALID because the CDN dependency, visible only in jsdetails, adds a real external risk vector). gemma3 and phi4 covered the widest surface. qwen2.5 had zero hallucinations across all callsites.

---

## Finding 1: Arbitrary Activity Termination via `finish()`

**Verdict**: PARTIAL  
**Reported by**: phi4 (callsites 89–90, "Unrestricted Activity Termination" / "Unrestricted Bridge Method Access"), gemma3 (callsites 89–90, "Uncontrolled WebView Page Navigation/Closure via finish()"), qwen2.5 (callsite 90, "Method Invocation from JavaScript to Java"), llama3.2 (callsite 90, "finish() Method")

### Problem Summary

`WebViewUtils$WebAppInterface.finish()` is registered as the `android` bridge inside the `renterToPng$1` lambda, which sets up a WebView to render a PDF page as PNG using HTML/JS. Any JavaScript executing in that WebView can call `android.finish()` to terminate the host activity immediately.

```java
@JavascriptInterface
public void finish() {
    // Calls Activity.finish() or equivalent to close the rendering WebView
    activity.finish();
}
```

In the current implementation the rendering WebView likely loads trusted internal HTML, making exploitation low-probability. However, if the HTML loaded by `renterToPng` ever includes external resources (scripts, iframes) — or if the URL resolving mechanism is changed — malicious JavaScript gains a clean activity-kill primitive.

Data flow:
```
JS  android.finish()
  → WebViewUtils$WebAppInterface.finish()
    → host Activity.finish()   // closes the PDF rendering context
```

### Potential Mitigation

1. Verify the WebView loads only from trusted local origins (`file://` assets or `data:` URIs) before registering this bridge; add an origin check inside `finish()` if any external resources are loaded.
2. Consider replacing the bridge with a `WebViewClient.onPageFinished()` callback, eliminating the need for JS-initiated termination entirely.

### Relevant Files

- `app/src/main/java/com/foobnix/android/utils/WebViewUtils.java` — `WebAppInterface` inner class and `finish()` method; `renterToPng()` method that registers the bridge

---

## Finding 2: Toast Injection via External CDN Script in `SvgActivity`

**Verdict**: PARTIAL  
**Reported by**: gemma3 (callsites 91–92, "Toast Injection via showToast()"), qwen2.5 (callsite 91, "Toast Injection"), phi4 (callsite 92, "Lack of Origin Validation for WebView Content")

### Problem Summary

`SvgActivity` renders SVG and MathML content by injecting an HTML template into the WebView via `loadData`. The template includes a `<script>` tag that fetches MathJax 2.7.5 from the Cloudflare CDN over HTTPS, and a completion hook that calls the bridge:

```html
<script type="text/javascript"
    src="https://cdnjs.cloudflare.com/ajax/libs/mathjax/2.7.5/MathJax.js?config=MML_CHTML">
</script>
<script type="text/javascript">
  MathJax.Hub.Register.StartupHook("End", function () {
      android.showToast("finish");
  });
</script>
```

The registered bridge is:

```java
@JavascriptInterface
public void showToast(String message) {
    Toast.makeText(SvgActivity.this, message, Toast.LENGTH_SHORT).show();
}
```

Two attack paths exist:

1. **CDN supply-chain / MITM**: If the CDN delivers a tampered MathJax build, or if HTTPS is stripped on a network-level (relevant for Android pre-7.0 which does not enforce certificate transparency), the injected script can call `android.showToast("Your PDF is corrupted — tap to recover")` with arbitrary social-engineering content.

2. **Pinned CDN version**: The app pins MathJax 2.7.5. If a vulnerability in MathJax 2.7.5 allows script injection through the rendered math content itself, that injected code runs in the WebView context and can call the bridge.

Toast messages are non-persistent and visually benign in most scenarios, but they can be used for social engineering ("Security warning: re-enter your PDF password").

### Potential Mitigation

1. **Bundle MathJax locally**: Ship MathJax as a local asset and load it with `file:///android_asset/` rather than fetching from a CDN. This eliminates the external dependency entirely.
2. If the CDN dependency must remain, pin the `<script>` tag with a `crossorigin="anonymous"` Subresource Integrity hash: `integrity="sha384-<hash>"`. The `loadData` API does not enforce SRI automatically, but applying it in the HTML and enabling `WebSettings.setMixedContentMode(MIXED_CONTENT_NEVER_ALLOW)` reduces the CDN attack surface.
3. Restrict `showToast` message length and content (e.g., reject messages over 64 bytes or containing non-ASCII characters).

### Relevant Files

- `app/src/main/java/test/SvgActivity.java` — `WebAppInterface` inner class, `showToast()` bridge method, `loadData()` call with MathJax CDN HTML

### Links to github 
- https://github.com/foobnix/LibreraReader/blob/master/app/src/main/java/test/SvgActivity.java
-https://github.com/foobnix/LibreraReader/blob/master/app/src/main/java/com/foobnix/android/utils/WebViewUtils.java
