# Security Research Findings — FadCam (com.fadcam v31)

Two callsites analyzed (Intent-webview_new-80 and 81), both in `WhatsNewActivity`, both exposing the same single-method `ProgressBridge` (obfuscated class `Lox1;`). No JavaScript snippets were available to inspectors.

This bridge has **minimal security risk**. The only exposed method is `updateProgress(int)`, which updates a progress indicator in what is evidently a "What's New" / changelog WebView screen. deepseek-r1 and llama3.2 correctly identified no meaningful vulnerabilities across both callsites (though marked PARTIAL rather than VALID by the researcher, reflecting residual uncertainty about the downstream int usage). llama3.2 nonetheless hallucinated 10 specific attack paths.

---

## Finding 1: Uncontrolled Integer Input to `updateProgress(int)`

**Verdict**: PARTIAL (low severity)  
**Reported by**: qwen2.5 (callsite 80, "updateProgress Method Invocation"), phi4 (callsite 80, "Potential JavaScript Interface Abuse"), gemma3 (callsites 80–81, "Uncontrolled Progress Update")

### Problem Summary

The `ProgressBridge` interface exposes a single method, `updateProgress(int progress)`, to JavaScript via the `WhatsNewActivity` WebView. Any JavaScript running in that WebView can call `ProgressBridge.updateProgress(n)` with an arbitrary integer. The typical implementation updates a progress bar or loading spinner:

```java
@JavascriptInterface
public void updateProgress(int progress) {
    // e.g. progressBar.setProgress(progress);  OR  runOnUiThread(...)
}
```

The concrete risk is low because:
- The WebView in `WhatsNewActivity` loads internal/changelog content, not arbitrary external URLs.
- `updateProgress(int)` has no file system, database, network, or intent side effects.
- The worst realistic outcome is a garbled progress bar or, if the value is used as an array index without bounds checking, a silent `ArrayIndexOutOfBoundsException`.

The finding is PARTIAL rather than INVALID because without the implementation it cannot be fully ruled out that the int is used downstream in a way with broader impact (e.g., as a percentage multiplied into a delay, or passed to a native function).

### Potential Mitigation

1. Clamp the incoming integer to the valid range before use: `progress = Math.max(0, Math.min(100, progress));`
2. If the WebView loads any external content, add an origin check before processing the call.

### Relevant Files

- `app/src/main/java/com/fadcam/ui/WhatsNewActivity.java` — `ProgressBridge` inner class and `addJavascriptInterface` call

### Link to github 
- https://github.com/anonfaded/FadCam/blob/master/app/src/main/java/com/fadcam/ui/WhatsNewActivity.java#L1351 

### The issues has been fixed. 