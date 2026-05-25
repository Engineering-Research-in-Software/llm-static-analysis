# `setNativeToJsBridgeMode` Exposed as JavaScript Interface

## Detection note

This issue was identified through automated LLM-based static analysis of WebView `addJavascriptInterface` bridges, as part of academic security research at the University of Southern Denmark (SDU) in the context of a masters level course named Engineering in Research.

The finding was manually reviewed before submission.

To aid the purposes of our research, we would kindly request acknowledgement of the reported issue as well as a final verdict from the open source community working on this repository, even if the issue is not acted on.

We are reporting in good faith and are happy to answer questions.

## Summary

The Cordova framework exposes `setNativeToJsBridgeMode(int, int)` as a `@JavascriptInterface` method, allowing JavaScript to control how native-to-JavaScript message delivery works (polling mode vs. online/push mode). Exposing this internal communication control to arbitrary JavaScript unnecessarily broadens the bridge attack surface. In YAM's current configuration (localhost-only content) practical risk is low, but the exposure warrants tracking.

**Severity:** Low
**Affected version(s):** v11 (latest at time of analysis)

---

## Affected file(s)

- Cordova engine class `org.apache.cordova.engine.b` — compiled from `@capacitor/android` dependency (not available in source tree)

---

## Vulnerable code

```java
// setNativeToJsBridgeMode is a @JavascriptInterface in the Cordova engine.
// No app-level source available — present in compiled bytecode of @capacitor/android.
@JavascriptInterface
public void setNativeToJsBridgeMode(int bridgeMode, int ...) {
    // Controls whether bridge uses polling or push mode for native→JS messages
}
```

---

## Proof of concept

```js
// Switch native bridge to polling mode (degrades communication performance):
_cordovaNative.setNativeToJsBridgeMode(0, 0);
```

---

## Impact

A page with bridge access (see related origin validation finding) could degrade native-to-JavaScript communication by switching the bridge mode, potentially disrupting app functionality. In the current localhost-only configuration, practical impact is low. No data exfiltration or privilege escalation is possible through this method alone.

---

## Suggested mitigation

This is a Cordova framework method in a compiled dependency — no app-level fix is possible without patching or replacing the Cordova engine. Recommended actions:

1. Track the upstream `@capacitor/android` dependency for security patches addressing bridge surface exposure.
2. Prevent external content from reaching the bridge (see related findings on origin validation and wildcard access origin) — this is the most practical mitigation available at the app level.
