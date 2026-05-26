# Arbitrary Watch Code Injection via `Android.bangleTx()` from `banglejs.com` Page

> **Disclosure note:** Given the severity (remote code execution on the paired watch via a single XSS on `banglejs.com`), private disclosure to the Gadgetbridge Core Team is suggested before this is filed as a public Codeberg issue. The team can be reached via the project's Mastodon account (https://social.anoxinon.de/@gadgetbridge) or via Codeberg profile contact for the Core Team members listed in the project README.

## Detection note

This issue was identified through automated LLM-based static analysis of WebView `addJavascriptInterface` bridges, as part of academic security research at the University of Southern Denmark (SDU) in the context of a masters level course named Engineering in Research.

The finding was manually reviewed before submission.

To aid the purposes of our research, we would kindly request acknowledgement of the reported issue as well as a final verdict from the open source community working on this repository, even if the issue is not acted on.

We are reporting in good faith and are happy to answer questions.

## Summary

`AppsManagementActivity$WebViewInterface.bangleTx(String message)` is exposed to JavaScript by the WebView loading `https://banglejs.com/apps/android.html`, and forwards `message` directly to the connected BangleJS watch over Bluetooth UART. Because BangleJS interprets data received over UART as Espruino JavaScript by default, any XSS in `banglejs.com`, or successful MITM on the HTTPS connection, lets the attacker execute arbitrary JavaScript on the user's watch, bypassing any watch-side app review.

**Severity:** High
**Affected version(s):** BangleJS Gadgetbridge variant, version code 245 (commit `01cce93`)

---

## Affected file(s)

- `app/src/main/java/nodomain/freeyourgadget/gadgetbridge/devices/banglejs/AppsManagementActivity.java` - `WebViewInterface.bangleTx()` bridge method

---

## Vulnerable code

```java
@JavascriptInterface
public void bangleTx(String message) {
    // Sends `message` directly to the connected BangleJS watch via Bluetooth TX.
    // No origin check; no message-type schema enforcement.
}
```

---

## Proof of concept

```js
// From XSS in banglejs.com/apps/android.html (the page loaded by the WebView)
// or from JS injected via HTTPS downgrade:
Android.bangleTx("\x10E.showMessage('hacked'); reset()\n");
// More damaging:
Android.bangleTx("\x10require('Storage').erase('+'*');\n");
// Watch-side: erases storage; subsequent commands can install arbitrary watch apps.
```

`\x10` (Ctrl-P) is BangleJS's "echo off" prefix and `\n` terminates the line, causing the watch's REPL to execute the JS body silently.

---

## Impact

An attacker with control over any JavaScript loaded into the WebView (a single XSS on the `banglejs.com` app store, a supply-chain compromise of an app listing, or HTTPS interception on a hostile network) can execute arbitrary code on the connected watch with no user prompt. Consequences include wiping watch storage, installing malicious watch apps, exfiltrating sensor data, or persistently bricking the watch.

---

## Suggested mitigation

1. Enforce a JSON schema for permitted `bangleTx` messages and reject anything that does not match an expected install or upload command. Reject free-form JS payloads outright.
2. Validate `webView.getUrl()` matches `https://banglejs.com/apps/android.html` (exact host check) before forwarding any byte to the watch.
3. For write operations to the watch, require explicit user confirmation (the watch's "Allow upload?" prompt), never auto-accept.
4. Apply Subresource Integrity or Content-Security-Policy hardening to the loaded HTML so a CDN compromise on `banglejs.com` cannot inject script.
