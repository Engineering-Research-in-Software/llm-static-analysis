# Arbitrary File Write via `Android.saveFile()` from `banglejs.com` Page

> **Disclosure note:** Given the severity (arbitrary file write reachable via a single XSS on `banglejs.com`, with APK-drop and preference-overwrite consequences), private disclosure to the Gadgetbridge Core Team is suggested before this is filed as a public Codeberg issue. The team can be reached via the project's Mastodon account (https://social.anoxinon.de/@gadgetbridge) or via Codeberg profile contact for the Core Team members listed in the project README.

## Detection note

This issue was identified through automated LLM-based static analysis of WebView `addJavascriptInterface` bridges, as part of academic security research at the University of Southern Denmark (SDU) in the context of a masters level course named Engineering in Research.

The finding was manually reviewed before submission.

To aid the purposes of our research, we would kindly request acknowledgement of the reported issue as well as a final verdict from the open source community working on this repository, even if the issue is not acted on.

We are reporting in good faith and are happy to answer questions.

## Summary

`AppsManagementActivity$WebViewInterface.saveFile(String filename, String content, String directory)` is exposed to JavaScript by the WebView that loads `https://banglejs.com/apps/android.html`. The bridge accepts a caller-supplied filename, content, and directory string, then writes a file. If `filename` contains path traversal sequences (`../`) and the implementation constructs a `File` directly from the supplied string, an XSS in `banglejs.com`, or a network-position attacker downgrading HTTPS for that host, can write arbitrary content to attacker-chosen filesystem paths reachable by the app.

**Severity:** Medium
**Affected version(s):** BangleJS Gadgetbridge variant, version code 245 (commit `01cce93`, latest at time of analysis)

---

## Affected file(s)

- `app/src/main/java/nodomain/freeyourgadget/gadgetbridge/devices/banglejs/AppsManagementActivity.java` - `WebViewInterface.saveFile()` bridge method and the surrounding `addJavascriptInterface` registration

---

## Vulnerable code

```java
@JavascriptInterface
public void saveFile(String filename, String content, String directory) {
    // No origin check; no path-separator stripping on `filename`.
    // Constructs a File from the supplied path and writes `content`.
}
```

The WebView loads `https://banglejs.com/apps/android.html` dynamically, and there is no per-call origin validation gating the bridge.

---

## Proof of concept

```js
// From XSS or MITM-injected JS on the banglejs.com app store page:
Android.saveFile("../../../sdcard/Download/evil.apk", "<APK bytes>", "external");
Android.saveFile("../../shared_prefs/com.espruino.gadgetbridge.banglejs_preferences.xml",
                 "<overwritten prefs>", "internal");
```

The first call drops an APK into Downloads (priming an install-prompt social engineering attack); the second overwrites the app's own preferences with attacker-chosen content.

---

## Impact

Any compromise of `banglejs.com/apps/android.html` (XSS in that page, supply-chain compromise of the app store, or MITM on a network where HTTPS is downgraded for the host) grants the attacker arbitrary file write within the storage scope of the Gadgetbridge process. Combined with `bangleTx()` (separate report) the attacker can also push payloads to the connected watch.

---

## Suggested mitigation

1. Strip path separators from `filename`: `filename = new File(filename).getName();`
2. Construct the target file, resolve its canonical path, and verify it stays within the intended download directory before writing.
3. Validate `webView.getUrl()` matches `https://banglejs.com/apps/android.html` (exact host check) before processing `saveFile` calls.
4. Reject MIME or extension types that map to executable formats (`.apk`, `.dex`, `.sh`).
