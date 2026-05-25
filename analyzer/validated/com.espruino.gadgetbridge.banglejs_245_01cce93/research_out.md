# Security Research Findings — Gadgetbridge BangleJS (com.espruino.gadgetbridge.banglejs v245)

All findings below are PARTIAL: real code paths confirmed, but exploitability requires either a compromised `banglejs.com` web page (XSS) or a malicious watch app sideloaded to the connected BangleJS device. The single analyzed callsite (73) covers `GBReqInt.onPostBody`; Findings 2–4 were researcher-identified from additional bridge inspection. qwen hallucinated SQL injection and intent-redirection via `onPostBody`; deepseek hallucinated five specific exploit paths (RCE, SQL, path traversal, intent redirection, reflection-based RCE) before identifying real concerns; gemma3 and phi4 produced zero hallucinations and correctly identified real concerns; starcoder2 and llama3.2 produced no output.

---

## Finding 1: Missing Origin Validation on `GBReqInt.onPostBody(String, String)`

**Problem Summary**
`GBReqInt` (`RequestInterceptorInterface`) exposes `onPostBody(String url, String body)` to JavaScript in `ExternalPebbleJSActivity`, `RebbleAppStoreActivity`, `PebbleJsService`, and `AppsManagementActivity`. It intercepts HTTP POST requests made from JavaScript apps (relayed via the WebView bridge) and passes the URL and request body to native code. No input validation or origin check is present at the bridge layer. Any JavaScript executing in the WebView — including via XSS — can invoke `onPostBody` with arbitrary URL and body strings that reach the HTTP processing stack unsanitized.

Data flow:
```
JS → GBReqInt.onPostBody(url, body)
  → RequestInterceptorInterface.onPostBody(String, String)
    → PebbleJsService processes the HTTP POST on behalf of the watch app
```

**Potential Mitigation**
Validate that `url` is within an expected scheme and host allowlist before processing. Add an origin check against `webView.getUrl()` to restrict calls to the expected device-app or app-store origin. Sanitize `body` before passing to any JSON parser or network layer.

**Relevant Files**
- `app/src/main/java/nodomain/freeyourgadget/gadgetbridge/webview/RequestInterceptorInterface.java` — `onPostBody()` bridge method
- `app/src/main/java/nodomain/freeyourgadget/gadgetbridge/service/devices/pebble/webview/PebbleJsService.java` — `startJsForDevice$lambda$0` registration context

---

## Finding 2: Arbitrary File Write via `Android.saveFile(String, String, String)`

**Problem Summary**
`AppsManagementActivity$WebViewInterface` exposes `saveFile(String filename, String content, String directory)` to JavaScript. The activity dynamically loads `https://banglejs.com/apps/android.html`. Any JavaScript from that page — or injected via XSS — can call `Android.saveFile(filename, content, directory)` with attacker-controlled strings. If `filename` contains path traversal sequences and the implementation constructs a `File` directly from the provided string, an attacker can write arbitrary content outside the intended download directory, including writing files to external storage.

Data flow:
```
XSS in banglejs.com/apps/android.html
  → JS: Android.saveFile("../../Download/evil.apk", "<payload>", "external")
    → AppsManagementActivity$WebViewInterface.saveFile(String, String, String)
      → File write to attacker-controlled path
```

**Potential Mitigation**
Strip path separators from `filename` using `filename = new File(filename).getName()`. Verify the canonical path stays within the intended download directory before writing. Apply origin validation: only accept `saveFile` calls when `webView.getUrl()` is `https://banglejs.com/apps/android.html`.

**Relevant Files**
- `app/src/main/java/nodomain/freeyourgadget/gadgetbridge/devices/banglejs/AppsManagementActivity.java` — `WebViewInterface.saveFile()` bridge method

---

## Finding 3: Arbitrary Watch Command Injection via `Android.bangleTx(String)`

**Problem Summary**
`AppsManagementActivity$WebViewInterface` exposes `bangleTx(String message)`, which transmits a raw string to the connected BangleJS watch over Bluetooth. The app store page uses this to install apps. An XSS in `banglejs.com/apps/android.html` allows `Android.bangleTx(maliciousJS)` calls that execute arbitrary JavaScript on the connected watch, bypassing any watch-side app review.

```java
@JavascriptInterface
public void bangleTx(String message) {
    // Sends message directly to BangleJS watch via Bluetooth TX
}
```

**Potential Mitigation**
Enforce a JSON schema for allowed `bangleTx` message types and reject freeform JS code strings. Apply origin validation before transmitting any `bangleTx` call. Require explicit user confirmation before write operations are sent to the watch.

**Relevant Files**
- `app/src/main/java/nodomain/freeyourgadget/gadgetbridge/devices/banglejs/AppsManagementActivity.java` — `WebViewInterface.bangleTx()` bridge method ([GitHub](https://github.com/Freeyourgadget/Gadgetbridge/blob/master/app/src/main/java/nodomain/freeyourgadget/gadgetbridge/devices/banglejs/AppsManagementActivity.java))

---

## Finding 4: Sensitive Token and Location Exposure via `GBjs` Bridge

**Problem Summary**
The `GBjs` bridge (`JSInterface`) in `ExternalPebbleJSActivity` and `PebbleJsService` exposes methods that return sensitive data to JavaScript: `getAccountToken()`, `getWatchToken()`, `getCurrentPosition()`, and `getAppConfigurationFile()`. Any malicious or compromised JavaScript app sideloaded to the watch can call these methods and exfiltrate the user's authentication tokens and GPS location. No authentication or per-session permission prompt guards these methods.

**Potential Mitigation**
Validate that JS apps are signed by a trusted source before granting token access. Require explicit user permission each session before `getCurrentPosition()` returns a value. Do not expose raw tokens; return limited-validity signed responses instead.

**Relevant Files**
- `app/src/main/java/nodomain/freeyourgadget/gadgetbridge/service/devices/pebble/webview/JSInterface.java` — `getAccountToken()`, `getWatchToken()`, `getCurrentPosition()`, `getAppConfigurationFile()` bridge methods
- `app/src/main/java/nodomain/freeyourgadget/gadgetbridge/activities/ExternalPebbleJSActivity.java` — bridge registration
