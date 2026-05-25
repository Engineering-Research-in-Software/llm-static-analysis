# Security Research Findings — Paynoway (com.github.samotari.paynoway v20100)

Three callsites analyzed (Intent-webview_new-106 through 108). Callsite 106 is the standard Cordova `_cordovaNative` bridge. Callsites 107 and 108 are the Apache Cordova InAppBrowser plugin's `postMessage(String)` bridge, registered without a name (107) and as `cordova_iab` (108) in `InAppBrowser$7$1JsObject`. The jsdetails table confirms the app loads a URL from a static field (`val$url`) into the InAppBrowser — consistent with opening a remote payment page. Paynoway is an open-source Bitcoin/Lightning Network payment app (github.com/samotari/paynoway).

All findings are PARTIAL. The `_cordovaNative` concerns are structurally identical to other Cordova apps in this dataset. The `postMessage` findings carry uniquely elevated severity in a payment context: models correctly converged on origin-validation absence as the key concern (gemma3, phi4, qwen2.5, llama3.2 all found PARTIAL evidence). deepseek hallucinated five specific attack paths across three callsites and correctly classified the remainder as "no direct exploit visible from signatures alone."

---

## Finding 1: Unauthenticated `InAppBrowser.postMessage` Enables Forged Payment Confirmations

**Verdict**: PARTIAL  
**Reported by**: gemma3 (callsites 107–108, "InAppBrowser postMessage Vulnerability", "Arbitrary Message Injection", "Lack of Origin Validation", "Potential for Arbitrary Java Code Execution"), phi4 (callsite 108, "Insecure PostMessage Usage", "Lacks Origin Validation"), qwen2.5 (callsites 107–108, "Lack of Origin Validation", "Insecure Data Flow via postMessage"), llama3.2 (callsite 107, "Insecure Post Message Method")

### Problem Summary

Paynoway opens Lightning Network payment pages in an InAppBrowser window. When payment is confirmed, the payment page JavaScript calls the `cordova_iab.postMessage(jsonPayload)` bridge to signal success back to the app. The bridge method on the Java side dispatches the message to the Cordova plugin's event pipeline — ultimately informing the app whether a transaction was paid.

```java
// InAppBrowser$7$1JsObject — registered as "cordova_iab"
@JavascriptInterface
public void postMessage(String message) {
    // Dispatches to InAppBrowser plugin's message handling
    // No check on which URL sent this message
}
```

Because there is no `message.origin` check — and because Android's `@JavascriptInterface` mechanism provides no origin restriction at the API level — any website loaded in the InAppBrowser window can call `cordova_iab.postMessage(...)` with arbitrary content. A malicious payment page can forge a payment confirmation:

```js
// Attacker-controlled payment page, no actual Lightning payment made:
cordova_iab.postMessage(JSON.stringify({
    status: 'paid',
    preimage: 'aaabbbcccdddeeefff...',  // forged payment preimage
    paymentHash: '...'
}));
```

If Paynoway's message handler does not cryptographically verify the payment preimage against the expected payment hash, it will treat this as a successful payment. An attacker serving a page at a URL that looks like a legitimate Lightning service provider can thus defraud the app.

Data flow:
```
User pays via InAppBrowser → malicious page skips actual Lightning payment
  JS  cordova_iab.postMessage('{"status":"paid","preimage":"..."}')
    → InAppBrowser$7$1JsObject.postMessage(String)
      → Cordova event bus → Paynoway JS handler
        → App records payment as successful (if preimage not verified)
```

### Potential Mitigation

1. **Cryptographic preimage verification**: When receiving a payment confirmation via `postMessage`, independently verify that the received payment preimage hashes to the expected payment hash (`sha256(preimage) == paymentHash`). This is the Lightning Network's built-in proof-of-payment — checking it in the app makes forged confirmations impossible regardless of the origin.
2. **Origin validation**: Restrict which URLs are trusted to send `postMessage` confirmations. Maintain a server-side allowlist of trusted payment-provider domains and check `webView.getUrl()` before processing any confirmation message.
3. **Out-of-band verification**: After receiving a `postMessage` confirmation, verify the payment status directly against the Lightning node or LNURL endpoint before granting any service — do not trust the InAppBrowser page's self-report.

### Relevant Files

- `node_modules/cordova-plugin-inappbrowser/src/android/InAppBrowser.java` — `InAppBrowser$7$1JsObject.postMessage()` implementation (plugin-provided)
- App-side payment handler (Dart/JS) — the code that processes `postMessage` events from `cordova_iab` and decides whether payment succeeded

---

## Finding 2: Unrestricted Plugin Dispatch via Cordova `exec()` and Missing Origin Validation

**Verdict**: PARTIAL  
**Reported by**: phi4 (callsite 106, "Insecure Bridge Method Invocation", "Lack of Origin Validation"), gemma3 (callsite 106, "Potential Message Origin Exploitation with retrieveJsMessages()", "Lack of Origin Validation on Message Passing")

### Problem Summary

Callsite 106 is the standard Cordova `_cordovaNative` bridge. As with all Cordova apps in this dataset, `exec(int, String, String, String, String)` routes to any registered plugin without an origin allowlist at the Java layer, and `setNativeToJsBridgeMode(int, int)` can disrupt native-to-JS message delivery.

For a payment app the `exec()` surface is especially sensitive: Paynoway likely registers plugins for LNURL fetching, QR code scanning, secure key storage, or clipboard access. Any JavaScript executing in the main WebView (including injected XSS) can invoke these via `exec("PluginName", "action", ...)`.

```js
// From the main WebView — calls any registered Cordova plugin
_cordovaNative.exec(1, "SecureStorage", "get", '["lightning_wallet_seed"]', '');
```

### Potential Mitigation

Apply Cordova's `Content-Security-Policy` to the main `index.html`, restrict `<allow-navigation>` to trusted origins in `config.xml`, and for sensitive plugins (key storage, network) add per-call origin validation inside the plugin's `execute()` method.

### Relevant Files

- `node_modules/cordova-android/framework/src/org/apache/cordova/engine/SystemExposedJsApi.java` — `exec()` and `setNativeToJsBridgeMode()` implementations
- `config.xml` — registered plugin list and allowed-navigation entries


### Links to github
https://github.com/samotari/paynoway/tree/fdroid-v2.1.0
https://github.com/samotari/paynoway/blob/fdroid-v2.1.0/platforms/android/CordovaLib/src/org/apache/cordova/engine/SystemExposedJsApi.java