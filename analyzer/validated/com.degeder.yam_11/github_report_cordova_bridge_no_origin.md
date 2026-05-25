# Cordova `_cordovaNative` Bridge Exposed Without Origin Validation

## Detection note

This issue was identified through automated LLM-based static analysis of WebView `addJavascriptInterface` bridges, as part of academic security research at the University of Southern Denmark (SDU) in the context of a masters level course named Engineering in Research.

The finding was manually reviewed before submission.

To aid the purposes of our research, we would kindly request acknowledgement of the reported issue as well as a final verdict from the open source community working on this repository, even if the issue is not acted on.

We are reporting in good faith and are happy to answer questions.

## Summary

The Cordova bridge methods `_cordovaNative.exec()`, `retrieveJsMessages()`, and `setNativeToJsBridgeMode()` are `@JavascriptInterface` methods accessible to any JavaScript executing in the WebView with no per-call origin validation. YAM currently serves content only from `http://localhost`, which limits practical risk. However, any external URL navigated to by the WebView — for example via a misconfigured `allowNavigation` entry or a dynamic `loadUrl()` call — would have unrestricted access to the full Cordova plugin bridge.

**Severity:** Low
**Affected version(s):** v11 (latest at time of analysis)

---

## Affected file(s)

- `android/app/src/main/res/xml/config.xml` — navigation and access policy
- `android/app/src/main/java/com/degeder/yam/MainActivity.java` — WebView configuration
- Cordova engine class `org.apache.cordova.engine.b` (compiled from `@capacitor/android` dependency — not in source tree)

---

## Vulnerable code

```java
// The _cordovaNative bridge is registered by the Cordova engine with no origin restriction.
// Any page the WebView loads can call:
// _cordovaNative.exec(successCallback, failCallback, pluginName, action, args)
// No origin check is performed by the framework.
```

---

## Proof of concept

```js
// Any external page navigated to would have full bridge access:
_cordovaNative.exec(
  function(result) { console.log(result); },
  function(err) {},
  "File",
  "readAsText",
  [{ "fileName": "/data/data/com.degeder.yam/files/sensitive.db" }]
);
```

---

## Impact

In the current configuration (content served exclusively from `http://localhost`) this issue has low practical impact. If any external URL were loaded in the WebView, that page would gain access to the full Cordova plugin bridge — including filesystem, device info, and any other installed plugins — without any origin validation. The wildcard `<access origin="*" />` in `config.xml` (see related finding) would permit such access.

---

## Suggested mitigation

1. Ensure no external URLs are navigated to in the WebView. Audit all `allowNavigation` entries in `config.xml` and remove any wildcard entries.
2. Verify no `loadUrl()` calls in native code navigate to external origins.
3. Restrict navigation to `http://localhost` only: replace `<access origin="*" />` with `<access origin="http://localhost/*" />`.
