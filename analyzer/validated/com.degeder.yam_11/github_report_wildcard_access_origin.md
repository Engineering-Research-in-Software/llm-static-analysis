# Cordova `config.xml` Wildcard `<access origin="*" />`

## Detection note

This issue was identified through automated LLM-based static analysis of WebView `addJavascriptInterface` bridges, as part of academic security research at the University of Southern Denmark (SDU) in the context of a masters level course named Engineering in Research.

The finding was manually reviewed before submission.

To aid the purposes of our research, we would kindly request acknowledgement of the reported issue as well as a final verdict from the open source community working on this repository, even if the issue is not acted on.

We are reporting in good faith and are happy to answer questions.

## Summary

The Cordova `config.xml` contains `<access origin="*" />`, configuring a wildcard origin access policy. Combined with the `_cordovaNative` bridge being exposed to all WebView JavaScript without origin validation, any external URL navigated to by the WebView would have unrestricted access to the Cordova plugin bridge. YAM never navigates to external URLs in its current configuration, making this a hardening gap rather than an active vulnerability, but restricting the access origin would eliminate the risk entirely.

**Severity:** Low
**Affected version(s):** v11 (latest at time of analysis)

---

## Affected file(s)

- `android/app/src/main/res/xml/config.xml` — access origin policy

---

## Vulnerable code

```xml
<!-- config.xml — wildcard permits any origin to access the Cordova bridge -->
<access origin="*" />
```

---

## Proof of concept

Not directly exploitable without external URL navigation. If any external URL were loaded in the WebView, the wildcard policy combined with the exposed bridge would grant that page full plugin access:

```js
// From any external page loaded in the WebView:
_cordovaNative.exec(successCb, failCb, "SomePlugin", "someAction", ["args"]);
```

---

## Impact

This is a defence-in-depth gap. In YAM's current configuration, the WebView only loads `http://localhost` content, so no external origin can reach the bridge. However, the wildcard access policy means any future change that introduces external URL loading (via `allowNavigation`, `loadUrl()`, or a redirect) would immediately expose the full Cordova bridge to that external content without requiring any further configuration change. Restricting the access origin is a zero-cost hardening measure.

---

## Suggested mitigation

Replace the wildcard access origin with a restrictive policy:

```xml
<!-- Replace this: -->
<access origin="*" />

<!-- With this: -->
<access origin="http://localhost/*" />
```

Or use Capacitor's `allowNavigation` configuration to explicitly block all external URL navigation, ensuring that even if the access policy is permissive, no external content can be loaded.
