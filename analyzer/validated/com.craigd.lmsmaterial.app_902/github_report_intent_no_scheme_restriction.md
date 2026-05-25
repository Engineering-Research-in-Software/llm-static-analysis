# WebView URL-to-Intent Without Scheme Restriction

## Detection note

This issue was identified through automated LLM-based static analysis of WebView `addJavascriptInterface` bridges, as part of academic security research at the University of Southern Denmark (SDU) in the context of a masters level course named Engineering in Research.

The finding was manually reviewed before submission.

To aid the purposes of our research, we would kindly request acknowledgement of the reported issue as well as a final verdict from the open source community working on this repository, even if the issue is not acted on.

We are reporting in good faith and are happy to answer questions.

## Summary

`shouldOverrideUrlLoading` in `MainActivity` intercepts all URLs not matching internal constants (`SETTINGS_URL`, `QUIT_URL`, `STARTPLAYER_URL`) and passes them to `Intent.ACTION_VIEW` without any scheme validation. A malicious page loaded in the WebView (for example via XSS in the LMS web UI) could navigate to `tel://`, `sms://`, `intent://`, or `android-app://` URIs, causing the device to dial phone numbers, send SMS, or launch arbitrary installed applications without user awareness.

**Severity:** Medium
**Affected version(s):** v0.9.2 (latest at time of analysis)

---

## Affected file(s)

- `lms-material/src/main/java/com/craigd/lmsmaterial/app/MainActivity.java` — `shouldOverrideUrlLoading()` (line 644–698)

---

## Vulnerable code

```java
// MainActivity.java:675 — no scheme check before Intent creation
Intent intent = new Intent(Intent.ACTION_VIEW, uri);
startActivity(intent);  // fires for any URI the WebView navigates to
```

---

## Proof of concept

```js
// XSS payload in LMS web UI navigates to a non-http URI:
location.href = "tel://+1234567890";
// or
location.href = "intent://com.example.malicious#Intent;scheme=android-app;end";
```

---

## Impact

An XSS vulnerability in the LMS web UI (or a compromised LMS server) can cause the app to pass arbitrary URIs to `startActivity()`. Depending on the URI scheme this may dial premium-rate phone numbers, send SMS to attacker-controlled numbers, or launch installed apps with attacker-controlled data URIs. Exploitability requires XSS or a compromised LMS server, which represents the trust boundary for this app.

---

## Suggested mitigation

Whitelist accepted URI schemes before creating the Intent:

```java
String scheme = uri.getScheme();
if (scheme == null || (!scheme.equals("http") && !scheme.equals("https"))) {
    return true; // block and ignore
}
// Explicitly deny dangerous schemes regardless of whitelist
if (scheme.equals("intent") || scheme.equals("android-app")) {
    return true;
}
```
