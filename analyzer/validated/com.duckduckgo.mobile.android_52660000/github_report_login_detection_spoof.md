# `LoginDetectionJavascriptInterface.loginDetected()` Spoofable by Any Page, Coerces Fireproofing Prompt

> **Disclosure channel:** This draft is intended for submission via DuckDuckGo's HackerOne program at https://hackerone.com/duckduckgo, per the project's `CONTRIBUTING.md`. It is included in this repository as a research record only and should not be filed as a public issue against `duckduckgo/Android` directly.

## Detection note

This issue was identified through automated LLM-based static analysis of WebView `addJavascriptInterface` bridges, as part of academic security research at the University of Southern Denmark (SDU) in the context of a masters level course named Engineering in Research.

The finding was manually reviewed before submission.

To aid the purposes of our research, we would kindly request acknowledgement of the reported issue as well as a final verdict from the open source community working on this repository, even if the issue is not acted on.

We are reporting in good faith and are happy to answer questions.

## Summary

`LoginDetectionJavascriptInterface` is registered globally on the browser WebView with no URL allowlist. Its `loginDetected()` method calls `viewModel.loginDetected()`, which fires `navigationAwareLoginDetector.onEvent(NavigationEvent.LoginAttempt(currentUrl))`. That is the trigger for DDG's automatic fireproofing flow, the dialog that asks the user whether to fireproof the current site so its cookies survive Fire data-clears.

Any web page can call `window.LoginDetection.loginDetected()` at any time and cause that prompt to appear for the current URL. A user who taps "Yes" preserves the attacker site's cookies even when the Fire button is used, directly undermining DDG's headline privacy feature.

**Severity:** Medium (privacy-specific to DDG's threat model)
**Affected version(s):** version code 52660000

---

## Affected file(s)

- `app/src/main/java/com/duckduckgo/app/browser/logindetection/LoginDetectionJavascriptInterface.kt`
- `app/src/main/java/com/duckduckgo/app/browser/logindetection/DOMLoginDetector.kt`
- `app/src/main/java/com/duckduckgo/app/browser/BrowserTabFragment.kt` (around line 4047, bridge registration)
- `app/src/main/java/com/duckduckgo/app/browser/BrowserTabViewModel.kt` (around line 3781)

---

## Vulnerable surface

```kotlin
@JavascriptInterface
fun loginDetected() {
    onLoginDetected()   // -> viewModel.loginDetected() -> NavigationEvent.LoginAttempt
}
```

The `log(message)` method on the same interface is harmless (only calls `logcat(INFO)` which is inaccessible without `READ_LOGS`).

---

## Proof of concept

```js
// From a tracker-heavy page that wants to persist its cookies across Fire:
setInterval(() => window.LoginDetection.loginDetected(), 5000);
// The fireproofing dialog reappears every 5s until the user taps Yes to dismiss.
```

A more subtle variant fires once after a fake "Sign in" button, hoping the user assumes the dialog is part of the login flow.

---

## Impact

Tapping "Yes" on the fireproof prompt preserves the originating site's cookies indefinitely. Since the Fire and Clear-Data feature is one of DDG's headline privacy guarantees, bypassing it via a one-tap social-engineered prompt is a direct privacy regression for users. The attack is one-click and silent from the WebView's perspective: the page does not need any user interaction to call the bridge.

---

## Suggested mitigation

- Cross-validate against the current URL before dispatching `LoginAttempt`: apply the same URL-path heuristic that already exists in `DOMLoginDetector.evaluateIfLoginPostRequest()` (checks for `login|sign-in|signin|session` in the path).
- Or: only register `LoginDetectionJavascriptInterface` after a POST request to a login-path URL has been intercepted. The current flow already detects this in `onEvent(ShouldInterceptRequest)` before calling `scanForPasswordFields`. Inject the bridge with `WebViewCompat.addDocumentStartJavaScript` scoped to the matching origin only.
