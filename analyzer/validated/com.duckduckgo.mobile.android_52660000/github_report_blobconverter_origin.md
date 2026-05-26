# `BlobConverterJavascriptInterface` Triggers Downloads from Any Web Page

> **Disclosure channel:** This draft is intended for submission via DuckDuckGo's HackerOne program at https://hackerone.com/duckduckgo, per the project's `CONTRIBUTING.md`. It is included in this repository as a research record only and should not be filed as a public issue against `duckduckgo/Android` directly.

## Detection note

This issue was identified through automated LLM-based static analysis of WebView `addJavascriptInterface` bridges, as part of academic security research at the University of Southern Denmark (SDU) in the context of a masters level course named Engineering in Research.

The finding was manually reviewed before submission.

To aid the purposes of our research, we would kindly request acknowledgement of the reported issue as well as a final verdict from the open source community working on this repository, even if the issue is not acted on.

We are reporting in good faith and are happy to answer questions.

## Summary

`BlobConverterJavascriptInterface` is registered globally on the browser tab WebView via `WebView.addJavascriptInterface()` with no URL or origin allowlist. Its sole method, `convertBlobToDataUri(String dataUrl, String contentType)`, calls back into the host and ultimately resolves to `viewModel.requestFileDownload(webView, url, null, mimeType)` in `BrowserTabFragment`. That means any web page rendered by the browser, not only those where the user clicked a `blob:` download link, can call `window.BlobConverter.convertBlobToDataUri(...)` with attacker-chosen arguments and trigger a file download with attacker-chosen content and MIME type.

The intended use is for pages where the user explicitly clicked a `blob:` download link and DDG's own injected `convertBlobIntoDataUriAndDownload` script runs. The bridge itself has no gate enforcing that intent.

**Severity:** Low to Medium (bounded by whatever user confirmation `requestFileDownload` presents downstream)
**Affected version(s):** version code 52660000 (latest at time of analysis)

---

## Affected file(s)

- `app/src/main/java/com/duckduckgo/app/browser/downloader/BlobConverterJavascriptInterface.kt`
- `app/src/main/java/com/duckduckgo/app/browser/downloader/BlobConverterInjector.kt`
- `app/src/main/java/com/duckduckgo/app/browser/BrowserTabFragment.kt` (around line 4228, bridge registration)
- `app/src/main/java/com/duckduckgo/app/browser/BrowserTabViewModel.kt` (around line 3786, `requestFileDownload`)

---

## Vulnerable surface

```kotlin
@JavascriptInterface
fun convertBlobToDataUri(dataUrl: String, contentType: String) {
    onBlobConverted(dataUrl, contentType)  // -> requestFileDownload
}
```

Both parameters are caller-controlled by any page in the WebView.

---

## Proof of concept

```js
// From any web page rendered in the DDG browser tab:
window.BlobConverter.convertBlobToDataUri(
    "data:application/octet-stream;base64,SGVsbG8gV29ybGQ=",
    "application/octet-stream"
);
```

The download is initiated without the user having clicked anything page-side.

---

## Impact

The exact severity depends on whether `requestFileDownload` shows a user confirmation dialog before writing. If it does, the worst case is confirm-dialog spam (UX nuisance and phishing setup). If it does not, or if the dialog is bypassed in any code path, an attacker page can silently drop arbitrary files into the user's Downloads folder, priming a tap-to-install social engineering attack with an APK or a swapped legitimate-looking file.

---

## Suggested mitigation

- Migrate to `WebViewCompat.addDocumentStartJavaScript` with a restricted origin allowlist (already used in the feature-flag-enabled path on newer Android versions; apply the same approach when falling back to `addJavascriptInterface`).
- Or: in `convertBlobToDataUri`, validate that the WebView's current URL matches the origin that the page-side `convertBlobIntoDataUriAndDownload` injected script was running on, and that `dataUrl` begins with the `data:` scheme.

---

## Note

A second finding on `LoginDetectionJavascriptInterface` from the same research pass is documented in `issue_2_login_detection_spoof.md` in this folder.
