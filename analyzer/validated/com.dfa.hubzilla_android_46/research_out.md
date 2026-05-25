# Security Research Findings

## PARTIAL Findings

---

### setUserProfile Origin Check Prefix Bypass

**Finding Problem Summary**

`setUserProfile(String)` in `AndroidBridge` performs an origin check before processing data, but uses `startsWith(baseUrl)` where `baseUrl` has no trailing slash (e.g. `https://hub.disroot.org`). A domain like `https://hub.disroot.org.evil.com` satisfies this prefix check. The same `startsWith("https://" + host)` pattern in `CustomWebViewClient.shouldOverrideUrlLoading()` means the WebView would also allow navigation to such a domain without redirecting to an external browser. An attacker who controls a domain that starts with the configured pod hostname could serve a page that calls `AndroidBridge.setUserProfile()` with arbitrary JSON, overwriting the locally cached user profile (display name, avatar URL, GUID).

Impact is low in practice: the stored profile data is not used for authentication or authorization — it drives UI display only (avatar image, username shown in the app). Exploitability also requires the attacker to register a domain prefixed by the victim's exact pod hostname, which is only possible if the pod hostname is a subdomain (e.g. `hub.example.org` → register `hub.example.org.evil.com` is impossible; but `hub.example.org` → register the parent-zone prefix trick is also not generally possible). Realistic attack surface is very narrow.

**Potential Mitigation**

Replace prefix matching with exact host comparison in both locations:

- `DiasporaStreamFragment.java:412` — parse `webView.getUrl()` with `Uri.parse()` and compare `.getHost()` against the configured pod host instead of using `startsWith(baseUrl)`.
- `CustomWebViewClient.java:57` — same: parse the URL and compare host exactly rather than `url.startsWith("https://" + host)`.

Alternatively, appending a trailing `/` to `baseUrl` before `startsWith` eliminates the subdomain bypass at the cost of blocking non-root paths on non-standard pods.

**Relevant Files**

- `app/src/main/java/com/dfa/hubzilla_android/activity/DiasporaStreamFragment.java` — line 412 (origin check in `setUserProfile`)
- `app/src/main/java/com/dfa/hubzilla_android/web/CustomWebViewClient.java` — line 57 (navigation allowlist)
- `app/src/main/java/com/dfa/hubzilla_android/data/DiasporaPodList.java` — line 418 (`getBaseUrl()` returns no trailing slash)
