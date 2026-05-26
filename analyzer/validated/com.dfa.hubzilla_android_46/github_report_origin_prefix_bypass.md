# Origin Check Prefix Bypass in `setUserProfile()` and `shouldOverrideUrlLoading()`

## Detection note

This issue was identified through automated LLM-based static analysis of WebView `addJavascriptInterface` bridges, as part of academic security research at the University of Southern Denmark (SDU) in the context of a masters level course named Engineering in Research.

The finding was manually reviewed before submission.

To aid the purposes of our research, we would kindly request acknowledgement of the reported issue as well as a final verdict from the open source community working on this repository, even if the issue is not acted on.

We are reporting in good faith and are happy to answer questions.

## Summary

`setUserProfile(String)` in `AndroidBridge` performs an origin check before processing data, but uses `startsWith(baseUrl)` where `baseUrl` has no trailing slash (e.g. `https://hub.disroot.org`). A domain like `https://hub.disroot.org.evil.com` satisfies that prefix check and bypasses the gate. The same `startsWith("https://" + host)` pattern is repeated in `CustomWebViewClient.shouldOverrideUrlLoading()`, meaning the WebView also navigates to such a domain in-app rather than handing it off to an external browser. An attacker who controls a domain prefixed by the user's configured pod host can serve a page that calls `AndroidBridge.setUserProfile(...)` with arbitrary JSON, overwriting the locally cached user profile.

**Severity:** Low (impact is limited to display-only profile data; the navigation allowlist bypass is the wider concern)
**Affected version(s):** version code 46 (0.8.16, latest at time of analysis)

---

## Affected file(s)

- `app/src/main/java/com/dfa/hubzilla_android/activity/DiasporaStreamFragment.java` around line 412 - origin check in `setUserProfile()`
- `app/src/main/java/com/dfa/hubzilla_android/web/CustomWebViewClient.java` around line 57 - navigation allowlist
- `app/src/main/java/com/dfa/hubzilla_android/data/DiasporaPodList.java` around line 418 - `getBaseUrl()` returns no trailing slash

---

## Vulnerable code

```java
// DiasporaStreamFragment.java (approximate)
if (!webView.getUrl().startsWith(baseUrl)) return;
// baseUrl = "https://hub.disroot.org" (no trailing slash)
// Matches: https://hub.disroot.org/...                  (intended)
//          https://hub.disroot.org.evil.com/...         (BYPASS)
```

The same pattern in `CustomWebViewClient.shouldOverrideUrlLoading()` lets navigation to `https://hub.disroot.org.evil.com` stay inside the WebView with bridge access intact.

---

## Proof of concept

Practical reachability is narrow: the bypass requires an attacker-controlled domain whose name is a prefix of the user's pod host. For a pod at `hub.example.org`, registering `hub.example.org.evil.com` is feasible if `evil.com` is owned by the attacker. The user must navigate to that domain (for example via a crafted link in a Hubzilla post that the WebView opens directly).

```js
// On https://hub.example.org.evil.com/profile-swap.html
AndroidBridge.setUserProfile(JSON.stringify({
    displayName: "Administrator", avatar: "https://attacker.example/avatar.png",
    guid: "<arbitrary>", podUrl: "https://hub.example.org"
}));
```

---

## Impact

- **Profile overwrite**: the locally cached display name, avatar URL, and GUID can be replaced with attacker-chosen values. Hubzilla Android uses these for UI display only (not for authentication or authorization), so the impact is bounded to spoofing the in-app username and avatar.
- **Navigation bypass**: the same `startsWith` weakness in `shouldOverrideUrlLoading()` keeps the user inside the WebView when visiting the lookalike domain, giving the attacker a longer dwell time on a page that has bridge access.

If any subsequent code path treats the stored `podUrl` or `guid` as authoritative for backend calls, severity rises; a code review for that follow-on usage is recommended.

---

## Suggested mitigation

Replace prefix matching with exact host comparison in both locations:

```java
private boolean isPodOrigin(String url) {
    if (url == null) return false;
    Uri uri = Uri.parse(url);
    String host = uri.getHost();
    if (host == null) return false;
    Uri pod = Uri.parse(getBaseUrl());
    return host.equalsIgnoreCase(pod.getHost());
}
```

Apply this in `DiasporaStreamFragment.setUserProfile()` and in `CustomWebViewClient.shouldOverrideUrlLoading()`.

Alternatively, appending a trailing `/` to `baseUrl` before `startsWith` eliminates the subdomain-prefix bypass, at the cost of blocking pod-relative non-root paths on non-standard pods. Exact-host comparison is preferred.

---

We acknowledge from the project README that Nomad is maintained by volunteers in their leisure time. There is no expectation of a fast response window; we are happy to wait and to provide any follow-up information that helps a fix land at whatever cadence works for the team.
