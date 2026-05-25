# Unsanitized Input to `postMessage` Bridge Without Origin Validation

## Detection note

This issue was identified through automated LLM-based static analysis of WebView `addJavascriptInterface` bridges, as part of academic security research at the University of Southern Denmark (SDU) in the context of a masters level course named Engineering in Research.

The finding was manually reviewed before submission.

To aid the purposes of our research, we would kindly request acknowledgement of the reported issue as well as a final verdict from the open source community working on this repository, even if the issue is not acted on.

We are reporting in good faith and are happy to answer questions.

## Summary

The generic in-app browser (`src/screens/web-view/index.tsx`) loads arbitrary external URLs and injects JavaScript that exposes `window.ReactNativeWebView.postMessage` to every page loaded. The `onMessage` handler processes received messages without validating their origin. Any external page opened in the in-app browser can post crafted messages to manipulate app state. Impact is limited to minor UX effects (redirect counter manipulation, triggering back navigation) as no handler uses unsafe sinks on received data.

**Severity:** Low
**Affected version(s):** latest commit on the default branch (commit hash unknown at time of analysis)

---

## Affected file(s)

- `src/screens/web-view/index.tsx` — `onMessage` handler (line 67)
- `src/components/web-view/index.tsx` — base WebView wrapper

---

## Vulnerable code

```tsx
// src/screens/web-view/index.tsx:67 — no origin check before processing
onMessage={event => {
  const { type, data } = JSON.parse(event.nativeEvent.data)
  switch (type) {
    case 'onload': // uses data.href without validating against requested origin
    case 'onerror': // triggers back navigation
    default: break
  }
}}
```

---

## Proof of concept

```js
// From any external page loaded in Bangumi's in-app browser:
window.ReactNativeWebView.postMessage(
  JSON.stringify({ type: "onload", data: { href: "http://attacker.com" } })
);
// Result: manipulates the in-app redirect counter
```

---

## Impact

An attacker-controlled page loaded in the in-app browser can post crafted messages that manipulate the redirect counter or trigger `onError()` (back navigation). There is no sensitive data access and no privilege escalation through this path — the `switch` statement's `default: break` prevents unknown message types from having effect. Impact is limited to minor, user-visible UX disruption.

---

## Suggested mitigation

Validate `data.href` against the originally requested URI before trusting it in redirect logic. Optionally, restrict `onMessage` processing to messages from expected origins by tracking the currently loaded URL and comparing it against the message source.
