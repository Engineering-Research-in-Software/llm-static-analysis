# Missing Error Handling on `postMessage` in Backup Upload Screen

## Detection note

This issue was identified through automated LLM-based static analysis of WebView `addJavascriptInterface` bridges, as part of academic security research at the University of Southern Denmark (SDU) in the context of a masters level course named Engineering in Research.

The finding was manually reviewed before submission.

To aid the purposes of our research, we would kindly request acknowledgement of the reported issue as well as a final verdict from the open source community working on this repository, even if the issue is not acted on.

We are reporting in good faith and are happy to answer questions.

## Summary

The `onMessage` handler in `src/screens/user/backup/upload/index.tsx` calls `JSON.parse` on the WebView message without a surrounding `try/catch`. If malformed JSON is received, an unhandled exception is thrown. Other `onMessage` handlers in the codebase (web-view, login, award, share screens) correctly guard `JSON.parse` with `try/catch`. The affected WebView loads only app-controlled injected HTML, so the practical attack surface is minimal, but the missing guard is a defensive inconsistency.

**Severity:** Low
**Affected version(s):** latest commit on the default branch (commit hash unknown at time of analysis)

---

## Affected file(s)

- `src/screens/user/backup/upload/index.tsx` — `onMessage` handler (line 36)

---

## Vulnerable code

```tsx
// src/screens/user/backup/upload/index.tsx:36 — JSON.parse without try/catch
onMessage={event => {
  const { data } = JSON.parse(event.nativeEvent.data)
  $.onMessage(data)
}}
```

Compare with the guarded pattern used elsewhere in the codebase:

```tsx
// src/screens/web-view/index.tsx:70-93 — correct guarded pattern
onMessage={event => {
  try {
    const { type, data } = JSON.parse(event.nativeEvent.data)
    // ...
  } catch (e) {
    // handle gracefully
  }
}}
```

---

## Proof of concept

```js
// Not applicable in practice — WebView content is app-controlled injected HTML.
// The unguarded parse would throw if malformed JSON were posted:
window.ReactNativeWebView.postMessage("not valid json {");
```

---

## Impact

Very low. The unguarded `JSON.parse` is only reachable via app-injected HTML content — no external attacker path exists in the current configuration. An unhandled exception here would cause the backup/upload screen to crash or fail silently, affecting only the user's own session. No data exfiltration or privilege escalation is possible.

---

## Suggested mitigation

Wrap the `onMessage` handler in a `try/catch` block consistent with the pattern used in other screens:

```tsx
onMessage={event => {
  try {
    const { data } = JSON.parse(event.nativeEvent.data)
    $.onMessage(data)
  } catch (e) {
    console.warn('onMessage parse error', e)
  }
}}
```
