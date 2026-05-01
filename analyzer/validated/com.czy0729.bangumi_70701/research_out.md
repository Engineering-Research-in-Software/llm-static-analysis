# Security Findings Research Output
**App:** com.czy0729.bangumi (Bangumi — React Native anime tracker)
**Scope:** WebView bridge callsites (Intent-webview_new-11, Intent-webview_new-12)

---

## Summary

No findings were marked fully **VALID** as vulnerability findings. After manual code verification:

- **7 VALID** assessments = AI models correctly concluded "no vulnerabilities" for their specific analysis
- **2 PARTIAL** = real issues exist but are overstated or lack demonstrated exploitability
- **12 INVALID** = speculation, architectural misunderstanding, or no code evidence

---

## Partial Findings

### 1. Unsanitized Input to postMessage Bridge (Callsite 11)

**Finding title:** Unsanitized Input to PostMessage
**Inspector:** ollama/phi4:14b

**Finding problem summary:**
The `postMessage(String)` Java bridge method in `RNCWebViewManager$f$c` accepts arbitrary strings from JavaScript with no validation at the bridge layer. The generic in-app browser (`web-view/index.tsx`) loads **arbitrary external URLs** and injects JavaScript that exposes `window.ReactNativeWebView.postMessage` to any page loaded. A page under attacker control could post crafted messages to the `onMessage` handler. The handler validates message type via a `switch` statement, and unknown types fall through to `default: break`, limiting impact. The claim of "code injection attacks" is **not supported** — no handler uses `eval()` or unsafe sinks on received data.

**Actual risk:**
An external page loaded in the in-app browser can call `window.ReactNativeWebView.postMessage('{"type":"onload","data":{"href":"...any URL..."}}')` to manipulate the redirect counter or trigger `onError()` (navigates back). Impact: minor UX manipulation, no sensitive data access, no privilege escalation.

**Potential mitigation:**
- Validate `data.href` against the originally requested URI before trusting it in redirect logic
- Optionally: restrict `onMessage` to only process messages when `currentURL` matches an expected origin

**Relevant files:**
- `src/screens/web-view/index.tsx` — generic browser; loads external URLs; `onMessage` handler at line 67
- `src/components/web-view/index.tsx` — base WebView wrapper

---

### 2. Lack of Input Validation on postMessage (Callsite 11)

**Finding title:** Lack of Input Validation on postMessage
**Inspector:** ollama/gemma3:12b

**Finding problem summary:**
Same root condition as above. The `postMessage` Java method has no validation. Multiple `onMessage` handlers do have `try/catch` around `JSON.parse` (web-view, login, award, share screens). However, `src/screens/user/backup/upload/index.tsx` (line 36) processes the message without try-catch:

```js
onMessage={event => {
  const { data } = JSON.parse(event.nativeEvent.data)
  $.onMessage(data)
}}
```

This WebView loads **controlled HTML injected by the app**, so no external attacker can reach it in normal operation. Risk is limited. The finding's claim of "various vulnerabilities depending on downstream handling" is too vague — actual downstream handling in the app is safe.

**Actual risk:**
Very low. The unguarded `JSON.parse` in backup/upload is only reachable by app-controlled injected HTML. No path for attacker-controlled input exists here.

**Potential mitigation:**
- Add try-catch to the `onMessage` handler in `src/screens/user/backup/upload/index.tsx` for defensive robustness

**Relevant files:**
- `src/screens/user/backup/upload/index.tsx` — missing try-catch at line 36
- `src/screens/web-view/index.tsx` — has try-catch (line 70–93)
- `src/screens/login/index/index.tsx` — has try-catch (line 69–100)

---

## Invalid Findings — Key Dismissal Reasons

| Finding | Reason Invalid |
|---------|---------------|
| Cross-app communication via postMessage | Misunderstands React Native WebView architecture. `postMessage` is a Java `@JavascriptInterface` method — data goes to `onMessage` handler in the same app, not to other apps |
| Arbitrary code execution via postMessage | No `eval()` or dynamic code execution in any `onMessage` handler. Would require attacker control of receiver code |
| PII disclosure via postMessage | Login screen captures `document.cookie` intentionally for OAuth flow. Generic browser injects JS that only posts `href`, not PII |
| Insecure Messaging Toggle (setMessagingEnabled) | `setMessagingEnabled` is a Java method called by the RN bridge — not exposed to JavaScript. JS cannot invoke it |
| SQL Injection via setMessagingEnabled | No SQL anywhere in WebView or bridge code |
| Path Traversal | No file path manipulation in any bridge handler |
| PII Exposure (getDeviceId etc.) | No such method calls in codebase — pure speculation |
| DoS via setMessagingEnabled toggle | Same as above — JS cannot call this method |
| Message origin validation | `message.origin` is a concept from the web `postMessage` API, not applicable to Android `@JavascriptInterface` |
| http:// content loading | No evidence of http:// URLs in any WebView source prop |
