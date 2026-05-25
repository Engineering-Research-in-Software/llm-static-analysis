# MMRL Security Findings — Verified Research Output

Findings sourced from `csv/com.dergoogler.mmrl_34292.csv` (APK version code 34292).
All findings were manually evaluated against the source in `MMRL-master`.

**Legend**: VALID = confirmed exploitable | PARTIAL = confirmed surface, unconfirmed exploit chain | INVALID = hallucinated / no evidence

---

## Finding 1: JavaScript Bridge Interface Exposure (WXInterface)

**CSV Verdict**: PARTIAL

**Finding Title (CSV)**: Arbitrary Code Execution via addJavascriptInterface / Unvalidated Javascript Injection via addJavascriptInterface / Insecure JavaScript Interface Exposure

**Problem Summary**:
The app exposes a Java object (`WXInterface`) to JavaScript via `addJavascriptInterface` under the bridge name `"wx"`. Module web UIs bundled with Magisk/KernelSU/APatch modules execute inside a WebView and can invoke any `@JavascriptInterface`-annotated method on this object via `window.wx.<method>()`. A malicious or compromised module WebUI could call privileged Java methods — the actual risk surface depends entirely on what methods `WXInterface` exposes.

**Why PARTIAL and not VALID**:
- `WXInterface` source is in the external `webuix-hwui` library (compiled into APK, not in this repo). Without auditing that library, specific exploitable methods cannot be confirmed.
- No SQL, file, intent, or PII-leaking methods were found in the available source code.
- The AI models that flagged this explicitly admitted "N/A — Potential based on..." for the specific sinks they claimed.
- `addJavascriptInterface` exposure itself is confirmed and real, but no verified exploit chain exists from available source.

**Potential Mitigation**:
- Audit `WXInterface` methods in the `webuix-hwui` / `webuix-helper` library — restrict any that expose shell execution, file I/O, or device identifiers
- Enforce module signature verification before loading module WebUIs in the bridge-enabled WebView
- Consider using `shouldInterceptRequest` with an allowlist instead of exposing broad Java methods
- Apply `@JavascriptInterface` sparingly and document each exposed method's trust boundary

**Relevant Files**:
- `app/build.gradle.kts` (lines 200–201) — `webuix-hwui` and `webuix-helper` dependency declarations
- `app/proguard-rules.pro` (line 56) — `-keep class com.dergoogler.mmrl.webui.interfaces.**` (confirms class is in APK)
- External: `com.dergoogler.mmrl.webui.interfaces.WXInterface` (inside `webuix-hwui` AAR, not in this repo)
- `app/src/main/kotlin/com/dergoogler/mmrl/ui/screens/moduleView/ViewDescriptionScreen.kt` — example of a separate WebView with controlled JS interface (the `markdown` bridge)

---

## Finding 2: Cleartext HTTP Traffic Permitted on Loopback Interfaces

**CSV Verdict**: PARTIAL

**Finding Title (CSV)**: Insecure Protocol Usage / Insecure Content Loading

**Problem Summary**:
`network_security_config.xml` explicitly permits unencrypted HTTP traffic to `127.0.0.1`, `0.0.0.0`, and `::1`. This enables a developer feature (`useWebUiDevUrl`) where the WebView can load module UI from a local development server instead of the bundled assets. The default dev URL is `https://127.0.0.1:8080` (HTTPS), but:

1. No scheme enforcement exists — a user could configure `http://127.0.0.1:8080` and the OS would permit it.
2. `0.0.0.0` is included in the cleartext allowlist. Unlike `127.0.0.1` and `::1`, `0.0.0.0` is not a true loopback — on some configurations it can resolve to all interfaces, potentially permitting cleartext traffic beyond localhost.
3. On a rooted device (this app's target platform), other root-level processes or debugging tools could intercept loopback traffic, reading WebUI content delivered over HTTP before it reaches the WebView.

**Why PARTIAL and not VALID**:
- `useWebUiDevUrl` defaults to `false` — feature is opt-in and not active for normal users.
- Exploitation requires either: (a) user enabling dev mode + switching to HTTP URL, or (b) a co-resident root process intercepting loopback traffic.
- No confirmed exploit chain for production users; relevant only in developer/rooted scenarios.

**Potential Mitigation**:
- Gate `useWebUiDevUrl` behind a debug build flag (`BuildConfig.DEBUG`) so it is unavailable in release APKs
- Enforce HTTPS scheme when persisting `webUiDevUrl` — reject `http://` values in the settings ViewModel
- Remove `0.0.0.0` from the `network_security_config.xml` cleartext domain list (not a standard loopback address)
- Consider removing the dev URL feature entirely from release builds

**Relevant Files**:
- `app/src/main/res/xml/network_security_config.xml` — cleartext allowlist for 127.0.0.1, 0.0.0.0, ::1
- `datastore/src/main/kotlin/com/dergoogler/mmrl/datastore/model/UserPreferences.kt` — `webUiDevUrl` (default: `https://127.0.0.1:8080`) and `useWebUiDevUrl` (default: `false`)
