# Security Research Findings — KnkPanime (com.example.knkpanime v101073)

Two callsites analyzed (Intent-webview_new-78 and 79), both sharing the same `flutter_inappwebview` bridge (`JavaScriptBridgeInterface`) registered in the app's `InAppWebView` instances. The app is a Flutter-based anime viewer that loads streaming content from external sources.

All findings are PARTIAL. The bridge is provided by the third-party `flutter_inappwebview` Flutter plugin — the Java-layer bridge methods are fixed by the plugin, but the actual attack surface depends on which Dart-side handlers the app registers via `addJavaScriptHandler()`, which are not visible in Java static analysis. No JavaScript snippets were available to inspectors.

Models heavily hallucinated specific attack paths through `_callHandler`: SQL injection (deepseek, qwen2.5), RCE (gemma3), generic injection (phi4) — all INVALID, as `_callHandler` dispatches to Dart-registered handlers, not to SQL/file/reflection operations. The one confirmed real concern is the absence of origin validation.

---

## Finding 1: No Origin Validation on `flutter_inappwebview._callHandler`

**Verdict**: PARTIAL  
**Reported by**: qwen2.5 (callsites 78–79, "Protocol & Origin Security"), deepseek-r1 (callsite 79, "Origin Security Issue"), phi4 (callsites 78–79, "Lack of Origin Validation"), gemma3 (callsites 78–79, "No Origin Validation Observed" / "Lack of Origin Validation")

### Problem Summary

The `flutter_inappwebview` plugin registers a `JavaScriptBridgeInterface` object named `flutter_inappwebview` with the Android WebView. This exposes `_callHandler(handlerName, args, callbackId)` to all JavaScript executing in the WebView with no check on the origin of the call. In Flutter apps, `addJavaScriptHandler` is used to register named handlers in Dart that JavaScript can invoke by name:

```dart
// Dart-side (app code) — not visible in Java static analysis
webViewController.addJavaScriptHandler(
    handlerName: 'getUserData',
    callback: (args) async { return await fetchSensitiveData(); }
);
```

From JavaScript, any code in the WebView - including scripts served by untrusted anime streaming domains, injected via XSS, or loaded from iframes - can invoke:

```js
window.flutter_inappwebview.callHandler('getUserData', arg1, arg2);
```

This call goes through the Java bridge method `_callHandler("getUserData", "[arg1, arg2]", callbackId)` and is dispatched to the Dart handler without any origin check at the plugin level.

Data flow:
```
JS  window.flutter_inappwebview.callHandler(handlerName, ...args)
  → JavaScriptBridgeInterface._callHandler(String handlerName, String args, String callbackId)
    → Dart MethodChannel dispatch → app-registered handler callback
```

The jsdetails table shows the app loads URLs from `Request.getUrl()` (dynamic, externally sourced anime stream URLs) as well as Flutter assets. External streaming domains are a realistic XSS surface that could be exploited to invoke registered handlers.

Note: `_hideContextMenu()` exposes no meaningful attack surface beyond minor UX manipulation.

### Potential Mitigation

The `flutter_inappwebview` plugin (v6+) provides `onCallJsHandler` and permission hooks. At the app level, each registered handler should validate the current URL before acting on the call:

```dart
webViewController.addJavaScriptHandler(
    handlerName: 'sensitiveOp',
    callback: (args) async {
        final currentUrl = await webViewController.getUrl();
        if (currentUrl == null || !Uri.parse(currentUrl).host.endsWith('trusted-domain.com')) {
            return {'error': 'unauthorized'};
        }
        // proceed
    }
);
```

Alternatively, restrict the WebView to a trusted origin allowlist using `InAppWebViewSettings` content policies and JavaScript restrictions.

### Relevant Files

- `com/pichillilorenzo/flutter_inappwebview_android/webview/JavaScriptBridgeInterface.java` — `_callHandler()` bridge method (plugin-provided, not app code)
- Flutter app Dart sources (not analyzed) — `addJavaScriptHandler()` registrations define the actual exploitable handlers


### Link to github 
- https://github.com/pichillilorenzo/flutter_inappwebview/blob/master/flutter_inappwebview_android/android/src/main/java/com/pichillilorenzo/flutter_inappwebview_android/webview/JavaScriptBridgeInterface.java#L53

- https://github.com/pichillilorenzo/flutter_inappwebview/blob/master/flutter_inappwebview/lib/src/in_app_webview/in_app_webview_controller.dart#L257