# Path Traversal in `WebAppAircraftInterface.importFromFile()` JavaScript Bridge

## Detection note

This issue was identified through automated LLM-based static analysis of WebView `addJavascriptInterface` bridges, as part of academic security research at the University of Southern Denmark (SDU) in the context of a masters level course named Engineering in Research.

The finding was manually reviewed before submission.

To aid the purposes of our research, we would kindly request acknowledgement of the reported issue as well as a final verdict from the open source community working on this repository, even if the issue is not acted on.

We are reporting in good faith and are happy to answer questions.

We note that this repository is marked deprecated in favour of the AvareX rewrite at `apps4av/avarex`. We are filing here because the legacy Avare APK remains installed on user devices and continues to be served from the Play Store listing referenced in this README; users on the legacy version remain exposed. The AvareX Flutter rewrite does not contain this Java code path and is unaffected.

## Summary

`WebAppAircraftInterface.importFromFile(String txt)` is a `@JavascriptInterface` method registered to the WebView as `AndroidList`. The method concatenates a caller-supplied filename into the user data directory and opens it for reading, with no canonicalization or traversal-sequence rejection. Any JavaScript executing in the Avare WebView can call `AndroidList.importFromFile("../../databases/avare.db")` and reach files outside the intended user data directory inside the app's private sandbox.

**Severity:** Medium
**Affected version(s):** version code 404 (latest at time of analysis)

---

## Affected file(s)

- `app/src/main/java/com/ds/avare/webinfc/WebAppAircraftInterface.java`
  - Line 442: `@JavascriptInterface importFromFile(String txt)` entry point
  - Line 488: sink `new FileInputStream(mPref.getUserDataFolder() + File.separator + txt)`
- `app/src/main/java/com/ds/avare/storage/Preferences.java` - `getUserDataFolder()` returns the base path
- `app/src/main/java/com/ds/avare/AircraftActivity.java` - line 96: bridge registration `mWebView.addJavascriptInterface(mInfc, "AndroidList")`

---

## Vulnerable code

```java
@JavascriptInterface
public void importFromFile(String txt) {
    // ...
    instream = new FileInputStream(mPref.getUserDataFolder() + File.separator + txt);
    // ...
}
```

The string `txt` flows from JavaScript directly into a filesystem path with no validation.

---

## Proof of concept

```js
// Any JS running in the Avare WebView can call:
AndroidList.importFromFile("../../databases/avare.db");
AndroidList.importFromFile("../shared_prefs/com.ds.avare_preferences.xml");
```

Each call causes the bridge to open a file outside the intended user data directory. Once the bridge ingests the file contents under the import code path, any downstream display or echo back to the WebView leaks sandbox data to JavaScript.

---

## Impact

Any JavaScript that reaches the Avare WebView (for example via a downloaded chart or plate page rendered in the WebView, or via a compromised resource bundled with the app) can read arbitrary files inside `/data/data/com.ds.avare/`, including SQLite databases (`avare.db`, route history, user-saved aircraft and plans), shared preferences, and other private files. Severity scales with whatever subsequent operation `importFromFile` performs with the file contents (echo back to JS, send to a server, or display in a view).

The same pattern likely repeats on neighboring methods in the interface (`saveDeleteWnb`, `saveWnb`, and the `WebAppPlanInterface` family); we recommend a sweep of all `@JavascriptInterface` methods in `webinfc/` that accept a filename or path string.

---

## Suggested mitigation

Resolve and validate the canonical path before opening the file:

```java
File base = new File(mPref.getUserDataFolder()).getCanonicalFile();
File target = new File(base, txt).getCanonicalFile();
if (!target.toPath().startsWith(base.toPath())) {
    return; // path traversal attempt, abort
}
instream = new FileInputStream(target);
```

Additionally, since this bridge is registered to a WebView that does not need to accept arbitrary filenames, consider restricting `txt` to an explicit allowlist of expected file names.
