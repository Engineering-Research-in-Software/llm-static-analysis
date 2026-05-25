# Security Research Findings

## Valid Findings

---

### 1. Path Traversal in `importFromFile`

**Finding Title:** Path Traversal in `importFromFile`

**Problem Summary:**
`WebAppAircraftInterface.importFromFile()` is a `@JavascriptInterface` method directly callable from JavaScript in the app's WebView (registered as `AndroidList`). It accepts a user-supplied filename string and constructs a file path by concatenating the app's user data folder with that input — with no sanitization:

```java
instream = new FileInputStream(mPref.getUserDataFolder() + File.separator + txt);
```

No validation of path-traversal sequences (e.g., `../`) is performed before opening the file. JavaScript executing in the WebView can call `AndroidList.importFromFile("../../databases/avare.db")` to read arbitrary files accessible to the app process, including SQLite databases, shared preferences, and other data within the app's private sandbox.

**Potential Mitigation:**
Resolve the canonical path and verify it is still within the intended directory before opening:

```java
File base = new File(mPref.getUserDataFolder()).getCanonicalFile();
File target = new File(base, txt).getCanonicalFile();
if (!target.toPath().startsWith(base.toPath())) {
    return; // path traversal attempt, abort
}
instream = new FileInputStream(target);
```

**Relevant Files:**
- `app/src/main/java/com/ds/avare/webinfc/WebAppAircraftInterface.java`
  - Line 442: `@JavascriptInterface` entry point `importFromFile(String path)`
  - Line 488: sink — `new FileInputStream(mPref.getUserDataFolder() + File.separator + txt)`
- `app/src/main/java/com/ds/avare/storage/Preferences.java` — `getUserDataFolder()` returns the base path
- `app/src/main/java/com/ds/avare/AircraftActivity.java` — line 96: bridge registration `mWebView.addJavascriptInterface(mInfc, "AndroidList")`
