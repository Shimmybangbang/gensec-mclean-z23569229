# Security overview: Stego Studio

This document explains what the tool protects, what it does not, and the controls built into it.

## 1. What the tool is for

Stego Studio hides a text message inside an image (steganography). A password is optional. When one is set,
the message is encrypted before it is hidden (cryptography).
The two do different jobs:

| Goal | With a password ("covert mode") | Without a password |
|---|---|---|
| **Concealment**: nobody can tell a message exists | Key-scattered LSB matching, no signature | **None.** A fixed `STG1` header marks the image |
| **Confidentiality**: nobody can read the message | AES-256-GCM | **None.** Anyone with this tool can read it |
| **Integrity**: tampering is detected | GCM authentication tag | None |

**Always use a password for anything sensitive.**

## 2. Threat model

**Assets:** the secret message, the password, and the computer the server runs on.

**Assumed attackers:**
1. Someone who obtains the output PNG, such as an email recipient, an interceptor, or someone who finds the file.
2. A malicious website open in your browser while the server is running.
3. A device on the same Wi-Fi or LAN.
4. A malicious image file supplied to the tool.

**Out of scope:** an attacker who already controls your computer (malware, keylogger, admin access).
Such an attacker can read the message as you type it.

## 3. Controls in place

### Network exposure
- **Bound to `127.0.0.1` only.** Other devices on the network cannot connect. Traffic never leaves the
  machine, so plain HTTP is acceptable here. TLS would add nothing on loopback.
- **Debug mode is off.** Flask's interactive debugger allows arbitrary code execution and must never be enabled.

### Protection from other websites (attacker 2)
A web page you visit can try to send requests to `http://localhost:5000`. The app defends against this with:
- **Host header allow-list** (`127.0.0.1:5000`, `localhost:5000`). This blocks **DNS rebinding**, where an
  attacker's domain is made to resolve to 127.0.0.1.
- **Origin / `Sec-Fetch-Site` checks** on every POST. Cross-site requests receive `403`. This acts as CSRF protection.
- **CORS is not enabled.** Even if a request got through, another site could not read the response.

### Browser-side hardening (response headers)
| Header | Purpose |
|---|---|
| `Content-Security-Policy` (`script-src 'self'`, `default-src 'none'`, …) | Blocks injected or inline scripts (XSS). JS and CSS are served as separate static files so no `'unsafe-inline'` is needed. |
| `X-Frame-Options: DENY`, `frame-ancestors 'none'` | Blocks clickjacking |
| `X-Content-Type-Options: nosniff` | Stops MIME-type confusion |
| `Cache-Control: no-store` | Keeps revealed messages out of the browser cache |
| `Referrer-Policy: no-referrer` | Prevents URL leakage |
| `Cross-Origin-Opener/Resource-Policy: same-origin` | Isolates the page from other origins |
| `Permissions-Policy` | Disables camera, microphone and geolocation |

In addition, the front end inserts all server text with `textContent`, never `innerHTML`. A decoded
message that contains HTML or `<script>` is therefore displayed as plain text and never executed.

### Malicious or oversized uploads (attacker 4)
- **25 MB upload limit** and a **2 MB limit on text fields**. Larger requests receive `413`.
- **Decompression-bomb guard:** images over 40 megapixels are rejected. The size is read from the image header
  *before* any pixels are decoded. Pillow's own `MAX_IMAGE_PIXELS` limit is also set.
- **Format allow-list** (PNG, JPEG, BMP, GIF, TIFF, WEBP). Uploads are parsed by Pillow and never executed or trusted
  by their filename.
- **Nothing is written to disk.** Images are processed in memory and discarded after each request. The server has no
  upload folder, so path-traversal attacks have nothing to target.
- The hidden **length field is bounds-checked** against the image size before it is read.
- **Passwords are capped at 1024 characters.**

### Cryptography and covert embedding (password mode)
- **Key derivation:** PBKDF2-HMAC-SHA256 with **600,000 iterations** (OWASP guidance) turns the password into a master
  key. HKDF splits it into three independent sub-keys: pixel positions, length mask and encryption.
- **Encryption:** **AES-256-GCM** with a fresh random 96-bit nonce for every message. Identical messages produce
  different output, and the authentication tag rejects a wrong password or a modified image. The message is
  never "decrypted" into garbage.
- **No signature, no fixed layout.** The hidden stream is `masked length | nonce | ciphertext | tag`. Every byte
  is indistinguishable from random noise, including the length, which is XOR-masked with a key-derived value.
- **Key-scattered positions.** Bits go to pseudo-random colour channels across the *whole* image. A
  ChaCha20 keystream keyed by the password chooses them. Without the password nobody knows where to look, and
  nothing is concentrated at the start of the image.
- **LSB matching** (randomly +1 or −1) is used instead of LSB replacement. Replacement leaves a well-known
  statistical fingerprint: pairs of values such as 4 and 5 end up with equal counts, which the classic chi-square
  attack detects. Matching avoids that pattern.
- **Sparse embedding.** At most 50% of channels are used, and a short message touches only a tiny fraction of them.
- **Same answer for every failure.** "No message", "wrong password" and "no password given" return the identical
  error, so the tool itself can't be used to confirm that an image carries hidden data.
- The password is never stored or logged. It exists only in memory for the duration of a single request.
- Images made by the first version (STG1 header with Fernet encryption) can still be decoded.

### Error handling and privacy
- Unexpected errors return a generic `"Internal error."`. Stack traces are logged locally and never sent to the browser.
- **Metadata is stripped.** The output PNG is rebuilt from raw pixels, so EXIF data from the cover photo (GPS
  location, camera model, timestamps) is **not** carried into the output.

### Dependencies
`requirements.txt` pins exact versions that were checked with `pip-audit` (no known vulnerabilities at the time of
writing). Re-audit whenever you update:

```
.venv\Scripts\pip-audit -r requirements.txt
```

## 4. Known limitations (be honest about these)

1. **Without a password, the message is neither hidden nor secret.** It sits after a fixed `STG1` signature,
   written from the first pixel.
2. **Covert mode resists casual and classic detection, not every possible attack.** Modern machine-learning
   steganalysers can still flag *heavy* embedding statistically, even though they can't read or locate it. Keep
   messages small relative to the image (the less you hide, the safer). Use real photos rather than flat graphics or
   screenshots: smooth areas show changes more easily.
3. **The password protects the message only if it is strong.** PBKDF2 slows guessing but cannot save a weak
   password like `1234`. The key-derivation salt is fixed for the app, because positions must be found without
   reading anything first. An attacker could therefore pre-compute guesses for common passwords against *all*
   Stego Studio images at once. A long, unique password makes this irrelevant.
4. **Fragile against modification.** Re-saving as JPEG, resizing, cropping, or uploading to messaging and social apps that
   recompress images destroys the message. Send the PNG as a file attachment.
5. **The original cover image is a liability.** If an attacker has both the original and the stego version, a pixel
   diff reveals exactly where the data is. Use a photo you took yourself and delete the original.
6. **No authentication.** Anyone with access to your user session on this computer can use the tool. This is acceptable for a
   single-user local tool, but not for a shared or public server.
7. **Not built for internet hosting.** Exposing it publicly would require at least HTTPS, a production WSGI
   server (e.g. waitress or gunicorn) behind a reverse proxy, rate limiting, and authentication. Change `HOST` and
   `ALLOWED_HOSTS` only if you add those.

## 5. Safe usage checklist
- [ ] Always set a password. Without one, nothing is hidden or secret.
- [ ] Use a strong, unique password, such as a passphrase of 4 or more random words.
- [ ] Keep the message small compared with the image, and use a real photo as the cover.
- [ ] Share the password through a different channel than the image.
- [ ] Send the PNG as a file, not as an "image" that a chat app will recompress.
- [ ] Delete the original cover image.
- [ ] Stop the server (`Ctrl+C`) when you are not using it.
