"""Functional + security tests. Run with:  .venv\\Scripts\\python.exe test_app.py"""
import base64
import io

import numpy as np
from PIL import Image

import app as app_module
import stego

BASE = "http://127.0.0.1:5000"
client = app_module.app.test_client()


def png_bytes(w=300, h=200):
    img = Image.fromarray(np.random.randint(0, 256, (h, w, 3), dtype=np.uint8))
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def post(path, data, headers=None):
    return client.post(BASE + path, data=data, headers=headers or {})


def check(name, cond):
    assert cond, name
    print("PASS", name)


# ---- core functionality
msg = "Hello, secret world! 🔐 <script>alert(1)</script>"
img = Image.open(io.BytesIO(png_bytes()))
check("round trip, no password", stego.decode(stego.encode(img, msg)) == msg)
enc = stego.encode(img, msg, "pw")
check("round trip, password", stego.decode(enc, "pw") == msg)
for pw in ("", "wrong"):
    try:
        stego.decode(enc, pw)
        check(f"rejects password {pw!r}", False)
    except stego.StegoError:
        check(f"rejects password {pw!r}", True)

r = post("/api/encode", {"image": (io.BytesIO(png_bytes()), "a.png"), "message": msg, "password": "pw"})
out = base64.b64decode(r.get_json()["image"].split(",")[1])
r = post("/api/decode", {"image": (io.BytesIO(out), "b.png"), "password": "pw"})
check("API round trip", r.get_json()["message"] == msg)

# ---- security headers
r = client.get(BASE + "/")
h = r.headers
check("CSP forbids inline script", "script-src 'self'" in h["Content-Security-Policy"]
      and "unsafe-inline" not in h["Content-Security-Policy"])
check("no inline <script> in page", b"<script>" not in r.data)
check("X-Frame-Options DENY", h["X-Frame-Options"] == "DENY")
check("nosniff", h["X-Content-Type-Options"] == "nosniff")
check("no-store", h["Cache-Control"] == "no-store")

# ---- host / origin protection
check("DNS rebinding host rejected", client.get("http://evil.example:5000/").status_code == 400)
r = post("/api/decode", {"image": (io.BytesIO(out), "b.png")}, {"Origin": "https://evil.example"})
check("cross-origin POST rejected", r.status_code == 403)
r = post("/api/decode", {"image": (io.BytesIO(out), "b.png")}, {"Sec-Fetch-Site": "cross-site"})
check("cross-site fetch rejected", r.status_code == 403)
r = post("/api/decode", {"image": (io.BytesIO(out), "b.png"), "password": "pw"}, {"Origin": BASE})
check("same-origin POST allowed", r.status_code == 200)

# ---- malicious uploads
r = post("/api/decode", {"image": (io.BytesIO(b"not an image at all"), "x.png")})
check("garbage file rejected cleanly", r.status_code == 400)
bomb = io.BytesIO()
Image.new("1", (10_000, 10_000)).save(bomb, "PNG")  # 100 MP, but tiny on disk
r = post("/api/decode", {"image": (io.BytesIO(bomb.getvalue()), "bomb.png")})
check(f"decompression bomb rejected ({len(bomb.getvalue())} bytes on disk)", r.status_code == 400)
r = post("/api/decode", {"image": (io.BytesIO(b"0" * (26 * 1024 * 1024)), "big.png")})
check("oversized upload rejected", r.status_code == 413)
r = post("/api/decode", {"image": (io.BytesIO(out), "b.png"), "password": "x" * 2000})
check("overlong password rejected", r.status_code == 400)
r = client.get(BASE + "/nope")
check("404 returns 404, no stack trace", r.status_code == 404 and b"Traceback" not in r.data)

# ---- metadata stripping
exif = Image.Exif()
exif[0x010F] = "SecretCameraMaker"
src = io.BytesIO()
Image.open(io.BytesIO(png_bytes())).save(src, "PNG", exif=exif)
r = post("/api/encode", {"image": (io.BytesIO(src.getvalue()), "a.png"), "message": "x"})
outb = base64.b64decode(r.get_json()["image"].split(",")[1])
check("EXIF not carried into output", b"SecretCameraMaker" not in outb)

# ---- covert (password) mode: undetectability
cover = Image.open(io.BytesIO(png_bytes(400, 300)))
cover_px = np.array(cover).astype(int)
covert = stego.encode(cover, "meet at noon", "correct horse")
covert_px = np.array(covert).astype(int)

lsb_start = np.packbits(covert_px.reshape(-1)[:64] & 1).tobytes()
check("no STG1 signature in covert image", b"STG1" not in lsb_start)
check("no STG1 signature anywhere in LSB stream",
      b"STG1" not in np.packbits(covert_px.reshape(-1) & 1).tobytes())

errors = set()
for im, pw in ((cover, ""), (cover, "correct horse"), (covert, ""), (covert, "wrong guess")):
    try:
        stego.decode(im, pw)
        errors.add("DECODED?!")
    except stego.StegoError as e:
        errors.add(str(e))
check("clean image / no password / wrong password all give the same error", len(errors) == 1)

diff = covert_px - cover_px
changed = np.argwhere(np.any(diff != 0, axis=2))
h, w = cover_px.shape[:2]
quadrants = {(int(y >= h // 2), int(x >= w // 2)) for y, x in changed}
check("changes scattered across the whole image (not sequential)",
      len(quadrants) == 4 and changed[:, 0].max() > h * 0.9)
check("every change is exactly +/-1", set(np.unique(diff)) <= {-1, 0, 1})
check("LSB matching used (both +1 and -1 changes occur)", (diff == 1).any() and (diff == -1).any())
check("covert round trip", stego.decode(covert, "correct horse") == "meet at noon")

r = post("/api/capacity", {"image": (io.BytesIO(png_bytes(400, 300)), "a.png")})
cap = r.get_json()
check("capacity reports both modes", 0 < cap["covert_capacity"] < cap["capacity"])
big = "x" * cap["covert_capacity"]
check("covert mode fills its full capacity", stego.decode(stego.encode(cover, big, "pw"), "pw") == big)
try:
    stego.encode(cover, big + "x", "pw")
    check("covert over-capacity rejected", False)
except stego.StegoError:
    check("covert over-capacity rejected", True)

# ---- images made by the first version still decode
import os, struct
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
salt = os.urandom(16)
key = base64.urlsafe_b64encode(PBKDF2HMAC(hashes.SHA256(), 32, salt, 390_000).derive(b"old"))
payload = salt + Fernet(key).encrypt("legacy message".encode())
data = b"STG1\x01" + struct.pack(">I", len(payload)) + payload
flat = np.array(cover).reshape(-1)
bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
flat[: bits.size] = (flat[: bits.size] & 0xFE) | bits
legacy = Image.fromarray(flat.reshape(np.array(cover).shape))
check("legacy v1 encrypted image still decodes", stego.decode(legacy, "old") == "legacy message")

print("\nALL TESTS PASSED")
