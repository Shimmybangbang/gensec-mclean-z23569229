"""LSB image steganography: hide text in the least-significant bit of each RGB channel.

Stream layout written into the pixel LSBs (row by row, R, G, B order):

    MAGIC "SDM1" (4 bytes) | FLAGS (1 byte) | LENGTH (4 bytes, big-endian) | PAYLOAD

FLAGS bit 0 set -> PAYLOAD = SALT (16) | NONCE (12) | AES-256-GCM ciphertext + tag
                   key = PBKDF2-HMAC-SHA256(password, salt, 600_000 iterations)
FLAGS bit 0 clear -> PAYLOAD = UTF-8 text (no secrecy, only hidden).

Output is always PNG: lossy formats such as JPEG would destroy the hidden bits.
"""
import io
import os
import struct

import numpy as np
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image

MAGIC = b"SDM1"
HEADER_LEN = len(MAGIC) + 1 + 4
FLAG_ENCRYPTED = 0x01
SALT_LEN, NONCE_LEN = 16, 12
KDF_ITERATIONS = 600_000


class StegoError(ValueError):
    """User-facing error (bad image, message too long, wrong password, ...)."""


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=KDF_ITERATIONS)
    return kdf.derive(password.encode("utf-8"))


def _load_rgb(image_bytes: bytes) -> np.ndarray:
    try:
        img = Image.open(io.BytesIO(image_bytes))
        img.load()
    except Exception as exc:  # Pillow raises many different exception types
        raise StegoError("Could not read that file as an image.") from exc
    return np.array(img.convert("RGB"), dtype=np.uint8)


def capacity(image_bytes: bytes) -> int:
    """Maximum number of payload bytes (after the header) the image can hold."""
    pixels = _load_rgb(image_bytes)
    return pixels.size // 8 - HEADER_LEN


def encode(image_bytes: bytes, message: str, password: str = "") -> bytes:
    """Return PNG bytes of the cover image with `message` hidden in it."""
    if not message:
        raise StegoError("Message is empty.")
    payload = message.encode("utf-8")
    flags = 0
    if password:
        salt, nonce = os.urandom(SALT_LEN), os.urandom(NONCE_LEN)
        payload = salt + nonce + AESGCM(_derive_key(password, salt)).encrypt(nonce, payload, MAGIC)
        flags |= FLAG_ENCRYPTED

    stream = MAGIC + bytes([flags]) + struct.pack(">I", len(payload)) + payload
    pixels = _load_rgb(image_bytes)
    flat = pixels.reshape(-1)
    bits = np.unpackbits(np.frombuffer(stream, dtype=np.uint8))
    if bits.size > flat.size:
        raise StegoError(
            f"Message too long: needs {len(stream)} bytes, image holds {flat.size // 8} bytes. "
            "Use a larger image or a shorter message."
        )
    flat[: bits.size] = (flat[: bits.size] & 0xFE) | bits

    out = io.BytesIO()
    Image.fromarray(pixels, "RGB").save(out, format="PNG", optimize=True)
    return out.getvalue()


def _read_bytes(flat: np.ndarray, start: int, count: int) -> bytes:
    end = (start + count) * 8
    if end > flat.size:
        raise StegoError("No hidden message found in this image.")
    return np.packbits(flat[start * 8 : end] & 1).tobytes()


def decode(image_bytes: bytes, password: str = "") -> str:
    """Return the hidden message, or raise StegoError."""
    flat = _load_rgb(image_bytes).reshape(-1)
    header = _read_bytes(flat, 0, HEADER_LEN)
    if header[:4] != MAGIC:
        raise StegoError("No hidden message found in this image.")
    flags = header[4]
    (length,) = struct.unpack(">I", header[5:9])
    payload = _read_bytes(flat, HEADER_LEN, length)

    if flags & FLAG_ENCRYPTED:
        if not password:
            raise StegoError("This message is password-protected. Enter the password.")
        if length < SALT_LEN + NONCE_LEN + 16:
            raise StegoError("Hidden data is corrupted.")
        salt, nonce, ct = payload[:SALT_LEN], payload[SALT_LEN : SALT_LEN + NONCE_LEN], payload[SALT_LEN + NONCE_LEN :]
        try:
            payload = AESGCM(_derive_key(password, salt)).decrypt(nonce, ct, MAGIC)
        except InvalidTag:
            raise StegoError("Wrong password, or the image was modified.") from None

    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        raise StegoError("Hidden data is corrupted.") from None
