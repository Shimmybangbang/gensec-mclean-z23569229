"""Image steganography: hide/reveal text in the least-significant bits of RGB pixels.

Two formats are written:

* **Plain** (no password): sequential LSB replacement, prefixed with a "STG1" header.
      MAGIC "STG1" | FLAGS (1 byte, 0) | LENGTH (4 bytes, big-endian) | UTF-8 text
  Offers no secrecy. Anyone can find and read it.

* **Covert** (with password): no signature or fixed layout. The bits look like noise.
      master   = PBKDF2-HMAC-SHA256(password, fixed app salt, 600k iterations)
      keys     = HKDF(master) -> position key, length mask, encryption key
      stream   = (LENGTH xor mask) (4 bytes) | NONCE (12) | AES-256-GCM(text) + TAG (16)
  Bits are written to pseudo-random channel positions chosen by a ChaCha20 keystream
  keyed from the password, using LSB *matching* (random +/-1) instead of LSB replacement,
  which defeats the classic chi-square / pairs-of-values attack.
  Without the password the bits cannot be located, so nobody can tell whether
  the image contains a message. A wrong password gives the same error as "no message".

Images written by the first version (STG1 header with FLAGS bit 0 set, Fernet) can still be read.
"""
import base64
import os
import struct

import numpy as np
from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image

# ---- plain / legacy format
MAGIC = b"STG1"
HEADER_LEN = len(MAGIC) + 1 + 4
FLAG_ENCRYPTED = 0x01
SALT_LEN = 16

# ---- covert format
KDF_ITERATIONS = 600_000  # OWASP recommendation for PBKDF2-HMAC-SHA256
KDF_SALT = b"StegoStudio/v2/master-key"
NONCE_LEN = 12
TAG_LEN = 16
COVERT_OVERHEAD = 4 + NONCE_LEN + TAG_LEN
# Use at most half the channels: keeps the embedding sparse (harder to detect)
# and keeps position generation fast.
COVERT_MAX_FRACTION = 0.5
_POS_BATCH = 1 << 16

NOT_FOUND = "No hidden message found, or the password is wrong."


class StegoError(Exception):
    pass


def _channels(image: Image.Image) -> np.ndarray:
    return np.array(image.convert("RGB"), dtype=np.uint8)


# ======================================================================= capacity
def capacity_bytes(image: Image.Image) -> int:
    """Max message bytes without a password (sequential, 1 bit per channel)."""
    w, h = image.size
    return (w * h * 3) // 8 - HEADER_LEN


def covert_capacity_bytes(image: Image.Image) -> int:
    """Max message bytes with a password (scattered, uses at most half the channels)."""
    w, h = image.size
    return int(w * h * 3 * COVERT_MAX_FRACTION) // 8 - COVERT_OVERHEAD


# ======================================================================= key handling
class _Keys:
    def __init__(self, password: str):
        master = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=KDF_SALT, iterations=KDF_ITERATIONS
        ).derive(password.encode("utf-8"))

        def sub(info: bytes, length: int) -> bytes:
            return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(master)

        self.position = sub(b"positions", 32)
        self.length_mask = sub(b"length-mask", 4)
        self.encryption = sub(b"encryption", 32)


def _positions(key: bytes, n: int, k: int) -> np.ndarray:
    """First k distinct pseudo-random indices in [0, n), derived from `key`.

    Uses a ChaCha20 keystream (stable forever, unlike numpy's RNG streams) and is
    prefix-consistent: the first k positions are the same no matter how many are requested.
    """
    if k > n:
        raise StegoError("Image is too small.")
    stream = Cipher(algorithms.ChaCha20(key, b"\0" * 16), mode=None).encryptor()
    seen = np.zeros(n, dtype=bool)
    chunks, total = [], 0
    while total < k:
        raw = np.frombuffer(stream.update(b"\0" * (_POS_BATCH * 8)), dtype="<u8")
        draw = (raw % np.uint64(n)).astype(np.int64)
        _, first = np.unique(draw, return_index=True)  # de-dupe within batch, keep order
        cand = draw[np.sort(first)]
        cand = cand[~seen[cand]]
        seen[cand] = True
        chunks.append(cand)
        total += cand.size
    return np.concatenate(chunks)[:k]


def _lsb_match(values: np.ndarray, bits: np.ndarray) -> np.ndarray:
    """Set LSBs to `bits` by randomly adding or subtracting 1 where they differ."""
    v = values.astype(np.int16)
    differ = (v & 1) != bits
    step = np.where(np.frombuffer(os.urandom(v.size), dtype=np.uint8) & 1, 1, -1)
    step = np.where(v == 0, 1, np.where(v == 255, -1, step))
    return np.where(differ, v + step, v).astype(np.uint8)


# ======================================================================= encode
def encode(image: Image.Image, message: str, password: str = "") -> Image.Image:
    text = message.encode("utf-8")
    pixels = _channels(image)
    flat = pixels.reshape(-1)

    if password:
        cap = covert_capacity_bytes(image)
        if len(text) > cap:
            raise _too_large(len(text), cap)
        keys = _Keys(password)
        masked_len = bytes(a ^ b for a, b in zip(struct.pack(">I", len(text)), keys.length_mask))
        nonce = os.urandom(NONCE_LEN)
        ct = AESGCM(keys.encryption).encrypt(nonce, text, masked_len)
        bits = np.unpackbits(np.frombuffer(masked_len + nonce + ct, dtype=np.uint8))
        pos = _positions(keys.position, flat.size, bits.size)
        flat[pos] = _lsb_match(flat[pos], bits)
    else:
        cap = capacity_bytes(image)
        if len(text) > cap:
            raise _too_large(len(text), cap)
        data = MAGIC + b"\0" + struct.pack(">I", len(text)) + text
        bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
        flat[: bits.size] = (flat[: bits.size] & 0xFE) | bits

    return Image.fromarray(flat.reshape(pixels.shape), "RGB")


def _too_large(need: int, cap: int) -> StegoError:
    return StegoError(
        f"Message too large: needs {need} bytes, image holds {max(cap, 0)} bytes. "
        "Use a larger image or a shorter message."
    )


# ======================================================================= decode
def decode(image: Image.Image, password: str = "") -> str:
    flat = _channels(image).reshape(-1)
    if password:
        try:
            return _decode_covert(flat, password)
        except StegoError:
            pass  # fall through: maybe a plain or legacy image
    return _decode_header(flat, password)


def _decode_covert(flat: np.ndarray, password: str) -> str:
    keys = _Keys(password)
    max_bits = int(flat.size * COVERT_MAX_FRACTION)
    head_pos = _positions(keys.position, flat.size, 32)
    masked_len = np.packbits(flat[head_pos] & 1).tobytes()
    (length,) = struct.unpack(">I", bytes(a ^ b for a, b in zip(masked_len, keys.length_mask)))
    total_bits = (COVERT_OVERHEAD + length) * 8
    if total_bits > max_bits:
        raise StegoError(NOT_FOUND)
    pos = _positions(keys.position, flat.size, total_bits)
    data = np.packbits(flat[pos] & 1).tobytes()
    nonce, ct = data[4 : 4 + NONCE_LEN], data[4 + NONCE_LEN :]
    try:
        return AESGCM(keys.encryption).decrypt(nonce, ct, masked_len).decode("utf-8")
    except (InvalidTag, UnicodeDecodeError):
        raise StegoError(NOT_FOUND)


def _read_bytes(flat: np.ndarray, start_byte: int, count: int) -> bytes:
    start, end = start_byte * 8, (start_byte + count) * 8
    if end > flat.size:
        raise StegoError(NOT_FOUND)
    return np.packbits(flat[start:end] & 1).tobytes()


def _decode_header(flat: np.ndarray, password: str) -> str:
    header = _read_bytes(flat, 0, HEADER_LEN)
    if header[: len(MAGIC)] != MAGIC:
        raise StegoError(NOT_FOUND)
    flags = header[len(MAGIC)]
    (length,) = struct.unpack(">I", header[len(MAGIC) + 1 :])
    payload = _read_bytes(flat, HEADER_LEN, length)

    if flags & FLAG_ENCRYPTED:  # legacy v1 password format
        if not password:
            raise StegoError("This message is password-protected. Enter the password to reveal it.")
        payload = _legacy_decrypt(payload, password)

    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        raise StegoError("Hidden data is corrupted or not text.")


def _legacy_decrypt(blob: bytes, password: str) -> bytes:
    salt, token = blob[:SALT_LEN], blob[SALT_LEN:]
    for iterations in (600_000, 390_000):
        key = base64.urlsafe_b64encode(
            PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
            .derive(password.encode("utf-8"))
        )
        try:
            return Fernet(key).decrypt(token)
        except InvalidToken:
            continue
    raise StegoError(NOT_FOUND)
