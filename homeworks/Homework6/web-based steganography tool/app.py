import base64
import io
import logging

from flask import Flask, abort, jsonify, render_template, request
from PIL import Image, UnidentifiedImageError
from werkzeug.exceptions import HTTPException

import stego

HOST = "127.0.0.1"
PORT = 5000

# Only these Host / Origin values are accepted. Blocks DNS-rebinding attacks and
# stops other websites open in your browser from silently calling this API.
ALLOWED_HOSTS = {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}
ALLOWED_ORIGINS = {f"http://{h}" for h in ALLOWED_HOSTS}

# Limits that stop a single upload from exhausting memory/CPU.
MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # 25 MB
MAX_PIXELS = 40_000_000  # ~40 megapixels (e.g. 8000x5000)
MAX_PASSWORD_LEN = 1024

Image.MAX_IMAGE_PIXELS = MAX_PIXELS  # Pillow's own decompression-bomb guard
ALLOWED_FORMATS = {"PNG", "JPEG", "BMP", "GIF", "TIFF", "WEBP"}

app = Flask(__name__)
app.config.update(
    MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
    MAX_FORM_MEMORY_SIZE=2 * 1024 * 1024,  # cap on the text fields
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------- request guards
@app.before_request
def check_host_and_origin():
    if request.host not in ALLOWED_HOSTS:
        abort(400)
    if request.method == "POST":
        origin = request.headers.get("Origin")
        if origin is not None and origin not in ALLOWED_ORIGINS:
            abort(403)
        if request.headers.get("Sec-Fetch-Site") not in (None, "same-origin", "none"):
            abort(403)


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; "
        "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    # Responses can contain secret messages: never cache them.
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------------------------------------------------------------- helpers
def _read_image():
    file = request.files.get("image")
    if not file or not file.filename:
        raise stego.StegoError("Please choose an image.")
    try:
        img = Image.open(file.stream)  # lazy: reads only the header
        if img.format not in ALLOWED_FORMATS:
            raise stego.StegoError("Unsupported image format.")
        if img.width * img.height > MAX_PIXELS:
            raise stego.StegoError("Image dimensions are too large (max ~40 megapixels).")
        img.load()
        return img
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError):
        raise stego.StegoError("That file isn't a supported image.")


def _password():
    pw = request.form.get("password", "")
    if len(pw) > MAX_PASSWORD_LEN:
        raise stego.StegoError("Password is too long.")
    return pw


# ---------------------------------------------------------------- error handlers
@app.errorhandler(stego.StegoError)
def handle_stego_error(err):
    return jsonify(error=str(err)), 400


@app.errorhandler(400)
def bad_request(_):
    return jsonify(error="Bad request."), 400


@app.errorhandler(403)
def forbidden(_):
    return jsonify(error="Cross-site requests are not allowed."), 403


@app.errorhandler(413)
def too_large(_):
    return jsonify(error="Upload is too large (max 25 MB)."), 413


@app.errorhandler(Exception)
def unexpected(err):
    if isinstance(err, HTTPException):  # 404, 405, etc.
        return jsonify(error=err.name), err.code
    # Log details locally, but never send stack traces to the client.
    log.exception("Unhandled error")
    return jsonify(error="Internal error."), 500


# ---------------------------------------------------------------- routes
@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/capacity")
def capacity():
    img = _read_image()
    return jsonify(
        capacity=max(stego.capacity_bytes(img), 0),
        covert_capacity=max(stego.covert_capacity_bytes(img), 0),
        width=img.width,
        height=img.height,
    )


@app.post("/api/encode")
def encode():
    img = _read_image()
    message = request.form.get("message", "")
    if not message:
        raise stego.StegoError("Please enter a message to hide.")
    out = stego.encode(img, message, _password())
    buf = io.BytesIO()
    # Lossless PNG (JPEG would destroy the hidden bits). The image is rebuilt from raw
    # pixels, so EXIF/GPS and other metadata from the cover image are not carried over.
    out.save(buf, format="PNG")
    return jsonify(image="data:image/png;base64," + base64.b64encode(buf.getvalue()).decode())


@app.post("/api/decode")
def decode():
    img = _read_image()
    return jsonify(message=stego.decode(img, _password()))


if __name__ == "__main__":
    # Bound to 127.0.0.1 only: not reachable from other devices on the network.
    # debug=False: the Werkzeug debugger allows remote code execution and must stay off.
    app.run(host=HOST, port=PORT, debug=False)
