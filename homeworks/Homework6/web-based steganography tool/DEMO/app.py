"""Local web UI for the steganography tool.  Run:  python app.py  ->  http://127.0.0.1:5000"""
import base64

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge

import stego

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # 20 MB upload limit
stego.Image.MAX_IMAGE_PIXELS = 40_000_000  # guard against decompression bombs


def _uploaded_image() -> bytes:
    f = request.files.get("image")
    if not f or not f.filename:
        raise stego.StegoError("Choose an image file first.")
    return f.read()


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'"
    )
    return resp


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/capacity")
def api_capacity():
    try:
        return jsonify(capacity=stego.capacity(_uploaded_image()))
    except stego.StegoError as e:
        return jsonify(error=str(e)), 400


@app.post("/api/encode")
def api_encode():
    try:
        png = stego.encode(
            _uploaded_image(),
            request.form.get("message", ""),
            request.form.get("password", ""),
        )
    except stego.StegoError as e:
        return jsonify(error=str(e)), 400
    return jsonify(image="data:image/png;base64," + base64.b64encode(png).decode("ascii"))


@app.post("/api/decode")
def api_decode():
    try:
        msg = stego.decode(_uploaded_image(), request.form.get("password", ""))
    except stego.StegoError as e:
        return jsonify(error=str(e)), 400
    return jsonify(message=msg)


@app.errorhandler(RequestEntityTooLarge)
def too_large(_):
    return jsonify(error="File is too large (limit 20 MB)."), 413


if __name__ == "__main__":
    # 127.0.0.1 = only reachable from this computer. debug=False so the Werkzeug debugger is never exposed.
    app.run(host="127.0.0.1", port=5000, debug=False)
