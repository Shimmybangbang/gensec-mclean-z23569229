# Steganography Tool (local web app)

Hide a text message inside an image, or reveal one, from a browser page served on your own machine.

## Run

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000. Stop with Ctrl+C.

## How it works

- **Hiding:** each bit of the message goes into the least-significant bit of one R, G or B value. That changes each color by at most 1/255, which you can't see.
- **Capacity:** 3 bits per pixel, so a 1920×1080 image holds about 777 KB.
- **Password (optional):** the message is encrypted with AES-256-GCM. The key comes from PBKDF2-HMAC-SHA256 with 600,000 iterations and a random salt. A wrong password or an edited image is detected.
- **Output is always PNG.** JPEG compression or resizing destroys the hidden bits.

## Files

- `stego.py`: encode/decode logic
- `app.py`: Flask server, bound to 127.0.0.1 only, 20 MB upload limit
- `templates/index.html`: the page

## Limits

Plain LSB embedding can be detected with statistical tests such as chi-square analysis. A password keeps the content secret, but not the fact that a message exists.
