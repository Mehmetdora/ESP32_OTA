"""ESP32 HTTP OTA sunucusu (Flask).

Calistirma:
    source venv/bin/activate
    python app.py
"""
import hashlib
import hmac
import json
import os
import time
from pathlib import Path

from flask import (Flask, abort, flash, jsonify, redirect, render_template,
                   request, send_file, url_for)

# ---------------- AYARLAR (ortam degiskeniyle de verilebilir) ----------------
ADMIN_PASSWORD = os.environ.get("OTA_ADMIN_PASSWORD", "admin")      # web sayfasina yukleme sifresi
DEVICE_TOKEN = os.environ.get("OTA_DEVICE_TOKEN", "esp32s3")  # ESP32 ile ayni olmali
PORT = int(os.environ.get("OTA_PORT", "5000"))
# -----------------------------------------------------------------------------

BASE = Path(__file__).resolve().parent
FW_DIR = BASE / "firmware"
FW_DIR.mkdir(exist_ok=True)
META_FILE = FW_DIR / "meta.json"

app = Flask(__name__)
app.secret_key = os.environ.get("OTA_SECRET_KEY", "dev-secret-degistir")
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024  # en fazla 8 MB


def load_meta():
    if META_FILE.exists():
        return json.loads(META_FILE.read_text())
    return {"releases": []}


def save_meta(meta):
    META_FILE.write_text(json.dumps(meta, indent=2))


def latest_release():
    rel = load_meta()["releases"]
    return rel[-1] if rel else None


def token_ok():
    return hmac.compare_digest(request.args.get("token", ""), DEVICE_TOKEN)


@app.route("/")
def index():
    meta = load_meta()
    return render_template("index.html",
                           latest=latest_release(),
                           releases=list(reversed(meta["releases"])))


@app.route("/upload", methods=["POST"])
def upload():
    if not hmac.compare_digest(request.form.get("password", ""), ADMIN_PASSWORD):
        flash("Yonetici sifresi yanlis.", "err")
        return redirect(url_for("index"))

    f = request.files.get("firmware")
    if not f or not f.filename.lower().endswith(".bin"):
        flash("Gecerli bir .bin dosyasi sec.", "err")
        return redirect(url_for("index"))

    meta = load_meta()
    cur = meta["releases"][-1]["version"] if meta["releases"] else 0
    ver_txt = request.form.get("version", "").strip()
    version = int(ver_txt) if ver_txt.isdigit() else cur + 1
    if version <= cur:
        flash(f"Surum numarasi mevcut surumden ({cur}) buyuk olmali.", "err")
        return redirect(url_for("index"))

    data = f.read()
    if len(data) < 100_000 or data[0] != 0xE9:
        flash("Bu dosya ESP32 uygulama .bin dosyasina benzemiyor "
              "(merged/bootloader degil, 'xxx.ino.bin' olmali).", "err")
        return redirect(url_for("index"))

    fname = f"fw_v{version}.bin"
    (FW_DIR / fname).write_bytes(data)
    meta["releases"].append({
        "version": version,
        "file": fname,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "uploaded": time.strftime("%Y-%m-%d %H:%M:%S"),
    })
    save_meta(meta)
    flash(f"Surum {version} yuklendi. ESP32 bir sonraki kontrolde guncellenecek.", "ok")
    return redirect(url_for("index"))


# ----------------------------- ESP32 API'si ---------------------------------
@app.route("/api/version")
def api_version():
    """Sadece surum numarasini duz metin olarak dondurur (ESP32 icin kolay)."""
    if not token_ok():
        abort(401)
    rel = latest_release()
    return str(rel["version"] if rel else 0), 200, {"Content-Type": "text/plain"}


@app.route("/api/info")
def api_info():
    if not token_ok():
        abort(401)
    return jsonify(latest_release() or {})


@app.route("/firmware.bin")
def firmware():
    if not token_ok():
        abort(401)
    rel = latest_release()
    if not rel:
        abort(404)
    return send_file(FW_DIR / rel["file"], mimetype="application/octet-stream")


if __name__ == "__main__":
    print(f"Yonetici sifresi : {ADMIN_PASSWORD}")
    print(f"Cihaz token'i    : {DEVICE_TOKEN}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
