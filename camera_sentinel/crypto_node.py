"""Encryption + authentication for camera/laptop node -> server ingest.
Design (matches the Secure Camera Network Analytics report):
  * Each node has a 32-byte master key (shared out-of-band, shown once at registration).
  * Two subkeys are derived (never the raw master on the wire):
        enc_key  = HMAC-SHA256(master, b"enc")      -> AES-256-GCM confidentiality
        auth_key = HMAC-SHA256(master, b"mac")      -> HMAC token authentication
  * Auth token is time-bound + single-use (nonce replay cache), so a captured token
    cannot be replayed to impersonate a node.
  * Payload is end-to-end AES-256-GCM encrypted; node_id is bound as associated data.
Requires: cryptography (pip). HMAC/compare via stdlib.
"""
import os, time, json, hmac, hashlib, threading, secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TOKEN_WINDOW = 30           # seconds a token stays valid
_used = {}                  # nonce -> expiry ts (single-use replay cache)
_lock = threading.Lock()

def new_master_key():
    return secrets.token_hex(32)           # 32 bytes -> 64 hex chars

def _subkeys(master_hex):
    master = bytes.fromhex(master_hex)
    enc = hmac.new(master, b"enc", hashlib.sha256).digest()      # 32 bytes
    mac = hmac.new(master, b"mac", hashlib.sha256).digest()      # 32 bytes
    return enc, mac

def make_token(node_id, master_hex, ts=None, nonce=None):
    """Client-side: build a time-bound single-use auth token."""
    _, mac = _subkeys(master_hex)
    ts = int(ts or time.time())
    nonce = nonce or secrets.token_hex(16)
    msg = f"{node_id}.{ts}.{nonce}".encode()
    tok = hmac.new(mac, msg, hashlib.sha256).hexdigest()
    return {"ts": ts, "nonce": nonce, "token": tok}

def verify_token(node_id, master_hex, ts, nonce, token):
    """Server-side: validate window, HMAC, and single-use."""
    now = time.time()
    try:
        ts = int(ts)
    except Exception:
        return False, "bad timestamp"
    if abs(now - ts) > TOKEN_WINDOW:
        return False, "token expired / clock skew"
    _, mac = _subkeys(master_hex)
    msg = f"{node_id}.{ts}.{nonce}".encode()
    expect = hmac.new(mac, msg, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expect, str(token)):
        return False, "bad token (authentication failed)"
    with _lock:
        # prune expired nonces
        for k in [k for k, v in _used.items() if v < now]:
            _used.pop(k, None)
        if nonce in _used:
            return False, "token replay detected (single-use)"
        _used[nonce] = now + TOKEN_WINDOW
    return True, "ok"

def encrypt_payload(node_id, master_hex, plaintext_bytes):
    """Client-side: AES-256-GCM encrypt, node_id bound as associated data."""
    enc, _ = _subkeys(master_hex)
    aes_nonce = os.urandom(12)
    ct = AESGCM(enc).encrypt(aes_nonce, plaintext_bytes, node_id.encode())
    return {"aes_nonce": aes_nonce.hex(), "ciphertext": ct.hex()}

def decrypt_payload(node_id, master_hex, aes_nonce_hex, ciphertext_hex):
    """Server-side: AES-256-GCM decrypt + authenticate."""
    enc, _ = _subkeys(master_hex)
    pt = AESGCM(enc).decrypt(bytes.fromhex(aes_nonce_hex),
                             bytes.fromhex(ciphertext_hex), node_id.encode())
    return pt
