#!/usr/bin/env python3
"""Muse-Link relay server (MVP).

Fire-and-forget store-and-forward relay, design rounds 3 to 6:
- Pure PGP. The server holds public identities only, verifies every
  message signature at ingest against the sender's registered public
  key, and rejects failures. It never sees an agent private key and
  never reads message bodies (bodies are end-to-end encrypted to the
  recipient inside the inner PGP layer).
- State lives in one small SQLite DB: identities, bootstrap tokens,
  and a message state ledger. Ciphertext payloads are files in a
  per-recipient queue directory, named by message ID.
- HTTP is the control frame (register, send, fetch, ack, agents);
  data travels as PGP messages inside the HTTP bodies.

Run:  python3 server.py [--host 127.0.0.1] [--port 8931] [--data-dir DIR]
Env:  MUSELINK_DATA_DIR, MUSELINK_PURGE_GRACE_SECONDS (default 5)
"""

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))
import gpgutil  # noqa: E402

FETCH_WINDOW_SECONDS = 300
MAX_BODY_BYTES = 256 * 1024

SCHEMA = """
CREATE TABLE IF NOT EXISTS identities (
    handle TEXT PRIMARY KEY,
    agent_name TEXT NOT NULL,
    owner_name TEXT NOT NULL,
    platform TEXT NOT NULL,
    protocol_version TEXT NOT NULL,
    capabilities TEXT NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
);
CREATE TABLE IF NOT EXISTS bootstrap_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    handle TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    message_id TEXT PRIMARY KEY,
    from_fp TEXT NOT NULL,
    to_fp TEXT NOT NULL,
    thread_id TEXT,
    state TEXT NOT NULL,
    queued_at INTEGER NOT NULL,
    fetched_at INTEGER,
    acked_at INTEGER,
    purged_at INTEGER,
    error TEXT,
    blob_path TEXT
);
"""


def now():
    return int(time.time())


def parse_header_block(text):
    """Parse 'Key: Value' lines up to the first blank line.

    Returns (headers_dict, remainder_str).
    """
    headers = {}
    lines = text.split("\n")
    idx = 0
    for i, line in enumerate(lines):
        if line.strip() == "":
            idx = i + 1
            break
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    else:
        idx = len(lines)
    return headers, "\n".join(lines[idx:])


def extract_pgp_block(text):
    m = re.search(r"-----BEGIN PGP MESSAGE-----.*?-----END PGP MESSAGE-----",
                  text, re.DOTALL)
    return m.group(0) if m else None


class Relay:
    def __init__(self, data_dir, purge_grace=None):
        self.data_dir = data_dir
        self.gnupg = os.path.join(data_dir, "gnupg")
        self.queue_dir = os.path.join(data_dir, "queue")
        self.db_path = os.path.join(data_dir, "relay.db")
        self.purge_grace = purge_grace if purge_grace is not None else int(
            os.environ.get("MUSELINK_PURGE_GRACE_SECONDS", "5"))
        # RLock, not Lock: handlers call identity helpers (which take the
        # lock) from inside locked sections. A plain Lock deadlocks there.
        self.lock = threading.RLock()
        os.makedirs(self.queue_dir, exist_ok=True)
        gpgutil.ensure_home(self.gnupg)
        self.db = sqlite3.connect(self.db_path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        with self.lock:
            self.db.executescript(SCHEMA)
            self.db.commit()
        self.server_fp = self._ensure_server_key()

    def _ensure_server_key(self):
        fps = [fp for fp in gpgutil.list_fingerprints(self.gnupg)
               if gpgutil.has_secret_key(self.gnupg, fp)]
        if fps:
            return fps[0]
        return gpgutil.generate_key(
            self.gnupg, "Muse-Link Relay",
            "muse-link relay server key", "relay@muse.link")

    # ---- identity helpers -------------------------------------------------
    def identity_by_fp(self, fp):
        with self.lock:
            row = self.db.execute(
                "SELECT * FROM identities WHERE fingerprint=?", (fp,)).fetchone()
        return dict(row) if row else None

    def identity_by_handle(self, handle):
        with self.lock:
            row = self.db.execute(
                "SELECT * FROM identities WHERE handle=?", (handle,)).fetchone()
        return dict(row) if row else None

    def all_identities(self):
        with self.lock:
            rows = self.db.execute("SELECT * FROM identities ORDER BY handle").fetchall()
        return [dict(r) for r in rows]

    # ---- registration -----------------------------------------------------
    def handle_register(self, armor):
        """Registration: PGP message encrypted to the server key containing
        the bootstrap JSON and the sender's new public key."""
        try:
            plain, validsig = gpgutil.decrypt(self.gnupg, armor)
        except gpgutil.GpgError as exc:
            return 400, {"error": "registration message could not be decrypted: " + str(exc)}
        text = plain.decode("utf-8", "replace")
        # Payload layout: bootstrap JSON, blank line, armored public key.
        json_part, _, rest = text.partition("\n\n")
        pubkey = None
        m = re.search(r"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----",
                      text, re.DOTALL)
        if m:
            pubkey = m.group(0)
        try:
            boot = json.loads(json_part.strip())
        except ValueError:
            return 400, {"error": "bootstrap JSON missing or invalid inside registration"}
        required = ["bootstrap_token", "agent_name", "owner_name", "handle",
                    "platform", "relay", "protocol_version", "capabilities"]
        missing = [k for k in required if k not in boot]
        if missing:
            return 400, {"error": "bootstrap JSON missing fields: " + ", ".join(missing)}
        if not pubkey:
            return 400, {"error": "no public key block inside registration"}
        try:
            new_fp = gpgutil.fingerprint_of_armor(pubkey)
        except gpgutil.GpgError:
            return 400, {"error": "public key block unreadable"}
        # The signer key is not in our keyring yet, so the first decrypt
        # could not produce a VALIDSIG. Import the enclosed key (it grants
        # nothing on its own; registration below is what activates it) and
        # decrypt again to check the signature properly.
        gpgutil.import_public(self.gnupg, pubkey)
        try:
            _, validsig = gpgutil.decrypt(self.gnupg, armor)
        except gpgutil.GpgError as exc:
            return 400, {"error": "registration re-decrypt failed: " + str(exc)}
        if validsig != new_fp:
            return 403, {"error": "registration not signed by the key it registers"}
        handle = boot["handle"]
        token_hash = hashlib.sha256(boot["bootstrap_token"].encode()).hexdigest()
        with self.lock:
            tok = self.db.execute(
                "SELECT * FROM bootstrap_tokens WHERE token_hash=?", (token_hash,)).fetchone()
            if tok is None:
                return 403, {"error": "unknown bootstrap token"}
            if tok["used_at"] is not None:
                return 403, {"error": "bootstrap token already used"}
            if tok["expires_at"] < now():
                return 403, {"error": "bootstrap token expired"}
            if tok["handle"] != handle:
                return 403, {"error": "bootstrap token is bound to a different handle"}
            if self.identity_by_handle(handle):
                return 409, {"error": "handle already registered"}
            if self.identity_by_fp(new_fp):
                return 409, {"error": "key already registered"}
            self.db.execute(
                "INSERT INTO identities (handle, agent_name, owner_name, platform,"
                " protocol_version, capabilities, fingerprint, public_key, status, created_at)"
                " VALUES (?,?,?,?,?,?,?,?, 'active', ?)",
                (handle, boot["agent_name"], boot["owner_name"], boot["platform"],
                 boot["protocol_version"], json.dumps(boot["capabilities"]),
                 new_fp, pubkey, now()))
            self.db.execute("UPDATE bootstrap_tokens SET used_at=? WHERE id=?",
                            (now(), tok["id"]))
            self.db.commit()
        gpgutil.import_public(self.gnupg, pubkey)
        return 200, {"status": "ok", "handle": handle, "fingerprint": new_fp,
                     "server_fingerprint": self.server_fp}

    # ---- signed client requests (fetch / ack / agents) --------------------
    def verify_request(self, armor, expected_action):
        """Verify a clearsigned, otherwise-empty client request.

        Returns (headers, identity) or raises ValueError with a reason.
        """
        try:
            text, validsig = gpgutil.verify_clearsigned(self.gnupg, armor)
        except gpgutil.GpgError as exc:
            raise ValueError("request signature invalid: " + str(exc))
        headers, _ = parse_header_block(text)
        if headers.get("Muse-Link-Request") != expected_action:
            raise ValueError("request action mismatch")
        if headers.get("From-Fingerprint") != validsig:
            raise ValueError("request fingerprint does not match signature")
        try:
            ts = int(headers.get("Timestamp", "0"))
        except ValueError:
            raise ValueError("request timestamp malformed")
        if abs(now() - ts) > FETCH_WINDOW_SECONDS:
            raise ValueError("request timestamp outside 5 minute window (stale)")
        ident = self.identity_by_fp(validsig)
        if ident is None:
            raise ValueError("request signer is not registered")
        if ident["status"] != "active":
            raise ValueError("request signer is revoked")
        return headers, ident

    def handle_agents(self, armor):
        try:
            _, ident = self.verify_request(armor, "agents")
        except ValueError as exc:
            return 403, {"error": str(exc)}
        agents = [{
            "handle": i["handle"], "agent_name": i["agent_name"],
            "owner_name": i["owner_name"], "platform": i["platform"],
            "fingerprint": i["fingerprint"], "status": i["status"],
            "public_key": i["public_key"],
        } for i in self.all_identities()]
        return 200, {"agents": agents, "server_fingerprint": self.server_fp,
                     "requested_by": ident["handle"]}

    # ---- message ingest ---------------------------------------------------
    def handle_send(self, armor):
        try:
            plain, validsig = gpgutil.decrypt(self.gnupg, armor)
        except gpgutil.GpgError as exc:
            return 400, {"error": "outer message could not be decrypted: " + str(exc)}
        text = plain.decode("utf-8", "replace")
        headers, rest = parse_header_block(text)
        from_fp = headers.get("From-Fingerprint", "")
        to_fp = headers.get("To-Fingerprint", "")
        message_id = headers.get("Message-ID", "")
        thread_id = headers.get("Thread-ID", "")
        sender = self.identity_by_fp(from_fp)
        if sender is None:
            self._ledger_error(message_id, from_fp, to_fp, thread_id,
                               "sender key not registered")
            return 403, {"error": "sender key is not registered"}
        if sender["status"] != "active":
            return 403, {"error": "sender is revoked"}
        if validsig is None or validsig != from_fp:
            self._ledger_error(message_id, from_fp, to_fp, thread_id,
                               "outer signature missing or does not match From-Fingerprint")
            return 403, {"error": "outer signature does not verify as the claimed sender"}
        recipient = self.identity_by_fp(to_fp)
        if recipient is None:
            return 404, {"error": "recipient fingerprint is not registered"}
        if recipient["status"] != "active":
            return 403, {"error": "recipient is revoked"}
        inner = extract_pgp_block(rest)
        if not inner:
            return 400, {"error": "no inner PGP message found in outer payload"}
        if not message_id:
            message_id = str(uuid.uuid4())
        # Forwarding leg: fresh outer layer, signed by the server,
        # encrypted to the recipient, inner message carried untouched.
        fwd_headers = (
            "Muse-Link-Outer: 1\n"
            "Kind: relayed\n"
            f"Relayed-By: {self.server_fp}\n"
            f"From-Fingerprint: {from_fp}\n"
            f"From-Handle: {sender['handle']}\n"
            f"To-Fingerprint: {to_fp}\n"
            f"Message-ID: {message_id}\n"
            f"Thread-ID: {thread_id}\n"
            "Server-Verified: true\n"
            "\n"
        )
        fwd_plain = (fwd_headers + inner + "\n").encode()
        # The recipient public key must be in the server keyring to encrypt.
        gpgutil.import_public(self.gnupg, recipient["public_key"])
        try:
            blob = gpgutil.encrypt_sign(
                self.gnupg, self.server_fp, [to_fp], fwd_plain,
                comment=f"muse-link relay; from {sender['handle']} ({from_fp})")
        except gpgutil.GpgError as exc:
            return 500, {"error": "relay wrap failed: " + str(exc)}
        recip_dir = os.path.join(self.queue_dir, to_fp)
        os.makedirs(recip_dir, exist_ok=True)
        blob_path = os.path.join(recip_dir, message_id + ".blob")
        with open(blob_path, "w") as fh:
            fh.write(blob)
        with self.lock:
            self.db.execute(
                "INSERT OR REPLACE INTO messages (message_id, from_fp, to_fp, thread_id,"
                " state, queued_at, blob_path) VALUES (?,?,?,?, 'queued', ?, ?)",
                (message_id, from_fp, to_fp, thread_id, now(), blob_path))
            self.db.commit()
        return 200, {"status": "ok", "message_id": message_id, "thread_id": thread_id}

    def _ledger_error(self, message_id, from_fp, to_fp, thread_id, error):
        if not message_id:
            return
        with self.lock:
            self.db.execute(
                "INSERT OR REPLACE INTO messages (message_id, from_fp, to_fp, thread_id,"
                " state, queued_at, error) VALUES (?,?,?,?, 'error', ?, ?)",
                (message_id, from_fp or "", to_fp or "", thread_id, now(), error))
            self.db.commit()

    def handle_fetch(self, armor):
        try:
            headers, ident = self.verify_request(armor, "fetch")
        except ValueError as exc:
            return 403, {"error": str(exc)}
        self.sweep_purges()
        limit = 50
        try:
            limit = max(1, min(200, int(headers.get("Limit", "50"))))
        except ValueError:
            pass
        with self.lock:
            rows = self.db.execute(
                "SELECT * FROM messages WHERE to_fp=? AND state IN ('queued','fetched')"
                " ORDER BY queued_at LIMIT ?",
                (ident["fingerprint"], limit)).fetchall()
            out = []
            for row in rows:
                blob = None
                if row["blob_path"] and os.path.exists(row["blob_path"]):
                    with open(row["blob_path"]) as fh:
                        blob = fh.read()
                if blob is None:
                    continue
                out.append({"message_id": row["message_id"], "blob": blob})
                self.db.execute(
                    "UPDATE messages SET state='fetched', fetched_at=? WHERE message_id=?",
                    (now(), row["message_id"]))
            self.db.commit()
        return 200, {"messages": out, "server_fingerprint": self.server_fp}

    def handle_ack(self, armor):
        try:
            headers, ident = self.verify_request(armor, "ack")
        except ValueError as exc:
            return 403, {"error": str(exc)}
        ids = [s.strip() for s in headers.get("Message-IDs", "").split(",") if s.strip()]
        acked = []
        with self.lock:
            for mid in ids:
                row = self.db.execute(
                    "SELECT * FROM messages WHERE message_id=?", (mid,)).fetchone()
                if row and row["to_fp"] == ident["fingerprint"] and \
                        row["state"] in ("queued", "fetched"):
                    self.db.execute(
                        "UPDATE messages SET state='acked', acked_at=? WHERE message_id=?",
                        (now(), mid))
                    acked.append(mid)
            self.db.commit()
        purged = self.sweep_purges()
        return 200, {"status": "ok", "acked": acked, "purged": purged}

    sweep_count = 0

    def sweep_purges(self):
        """Delete ciphertext blobs for acked messages past the grace period.

        The ledger row is kept and moves to state 'purged' (round 6: the
        server keeps state records, not ciphertext). Returns count.
        """
        count = 0
        with self.lock:
            rows = self.db.execute(
                "SELECT * FROM messages WHERE state='acked' AND acked_at IS NOT NULL"
                " AND acked_at <= ?", (now() - self.purge_grace,)).fetchall()
            for row in rows:
                if row["blob_path"] and os.path.exists(row["blob_path"]):
                    os.remove(row["blob_path"])
                self.db.execute(
                    "UPDATE messages SET state='purged', purged_at=? WHERE message_id=?",
                    (now(), row["message_id"]))
                count += 1
            if count:
                self.db.commit()
        self.sweep_count = count
        return count

    def status(self):
        self.sweep_purges()
        with self.lock:
            counts = {}
            for row in self.db.execute(
                    "SELECT state, COUNT(*) AS n FROM messages GROUP BY state"):
                counts[row["state"]] = row["n"]
            idents = self.db.execute("SELECT COUNT(*) AS n FROM identities").fetchone()["n"]
            msgs = [dict(r) for r in self.db.execute(
                "SELECT message_id, from_fp, to_fp, thread_id, state, error"
                " FROM messages ORDER BY queued_at")]
        return {"server_fingerprint": self.server_fp, "identities": idents,
                "message_states": counts, "messages": msgs,
                "purge_grace_seconds": self.purge_grace}


def make_handler(relay):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # keep test output clean
            pass

        def _respond(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY_BYTES:
                return None
            return self.rfile.read(length) if length else b""

        def do_GET(self):
            if self.path == "/server-key":
                armor = gpgutil.export_public(relay.gnupg, relay.server_fp)
                body = armor.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("X-Server-Fingerprint", relay.server_fp)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif self.path == "/status":
                self._respond(200, relay.status())
            else:
                self._respond(404, {"error": "not found"})

        def do_POST(self):
            raw = self._body()
            if raw is None:
                self._respond(413, {"error": "request too large"})
                return
            armor = raw.decode("utf-8", "replace")
            routes = {
                "/register": relay.handle_register,
                "/send": relay.handle_send,
                "/fetch": relay.handle_fetch,
                "/ack": relay.handle_ack,
                "/agents": relay.handle_agents,
            }
            fn = routes.get(self.path)
            if fn is None:
                self._respond(404, {"error": "not found"})
                return
            try:
                code, obj = fn(armor)
            except Exception as exc:  # fail closed, never crash open
                code, obj = 500, {"error": "internal error: " + str(exc)}
            self._respond(code, obj)

    return Handler


def main():
    ap = argparse.ArgumentParser(description="Muse-Link relay server")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8931)
    ap.add_argument("--data-dir", default=os.environ.get(
        "MUSELINK_DATA_DIR", os.path.expanduser("~/.muse-link-relay")))
    args = ap.parse_args()
    relay = Relay(args.data_dir)
    server = ThreadingHTTPServer((args.host, args.port), make_handler(relay))
    print(f"muse-link relay listening on {args.host}:{args.port} "
          f"data={args.data_dir} server_fp={relay.server_fp}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
