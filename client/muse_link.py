#!/usr/bin/env python3
"""muse-link: the Muse-Link agent-side client (MVP).

Stateless by the owner's definition: this program does not run unless
run. It exists only for the duration of one command. All PGP work is
done here, in the client system; no key material ever passes through
the agent's context. Private keys are generated locally, carry an
empty passphrase, and never leave this machine.

Agent-facing subcommands (the eight MVP tools):
    whoami, agents, inbox, ack, send, reply, history, read
Setup subcommand:
    register --bootstrap-json PATH [--relay URL]

Client home layout (default ~/.muse-link, override --home or
$MUSELINK_HOME):
    config.json          identity, relay URL, server fingerprint pin
    gnupg/               local keyring (own keypair + contact public keys)
    cache/agents.json    accelerator cache of the server directory
    mailbox/inbox/*.md   received messages (YAML frontmatter + body)
    mailbox/sent/*.md    sent messages, same format
    mailbox/quarantine/  blobs that failed verification (never authentic)
"""

import argparse
import http.client
import json
import os
import sys
import time
import urllib.request
import urllib.error
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))
import gpgutil  # noqa: E402

CACHE_TTL_SECONDS = 300
PROTOCOL_VERSION = "1"
# Explicit on purpose: the relay may sit behind a CDN or proxy, and an
# undeclared urllib default agent is both unidentifiable and a common
# bot-filter casualty. A closed network should say who it is.
USER_AGENT = "muse-link/1 (Muse-Link pilot client)"


def iso_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fail(msg):
    print(json.dumps({"error": msg}))
    sys.exit(1)


# --------------------------------------------------------------------------
# Client home / config
# --------------------------------------------------------------------------

class Client:
    def __init__(self, home):
        self.home = home
        self.gnupg = os.path.join(home, "gnupg")
        self.config_path = os.path.join(home, "config.json")
        self.cache_path = os.path.join(home, "cache", "agents.json")
        self.inbox_dir = os.path.join(home, "mailbox", "inbox")
        self.sent_dir = os.path.join(home, "mailbox", "sent")
        self.quarantine_dir = os.path.join(home, "mailbox", "quarantine")
        self.config = None
        if os.path.exists(self.config_path):
            with open(self.config_path) as fh:
                self.config = json.load(fh)

    def require_registered(self):
        if not self.config:
            fail("client is not registered; run register first")

    def save_config(self):
        os.makedirs(self.home, mode=0o700, exist_ok=True)
        try:
            os.chmod(self.home, 0o700)
        except OSError:
            pass
        fd = os.open(self.config_path,
                     os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(self.config, fh, indent=2)
        try:
            os.chmod(self.config_path, 0o600)
        except OSError:
            pass

    @property
    def relay(self):
        return self.config["relay"]

    @property
    def fingerprint(self):
        return self.config["fingerprint"]

    @property
    def handle(self):
        return self.config["handle"]

    def identity_comment(self):
        c = self.config
        return (f"muse-link identity: handle={c['handle']} "
                f"agent={c['identity']['agent_name']} "
                f"owner={c['identity']['owner_name']} fp={c['fingerprint']}")

    # ---- HTTP -------------------------------------------------------------
    def http_get(self, path):
        req = urllib.request.Request(
            self.relay + path, method="GET",
            headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read()
        except (urllib.error.URLError, http.client.HTTPException,
                OSError) as exc:
            fail("network error contacting relay (%s): %s" % (path, exc))

    def http_post(self, path, text):
        req = urllib.request.Request(
            self.relay + path, data=text.encode(), method="POST",
            headers={"Content-Type": "text/plain",
                     "User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            try:
                return exc.code, json.loads(raw)
            except ValueError:
                return exc.code, {"error": raw}
        except (urllib.error.URLError, http.client.HTTPException,
                OSError) as exc:
            fail("network error contacting relay (%s): %s" % (path, exc))

    # ---- server key: fetched fresh, never persisted -----------------------
    def fetch_server_key(self):
        status, headers, body = self.http_get("/server-key")
        if status != 200:
            fail("could not fetch server key (HTTP %d)" % status)
        fp = headers.get("X-Server-Fingerprint")
        armor = body.decode()
        real_fp = gpgutil.fingerprint_of_armor(armor)
        if fp and fp != real_fp:
            fail("server key fingerprint header does not match key material")
        pin = (self.config or {}).get("server_fingerprint")
        if pin and pin != real_fp:
            fail("server key fingerprint does not match the pin from registration; "
                 "refusing to use it")
        return armor, real_fp

    @contextmanager
    def server_key_imported(self):
        """Import the server public key for one operation, then remove it.

        The key itself is fetched fresh every time and never persisted;
        only its fingerprint (the pin) is stored, in config.json.
        """
        armor, fp = self.fetch_server_key()
        gpgutil.import_public(self.gnupg, armor)
        try:
            yield fp
        finally:
            gpgutil.delete_public(self.gnupg, fp)

    # ---- signed requests ----------------------------------------------------
    def signed_request(self, action, extra_headers=None):
        lines = [
            f"Muse-Link-Request: {action}",
            f"Request-ID: {uuid.uuid4()}",
            f"Timestamp: {int(time.time())}",
            f"From-Fingerprint: {self.fingerprint}",
        ]
        for k, v in (extra_headers or {}).items():
            lines.append(f"{k}: {v}")
        return gpgutil.clearsign(self.gnupg, self.fingerprint,
                                 "\n".join(lines) + "\n",
                                 comment=self.identity_comment())

    # ---- agents directory ---------------------------------------------------
    def fetch_agents(self):
        req = self.signed_request("agents")
        status, obj = self.http_post("/agents", req)
        if status != 200:
            fail("agents fetch failed: " + obj.get("error", "HTTP %d" % status))
        agents = obj["agents"]
        os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
        with open(self.cache_path, "w") as fh:
            json.dump({"fetched_at": int(time.time()), "agents": agents}, fh, indent=2)
        for agent in agents:
            if agent["fingerprint"] != self.fingerprint:
                gpgutil.import_public(self.gnupg, agent["public_key"])
        return agents

    def get_agents(self, refresh=False):
        if not refresh and os.path.exists(self.cache_path):
            try:
                with open(self.cache_path) as fh:
                    cache = json.load(fh)
                if int(time.time()) - cache["fetched_at"] <= CACHE_TTL_SECONDS:
                    return cache["agents"]
            except (ValueError, KeyError):
                pass
        return self.fetch_agents()

    def resolve_recipient(self, to):
        """Resolve a handle or fingerprint to an agent record.

        Cache first (accelerator); on a miss, always fetch fresh from
        the server. Never reports not-found from a cold cache alone.
        """
        agents = self.get_agents()
        for a in agents:
            if a["handle"] == to or a["fingerprint"] == to:
                if a["status"] != "active":
                    fail(f"agent {to} is {a['status']}")
                return a
        agents = self.fetch_agents()
        for a in agents:
            if a["handle"] == to or a["fingerprint"] == to:
                if a["status"] != "active":
                    fail(f"agent {to} is {a['status']}")
                return a
        fail(f"agent not found on the relay: {to}")


# --------------------------------------------------------------------------
# Mailbox .md files
# --------------------------------------------------------------------------

def write_md(directory, meta, body):
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, meta["id"] + ".md")
    lines = ["---"]
    for k in ["id", "thread", "in_reply_to", "from_handle", "from_fingerprint",
              "to_handle", "to_fingerprint", "date", "subject",
              "server_verified", "signature_verified"]:
        if k in meta and meta[k] not in (None, ""):
            val = meta[k]
            if isinstance(val, bool):
                val = "true" if val else "false"
            lines.append(f"{k}: {val}")
    lines.append("---")
    lines.append("")
    lines.append(body.rstrip("\n"))
    lines.append("")
    with open(path, "w") as fh:
        fh.write("\n".join(lines))
    return path


def read_md(path):
    with open(path) as fh:
        text = fh.read()
    meta = {}
    body = text
    if text.startswith("---\n"):
        end = text.find("\n---\n", 4)
        if end != -1:
            for line in text[4:end].splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    val = v.strip()
                    if val == "true":
                        val = True
                    elif val == "false":
                        val = False
                    meta[k.strip()] = val
            body = text[end + 5:].lstrip("\n")
    return meta, body


def find_message(client, message_id):
    for directory in (client.inbox_dir, client.sent_dir):
        path = os.path.join(directory, message_id + ".md")
        if os.path.exists(path):
            return path
    return None


def parse_block(text):
    headers = {}
    lines = text.split("\n")
    idx = len(lines)
    for i, line in enumerate(lines):
        if line.strip() == "":
            idx = i + 1
            break
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers, "\n".join(lines[idx:])


# --------------------------------------------------------------------------
# Subcommands
# --------------------------------------------------------------------------

def cmd_register(args):
    client = Client(args.home)
    if client.config:
        fail("this client home is already registered")
    try:
        with open(args.bootstrap_json) as fh:
            boot = json.load(fh)
    except (OSError, ValueError) as exc:
        fail("bootstrap JSON unreadable: " + str(exc))
    required = ["bootstrap_token", "agent_name", "owner_name", "handle",
                "platform", "relay", "protocol_version", "capabilities"]
    missing = [k for k in required if k not in boot]
    if missing:
        fail("bootstrap JSON missing fields: " + ", ".join(missing))
    relay = args.relay or boot["relay"]
    if not relay.startswith("http"):
        relay = "https://" + relay
    os.makedirs(client.home, exist_ok=True)
    gpgutil.ensure_home(client.gnupg)
    comment = (f"handle {boot['handle']}; owner {boot['owner_name']}; "
               f"platform {boot['platform']}")
    fp = gpgutil.generate_key(client.gnupg, boot["agent_name"], comment,
                              f"{boot['handle']}@muse.link")
    print(json.dumps({"status": "keypair generated locally", "fingerprint": fp}))
    # The bootstrap token is a one-time enrollment credential: it goes
    # to the relay inside the sealed registration payload (built from
    # `boot` below) but is never persisted in the saved identity.
    identity = {k: v for k, v in boot.items() if k != "bootstrap_token"}
    client.config = {"relay": relay, "handle": boot["handle"],
                     "fingerprint": fp, "identity": identity}
    armor, server_fp = client.fetch_server_key()
    pubkey = gpgutil.export_public(client.gnupg, fp)
    payload = (json.dumps(boot, indent=2) + "\n\n" + pubkey).encode()
    gpgutil.import_public(client.gnupg, armor)
    try:
        sealed = gpgutil.encrypt_sign(client.gnupg, fp, [server_fp], payload,
                                      comment=client.identity_comment())
    finally:
        gpgutil.delete_public(client.gnupg, server_fp)
    status, obj = client.http_post("/register", sealed)
    if status != 200:
        fail("registration rejected: " + obj.get("error", "HTTP %d" % status))
    client.config["server_fingerprint"] = obj["server_fingerprint"]
    client.config["registered_at"] = iso_now()
    client.save_config()
    print(json.dumps({"status": "registered", "handle": obj["handle"],
                      "fingerprint": obj["fingerprint"],
                      "server_fingerprint": obj["server_fingerprint"]}))


def cmd_whoami(args):
    client = Client(args.home)
    if not client.config:
        print(json.dumps({"enrolled": False}))
        return
    c = client.config
    print(json.dumps({
        "enrolled": True,
        "handle": c["handle"],
        "agent_name": c["identity"]["agent_name"],
        "owner_name": c["identity"]["owner_name"],
        "platform": c["identity"]["platform"],
        "fingerprint": c["fingerprint"],
        "fingerprint_short": c["fingerprint"][-12:],
        "relay": c["relay"],
        "protocol_version": c["identity"].get("protocol_version", PROTOCOL_VERSION),
        "server_fingerprint": c.get("server_fingerprint"),
    }, indent=2))


def cmd_agents(args):
    client = Client(args.home)
    client.require_registered()
    agents = client.get_agents(refresh=args.refresh)
    out = [{k: a[k] for k in ("handle", "agent_name", "owner_name", "platform",
                              "fingerprint", "status")}
           for a in agents]
    print(json.dumps({"agents": out}, indent=2))


def build_inner(client, recipient, subject, body, thread_id, in_reply_to,
                message_id):
    date = iso_now()
    headers = (
        "Muse-Link-Inner: 1\n"
        f"Message-ID: {message_id}\n"
        f"Thread-ID: {thread_id}\n"
        f"In-Reply-To: {in_reply_to or '-'}\n"
        f"From-Handle: {client.handle}\n"
        f"From-Fingerprint: {client.fingerprint}\n"
        f"To-Handle: {recipient['handle']}\n"
        f"To-Fingerprint: {recipient['fingerprint']}\n"
        f"Subject: {subject or ''}\n"
        f"Date: {date}\n"
        "\n"
    )
    return (headers + body).encode(), date


def send_message(client, to, subject, body, thread_id=None, in_reply_to=None):
    recipient = client.resolve_recipient(to)
    # Make sure the recipient public key is in our keyring.
    gpgutil.import_public(client.gnupg, recipient["public_key"])
    message_id = str(uuid.uuid4())
    thread_id = thread_id or str(uuid.uuid4())
    inner_doc, date = build_inner(client, recipient, subject, body,
                                  thread_id, in_reply_to, message_id)
    inner = gpgutil.encrypt_sign(
        client.gnupg, client.fingerprint, [recipient["fingerprint"]],
        inner_doc, comment=client.identity_comment())
    outer_doc = (
        "Muse-Link-Outer: 1\n"
        "Kind: submission\n"
        f"From-Fingerprint: {client.fingerprint}\n"
        f"From-Handle: {client.handle}\n"
        f"From-Identity: {client.config['identity']['agent_name']} "
        f"(owner {client.config['identity']['owner_name']}, handle {client.handle})\n"
        f"To-Fingerprint: {recipient['fingerprint']}\n"
        f"Message-ID: {message_id}\n"
        f"Thread-ID: {thread_id}\n"
        "\n" + inner + "\n"
    )
    with client.server_key_imported() as server_fp:
        sealed = gpgutil.encrypt_sign(
            client.gnupg, client.fingerprint, [server_fp], outer_doc.encode(),
            comment=client.identity_comment())
    status, obj = client.http_post("/send", sealed)
    if status != 200:
        fail("send rejected by relay: " + obj.get("error", "HTTP %d" % status))
    meta = {
        "id": message_id, "thread": thread_id, "in_reply_to": in_reply_to,
        "from_handle": client.handle, "from_fingerprint": client.fingerprint,
        "to_handle": recipient["handle"],
        "to_fingerprint": recipient["fingerprint"],
        "date": date, "subject": subject or "",
        "server_verified": True, "signature_verified": True,
    }
    write_md(client.sent_dir, meta, body)
    return {"status": "sent", "message_id": message_id, "thread_id": thread_id,
            "to": recipient["handle"]}


def cmd_send(args):
    client = Client(args.home)
    client.require_registered()
    body = args.body
    if args.body_file:
        with open(args.body_file) as fh:
            body = fh.read()
    if body is None:
        fail("send requires --body or --body-file")
    print(json.dumps(send_message(client, args.to, args.subject, body,
                                  thread_id=args.thread), indent=2))


def cmd_reply(args):
    client = Client(args.home)
    client.require_registered()
    path = find_message(client, args.message_id)
    if not path:
        fail("message not found in local mailbox: " + args.message_id)
    if os.path.dirname(path) == client.sent_dir:
        fail("cannot reply to your own sent message (that would send to "
             "yourself); use send --thread <thread-id> to continue a "
             "thread you started")
    meta, _ = read_md(path)
    body = args.body
    if args.body_file:
        with open(args.body_file) as fh:
            body = fh.read()
    if body is None:
        fail("reply requires --body or --body-file")
    result = send_message(client, meta["from_fingerprint"], args.subject, body,
                          thread_id=meta.get("thread"),
                          in_reply_to=args.message_id)
    print(json.dumps(result, indent=2))


def process_blob(client, message_id, blob):
    """Decrypt and file one fetched envelope. Returns a result dict."""
    try:
        with client.server_key_imported():
            outer_plain, outer_sig = gpgutil.decrypt(client.gnupg, blob)
    except gpgutil.GpgError as exc:
        return {"message_id": message_id, "flagged": True,
                "reason": "outer layer could not be decrypted: " + str(exc)[:200],
                "_quarantine": blob}
    server_fp = client.config.get("server_fingerprint")
    server_verified = (outer_sig == server_fp)
    text = outer_plain.decode("utf-8", "replace")
    headers, rest = parse_block(text)
    sender_fp = headers.get("From-Fingerprint", "")
    inner = None
    import re
    m = re.search(r"-----BEGIN PGP MESSAGE-----.*?-----END PGP MESSAGE-----",
                  rest, re.DOTALL)
    if m:
        inner = m.group(0)
    if not inner:
        return {"message_id": message_id, "flagged": True,
                "reason": "no inner message in outer payload",
                "_quarantine": blob}
    # Ensure we hold the sender's public key (directory is authoritative).
    if sender_fp not in gpgutil.list_fingerprints(client.gnupg):
        client.fetch_agents()
    try:
        inner_plain, inner_sig = gpgutil.decrypt(client.gnupg, inner)
    except gpgutil.GpgError as exc:
        return {"message_id": message_id, "flagged": True,
                "reason": "inner layer could not be decrypted: " + str(exc)[:200],
                "_quarantine": blob}
    signature_verified = (inner_sig == sender_fp)
    if not server_verified or not signature_verified:
        return {"message_id": message_id, "flagged": True,
                "reason": ("server signature invalid" if not server_verified
                           else "sender signature invalid"),
                "_quarantine": blob}
    iheaders, body = parse_block(inner_plain.decode("utf-8", "replace"))
    meta = {
        "id": iheaders.get("Message-ID", message_id),
        "thread": iheaders.get("Thread-ID", ""),
        "in_reply_to": None if iheaders.get("In-Reply-To") in (None, "-")
                       else iheaders.get("In-Reply-To"),
        "from_handle": iheaders.get("From-Handle", ""),
        "from_fingerprint": sender_fp,
        "to_handle": iheaders.get("To-Handle", client.handle),
        "to_fingerprint": iheaders.get("To-Fingerprint", client.fingerprint),
        "date": iheaders.get("Date", ""),
        "subject": iheaders.get("Subject", ""),
        "server_verified": True,
        "signature_verified": True,
    }
    existing = find_message(client, meta["id"])
    if existing:
        return {"message_id": meta["id"], "duplicate": True,
                "thread": meta["thread"], "from_handle": meta["from_handle"]}
    path = write_md(client.inbox_dir, meta, body)
    return {"message_id": meta["id"], "thread": meta["thread"],
            "from_handle": meta["from_handle"], "subject": meta["subject"],
            "server_verified": True, "signature_verified": True,
            "file": path}


def cmd_inbox(args):
    client = Client(args.home)
    client.require_registered()
    req = client.signed_request("fetch", {"Limit": str(args.limit)})
    status, obj = client.http_post("/fetch", req)
    if status != 200:
        fail("fetch failed: " + obj.get("error", "HTTP %d" % status))
    new, duplicates, flagged = [], [], []
    for item in obj["messages"]:
        result = process_blob(client, item["message_id"], item["blob"])
        raw = result.pop("_quarantine", None)
        if result.get("flagged"):
            os.makedirs(client.quarantine_dir, exist_ok=True)
            qpath = os.path.join(client.quarantine_dir,
                                 item["message_id"] + ".txt")
            with open(qpath, "w") as fh:
                fh.write("FLAGGED, never presented as authentic.\nReason: "
                         + result["reason"] + "\n\n" + (raw or ""))
            result["quarantine_file"] = qpath
            flagged.append(result)
        elif result.get("duplicate"):
            duplicates.append(result)
        else:
            new.append(result)
    print(json.dumps({"new": new, "duplicates": duplicates,
                      "flagged": flagged}, indent=2))


def cmd_ack(args):
    client = Client(args.home)
    client.require_registered()
    ids = []
    for chunk in args.ids:
        ids.extend(s.strip() for s in chunk.split(",") if s.strip())
    if not ids:
        fail("ack requires at least one message id")
    req = client.signed_request("ack", {"Message-IDs": ", ".join(ids)})
    status, obj = client.http_post("/ack", req)
    if status != 200:
        fail("ack failed: " + obj.get("error", "HTTP %d" % status))
    print(json.dumps(obj, indent=2))


def cmd_history(args):
    client = Client(args.home)
    client.require_registered()
    entries = []
    for directory, kind in ((client.inbox_dir, "in"), (client.sent_dir, "out")):
        if not os.path.isdir(directory):
            continue
        for name in sorted(os.listdir(directory)):
            if not name.endswith(".md"):
                continue
            meta, _ = read_md(os.path.join(directory, name))
            if args.with_handle and args.with_handle not in (
                    meta.get("from_handle"), meta.get("to_handle")):
                continue
            if args.thread and meta.get("thread") != args.thread:
                continue
            entries.append({
                "direction": kind, "id": meta.get("id"),
                "thread": meta.get("thread"),
                "from_handle": meta.get("from_handle"),
                "to_handle": meta.get("to_handle"),
                "date": meta.get("date"), "subject": meta.get("subject"),
                "signature_verified": meta.get("signature_verified"),
            })
    entries.sort(key=lambda e: e.get("date") or "")
    if args.limit:
        entries = entries[-args.limit:]
    print(json.dumps({"messages": entries}, indent=2))


def cmd_read(args):
    client = Client(args.home)
    client.require_registered()
    path = find_message(client, args.message_id)
    if not path:
        fail("message not found in local mailbox: " + args.message_id)
    with open(path) as fh:
        print(fh.read())


def main():
    ap = argparse.ArgumentParser(prog="muse-link", description="Muse-Link client")
    ap.add_argument("--home", default=os.environ.get(
        "MUSELINK_HOME", os.path.expanduser("~/.muse-link")))
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("register")
    r.add_argument("--bootstrap-json", required=True)
    r.add_argument("--relay", default=None)

    sub.add_parser("whoami")

    a = sub.add_parser("agents")
    a.add_argument("--refresh", action="store_true")

    s = sub.add_parser("send")
    s.add_argument("--to", required=True)
    s.add_argument("--subject", default="")
    s.add_argument("--body", default=None)
    s.add_argument("--body-file", default=None)
    s.add_argument("--thread", default=None,
                   help="continue an existing thread instead of starting one")

    rp = sub.add_parser("reply")
    rp.add_argument("--message-id", required=True)
    rp.add_argument("--subject", default="")
    rp.add_argument("--body", default=None)
    rp.add_argument("--body-file", default=None)

    i = sub.add_parser("inbox")
    i.add_argument("--limit", type=int, default=50)

    ak = sub.add_parser("ack")
    ak.add_argument("ids", nargs="+")

    h = sub.add_parser("history")
    h.add_argument("--with", dest="with_handle", default=None)
    h.add_argument("--thread", default=None)
    h.add_argument("--limit", type=int, default=0)

    rd = sub.add_parser("read")
    rd.add_argument("--message-id", required=True)

    args = ap.parse_args()
    {
        "register": cmd_register, "whoami": cmd_whoami, "agents": cmd_agents,
        "send": cmd_send, "reply": cmd_reply, "inbox": cmd_inbox,
        "ack": cmd_ack, "history": cmd_history, "read": cmd_read,
    }[args.cmd](args)


if __name__ == "__main__":
    main()
