#!/usr/bin/env python3
"""Muse-Link MVP end-to-end test.

Spins up the relay on localhost with a temp data dir and two simulated
peer clients (A and B) with temp homes, then exercises the full round
trip and the failure modes from the design's acceptance list:

  register x2, token reuse rejected, agents listing, send, fetch,
  .md on disk with verification fields, refetch-before-ack redelivery
  with dedupe, reply threading, ack -> ledger acked -> grace -> blob
  purged, tampered queued blob flagged and never filed as authentic,
  stale fetch rejected, unregistered key rejected at ingest.

Run: python3 tests/test_e2e.py   (exit 0 = all passed)
"""

import glob
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
import urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "common"))
import gpgutil  # noqa: E402

SERVER = os.path.join(ROOT, "relay", "server.py")
LINK = os.path.join(ROOT, "relay", "link")
CLIENT = os.path.join(ROOT, "client", "muse_link.py")
TMP = os.path.join(ROOT, "tests", ".tmp")

PASSED = []


def ok(name):
    PASSED.append(name)
    print("PASS: " + name, flush=True)


def run(cmd, env_extra=None, expect_fail=False):
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if expect_fail:
        assert proc.returncode != 0, f"expected failure, got success: {cmd}\n{proc.stdout}"
        return proc
    assert proc.returncode == 0, \
        f"command failed: {cmd}\nstdout: {proc.stdout}\nstderr: {proc.stderr}"
    return proc


def last_json(proc):
    out = proc.stdout.strip()
    try:
        return json.loads(out)
    except ValueError:
        return json.loads(out.splitlines()[-1])


def http(method, url, data=None):
    req = urllib.request.Request(url, data=data, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def main():
    shutil.rmtree(TMP, ignore_errors=True)
    os.makedirs(TMP)
    data_dir = os.path.join(TMP, "relay-data")
    port = None
    server_proc = None
    for candidate in range(18931, 18941):
        env = dict(os.environ, MUSELINK_PURGE_GRACE_SECONDS="3")
        server_proc = subprocess.Popen(
            [sys.executable, SERVER, "--host", "127.0.0.1",
             "--port", str(candidate), "--data-dir", data_dir],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
        base = f"http://127.0.0.1:{candidate}"
        for _ in range(50):
            time.sleep(0.2)
            try:
                status, _, _ = http("GET", base + "/server-key")
                if status == 200:
                    port = candidate
                    break
            except Exception:
                pass
            if server_proc.poll() is not None:
                break
        if port:
            break
        server_proc.kill()
    assert port, "relay did not start"
    print(f"relay up on {base} (data {data_dir})", flush=True)

    def link(*args):
        return run([LINK, "--data-dir", data_dir] + list(args))

    def client(home, *args):
        return run([sys.executable, CLIENT, "--home", home] + list(args))

    try:
        # --- bootstrap tokens via the operator host CLI -------------------
        tok_a = last_json(link("bootstrap", "--handle", "peer-a"))["bootstrap_token"]
        tok_b = last_json(link("bootstrap", "--handle", "peer-b"))["bootstrap_token"]
        ok("host CLI issues bootstrap tokens for both peers")

        home_a, home_b = os.path.join(TMP, "home-a"), os.path.join(TMP, "home-b")

        def boot_json(path, token, handle, agent, owner):
            doc = {"bootstrap_token": token, "agent_name": agent,
                   "owner_name": owner, "handle": handle, "platform": "muse",
                   "relay": base, "protocol_version": "1",
                   "capabilities": ["text"]}
            with open(path, "w") as fh:
                json.dump(doc, fh)
            return path

        boot_a = boot_json(os.path.join(TMP, "boot-a.json"), tok_a,
                           "peer-a", "Peer A Muse", "Alice")
        boot_b = boot_json(os.path.join(TMP, "boot-b.json"), tok_b,
                           "peer-b", "Peer B Muse", "Bob")
        reg_a = last_json(client(home_a, "register", "--bootstrap-json", boot_a))
        assert reg_a["status"] == "registered" and reg_a["handle"] == "peer-a"
        reg_b = last_json(client(home_b, "register", "--bootstrap-json", boot_b))
        assert reg_b["status"] == "registered"
        ok("both peers register (local keygen, PGP registration, HTTP 200)")

        # --- token reuse is rejected --------------------------------------
        home_a2 = os.path.join(TMP, "home-a2")
        run([sys.executable, CLIENT, "--home", home_a2, "register",
             "--bootstrap-json", boot_a], expect_fail=True)
        ok("burned bootstrap token cannot register a second client")

        fp_b = reg_b["fingerprint"]
        who_a = last_json(client(home_a, "whoami"))
        assert who_a["handle"] == "peer-a" and who_a["enrolled"] is True
        ok("whoami reports A's enrolled identity")

        # --- agents listing -------------------------------------------------
        agents = last_json(client(home_a, "agents"))["agents"]
        handles = {a["handle"] for a in agents}
        assert handles == {"peer-a", "peer-b"}, handles
        ok("agents listing shows both peers")

        # --- A sends to B ---------------------------------------------------
        sent = last_json(client(home_a, "send", "--to", "peer-b",
                                "--subject", "Trailer question",
                                "--body", "Hello B, body-one from A."))
        m1, thread1 = sent["message_id"], sent["thread_id"]
        assert os.path.exists(os.path.join(home_a, "mailbox", "sent", m1 + ".md"))
        ok("A sends to B; sent copy filed in A's sent/ as .md")

        # --- B fetches: decrypts to .md with verification fields ------------
        inbox1 = last_json(client(home_b, "inbox"))
        new_ids = [m["message_id"] for m in inbox1["new"]]
        assert m1 in new_ids, inbox1
        entry = [m for m in inbox1["new"] if m["message_id"] == m1][0]
        assert entry["signature_verified"] is True and entry["server_verified"] is True
        md_path = os.path.join(home_b, "mailbox", "inbox", m1 + ".md")
        md_text = open(md_path).read()
        assert "Hello B, body-one from A." in md_text
        assert "signature_verified: true" in md_text
        assert "from_handle: peer-a" in md_text
        assert f"thread: {thread1}" in md_text
        ok("B fetch decrypts to inbox .md with correct body and verification fields")

        # --- refetch before ack: redelivery + dedupe -------------------------
        inbox2 = last_json(client(home_b, "inbox"))
        dup_ids = [m["message_id"] for m in inbox2["duplicates"]]
        assert m1 in dup_ids, inbox2
        files = glob.glob(os.path.join(home_b, "mailbox", "inbox", "*.md"))
        assert len(files) == 1, files
        ok("refetch before ack redelivers; dedupe keeps exactly one file")

        # --- B replies in thread; A fetches ----------------------------------
        reply = last_json(client(home_b, "reply", "--message-id", m1,
                                 "--body", "Reply body from B."))
        m2 = reply["message_id"]
        assert reply["thread_id"] == thread1
        inbox_a = last_json(client(home_a, "inbox"))
        assert m2 in [m["message_id"] for m in inbox_a["new"]], inbox_a
        md_a = open(os.path.join(home_a, "mailbox", "inbox", m2 + ".md")).read()
        assert "Reply body from B." in md_a and f"thread: {thread1}" in md_a
        assert f"in_reply_to: {m1}" in md_a
        ok("B replies; A fetches the reply in the same thread")

        # --- ack: ledger acked, grace passes, blob purged ---------------------
        client(home_b, "ack", m1)
        status = last_json(link("status"))
        states = {m["message_id"]: m["state"] for m in status["messages"]}
        assert states.get(m1) == "acked", states
        blob_path = os.path.join(data_dir, "queue", fp_b, m1 + ".blob")
        assert os.path.exists(blob_path), "blob should survive inside grace"
        time.sleep(4.0)
        http("GET", base + "/status")  # any relay touch runs the purge sweep
        status2 = last_json(link("status"))
        states2 = {m["message_id"]: m["state"] for m in status2["messages"]}
        assert states2.get(m1) == "purged", states2
        assert not os.path.exists(blob_path)
        ok("after ack: ledger shows acked, then purged; ciphertext blob deleted")

        # --- tampered queued blob is flagged, never authentic ------------------
        sent3 = last_json(client(home_a, "send", "--to", "peer-b",
                                 "--body", "tamper target body"))
        m3 = sent3["message_id"]
        blob3 = os.path.join(data_dir, "queue", fp_b, m3 + ".blob")
        raw = open(blob3).read()
        mid = len(raw) // 2
        flipped = raw[:mid] + ("A" if raw[mid] != "A" else "B") + raw[mid + 1:]
        with open(blob3, "w") as fh:
            fh.write(flipped)
        inbox3 = last_json(client(home_b, "inbox"))
        flagged_ids = [m["message_id"] for m in inbox3["flagged"]]
        assert m3 in flagged_ids, inbox3
        assert m3 not in [m["message_id"] for m in inbox3["new"]]
        assert not os.path.exists(os.path.join(home_b, "mailbox", "inbox", m3 + ".md"))
        assert os.path.exists(os.path.join(home_b, "mailbox", "quarantine", m3 + ".txt"))
        ok("tampered queued blob is flagged, quarantined, never filed as authentic")

        # --- stale fetch request is rejected ----------------------------------
        gnupg_b = os.path.join(home_b, "gnupg")
        stale_text = ("Muse-Link-Request: fetch\nRequest-ID: stale-1\n"
                      f"Timestamp: {int(time.time()) - 3600}\n"
                      f"From-Fingerprint: {fp_b}\n")
        stale = gpgutil.clearsign(gnupg_b, fp_b, stale_text)
        code, _, body = http("POST", base + "/fetch", stale.encode())
        assert code == 403 and b"window" in body, (code, body)
        ok("fetch with a stale timestamp is rejected (5 minute window)")

        # --- unregistered key is rejected at ingest ----------------------------
        rogue_home = os.path.join(TMP, "rogue-gnupg")
        rogue_fp = gpgutil.generate_key(rogue_home, "Rogue Agent",
                                        "unregistered", "rogue@muse.link")
        _, hdrs, key_body = http("GET", base + "/server-key")
        server_fp = hdrs["X-Server-Fingerprint"]
        gpgutil.import_public(rogue_home, key_body.decode())
        inner = gpgutil.encrypt_only(rogue_home, [rogue_fp],
                                     b"rogue inner payload")
        outer = ("Muse-Link-Outer: 1\nKind: submission\n"
                 f"From-Fingerprint: {rogue_fp}\nFrom-Handle: rogue\n"
                 f"To-Fingerprint: {fp_b}\n"
                 f"Message-ID: rogue-1\nThread-ID: rogue-t\n\n" + inner + "\n")
        sealed = gpgutil.encrypt_sign(rogue_home, rogue_fp, [server_fp],
                                      outer.encode())
        code, _, body = http("POST", base + "/send", sealed.encode())
        assert code == 403 and b"not registered" in body, (code, body)
        ok("message from an unregistered key is rejected at ingest")

        print(f"\nALL {len(PASSED)} TEST GROUPS PASSED")
        # Clean up temp homes on success: they hold simulated peers'
        # private keys, which should not linger in the workspace.
        # On failure the tree is kept for debugging.
        shutil.rmtree(TMP, ignore_errors=True)
        return 0
    finally:
        if server_proc:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_proc.kill()


if __name__ == "__main__":
    sys.exit(main())
