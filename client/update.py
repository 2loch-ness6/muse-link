#!/usr/bin/env python3
"""update.py: Muse-Link client self-updater.

Stdlib only. Checks the public GitHub repo for the latest release,
downloads the client tarball and its SHA256SUMS over plain HTTPS,
verifies the tarball checksum, and atomically swaps the client files
in this install. State and keys in ~/.muse-link are never touched:
this script only writes inside its own install tree.

Install layout (the directory this file lives in is the install dir):

    <install>/muse_link.py     the client (swapped)
    <install>/update.py        this updater (swaps itself, last)
    <install>/../common/gpgutil.py   the helper module (swapped)
    (a sibling common/ or a flat gpgutil.py next to the client are
    also recognised)

Downloads retry transient network errors with the same hardening as
the client (issue #2: the egress proxy forcibly terminates a large
share of Python urllib flows mid-body; HTTP error statuses are real
responses and are NOT retried). Max 4 attempts, backoff 0.5/1/2s,
identical request bytes on every attempt.

Usage:
    python3 update.py           check and update if a release is newer
    python3 update.py --check   report versions only, change nothing
"""

import hashlib
import http.client
import io
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

REPO = "2loch-ness6/muse-link"
API_LATEST = "https://api.github.com/repos/%s/releases/latest" % REPO
USER_AGENT = "muse-link-updater/1 (Muse-Link client updater)"
RETRY_DELAYS = (0.5, 1.0, 2.0)
SUMS_NAME = "SHA256SUMS"


class UpdateError(Exception):
    pass


# ---------------------------------------------------------------------------
# HTTP with the client's retry hardening (issue #2)
# ---------------------------------------------------------------------------

def fetch(url):
    """GET url, return body bytes. Retries transient network errors
    with identical request bytes; HTTP statuses are not retried."""
    for attempt in range(len(RETRY_DELAYS) + 1):
        req = urllib.request.Request(
            url, method="GET", headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            raise UpdateError("HTTP %d fetching %s" % (exc.code, url))
        except (urllib.error.URLError, http.client.HTTPException,
                OSError) as exc:
            if attempt == len(RETRY_DELAYS):
                raise UpdateError(
                    "network error fetching %s after %d attempts: %s"
                    % (url, attempt + 1, exc))
            time.sleep(RETRY_DELAYS[attempt])


# ---------------------------------------------------------------------------
# Install layout
# ---------------------------------------------------------------------------

def install_paths():
    """Resolve (client, updater, gpgutil) paths for this install."""
    here = os.path.dirname(os.path.abspath(__file__))
    client = os.path.join(here, "muse_link.py")
    updater = os.path.join(here, "update.py")
    gpg_candidates = [
        os.path.normpath(os.path.join(here, "..", "common", "gpgutil.py")),
        os.path.join(here, "common", "gpgutil.py"),
        os.path.join(here, "gpgutil.py"),
    ]
    gpgutil = next((p for p in gpg_candidates if os.path.exists(p)),
                   gpg_candidates[0])
    return client, updater, gpgutil


def guard_paths(paths):
    """Hard rule: never write inside the client state home."""
    state_home = os.path.realpath(os.path.expanduser("~/.muse-link"))
    for p in paths:
        rp = os.path.realpath(p)
        if rp == state_home or rp.startswith(state_home + os.sep):
            raise UpdateError(
                "refusing to touch client state home: %s" % p)


def installed_version(client_path):
    """Parse VERSION out of the sibling client; a client from before
    version stamping counts as 0.0.0 (older than any release)."""
    if not os.path.exists(client_path):
        raise UpdateError("no client found at %s; run this updater "
                          "from the client install directory"
                          % client_path)
    with open(client_path, "r", encoding="utf-8") as fh:
        for line in fh:
            m = re.match(r'VERSION\s*=\s*"([^"]+)"', line)
            if m:
                return m.group(1)
    return "0.0.0"


def version_key(v):
    return tuple(int(x) for x in v.split(".") if x.isdigit())


# ---------------------------------------------------------------------------
# Release discovery and verification
# ---------------------------------------------------------------------------

def latest_release():
    try:
        raw = fetch(API_LATEST)
    except UpdateError as exc:
        if "HTTP 404" in str(exc):
            raise UpdateError("no releases published yet for %s" % REPO)
        raise
    rel = json.loads(raw.decode())
    tag = rel.get("tag_name", "")
    version = tag[1:] if tag.startswith("v") else tag
    assets = {a["name"]: a["browser_download_url"]
              for a in rel.get("assets", [])}
    tarball_name = "muse-link-client-%s.tar.gz" % version
    if tarball_name not in assets:
        raise UpdateError("release %s has no %s asset (assets: %s)"
                          % (tag, tarball_name, sorted(assets)))
    if SUMS_NAME not in assets:
        raise UpdateError("release %s has no %s asset" % (tag, SUMS_NAME))
    return version, assets[tarball_name], assets[SUMS_NAME], tarball_name


def expected_sha256(sums_text, filename):
    for line in sums_text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == filename:
            return parts[0].lower()
    raise UpdateError("%s not listed in %s" % (filename, SUMS_NAME))


def find_payload(root):
    """Locate the three payload files inside an extracted release."""
    wanted = {"client/muse_link.py": None,
              "client/update.py": None,
              "common/gpgutil.py": None}
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            for suffix in wanted:
                if rel == suffix or rel.endswith("/" + suffix):
                    wanted[suffix] = full
    missing = [k for k, v in wanted.items() if v is None]
    if missing:
        raise UpdateError("release tarball is missing: %s"
                          % ", ".join(missing))
    return wanted


# ---------------------------------------------------------------------------
# Atomic swap with backup
# ---------------------------------------------------------------------------

def atomic_copy(src, dest):
    tmp = dest + ".update-tmp"
    shutil.copyfile(src, tmp)
    if os.path.exists(dest):
        shutil.copymode(dest, tmp)
    else:
        os.chmod(tmp, 0o755)
    os.replace(tmp, dest)


def swap(payload, targets, current_version):
    here = os.path.dirname(os.path.abspath(__file__))
    backup_dir = os.path.join(here, "backup-" + current_version)
    if os.path.exists(backup_dir):
        backup_dir = backup_dir + "-" + time.strftime("%H%M%S")
    os.makedirs(backup_dir)
    pairs = [(payload["client/muse_link.py"], targets[0]),
             (payload["common/gpgutil.py"], targets[2]),
             (payload["client/update.py"], targets[1])]  # self last
    for src, dest in pairs:
        if os.path.exists(dest):
            shutil.copy2(dest, os.path.join(backup_dir,
                                            os.path.basename(dest)))
        atomic_copy(src, dest)
    return backup_dir


# ---------------------------------------------------------------------------

def main():
    check_only = "--check" in sys.argv[1:]
    client, updater, gpgutil = install_paths()
    guard_paths([client, updater, gpgutil])
    current = installed_version(client)

    version, tarball_url, sums_url, tarball_name = latest_release()
    print("installed: %s" % current)
    print("latest release: %s" % version)
    if version_key(version) <= version_key(current):
        print("already up to date, nothing to do")
        return 0
    if check_only:
        print("update available (check only, nothing changed)")
        return 0

    sums_text = fetch(sums_url).decode()
    want = expected_sha256(sums_text, tarball_name)
    blob = fetch(tarball_url)
    got = hashlib.sha256(blob).hexdigest()
    if got != want:
        raise UpdateError(
            "checksum mismatch for %s: SHA256SUMS says %s, "
            "download hashes to %s; aborting, nothing changed"
            % (tarball_name, want, got))
    print("checksum verified for %s" % tarball_name)

    tmpdir = tempfile.mkdtemp(prefix="muse-link-update-")
    try:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
            tf.extractall(tmpdir, filter="data")
        payload = find_payload(tmpdir)
        backup_dir = swap(payload, (client, updater, gpgutil), current)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    after = installed_version(client)
    print("updated: %s -> %s" % (current, after))
    print("files swapped: muse_link.py, gpgutil.py, update.py")
    print("previous files backed up to: %s" % backup_dir)
    print("state and keys in ~/.muse-link were not touched")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except UpdateError as exc:
        print("update failed: %s" % exc, file=sys.stderr)
        sys.exit(1)
