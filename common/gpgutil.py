"""Shared GPG helpers for Muse-Link.

All crypto in Muse-Link is native GPG, driven through subprocess calls to
the system `gpg` binary. Keys are generated with an empty passphrase by
design (design round 4): agents must operate unattended, and the private
key's protection is the protected store plus the machine's own access
controls. Private keys never leave the machine that generated them.

Nothing in this module prints or logs key material.
"""

import os
import subprocess


class GpgError(Exception):
    pass


def _run(home, args, data=None, want_status=False):
    cmd = ["gpg", "--batch", "--yes", "--pinentry-mode", "loopback",
           "--passphrase", "", "--homedir", str(home)]
    if want_status:
        cmd += ["--status-fd", "2"]
    cmd += args
    proc = subprocess.run(cmd, input=data, capture_output=True)
    return proc


def _parse_status(stderr_bytes):
    """Return dict of GNUPG status keyword -> list of argument strings."""
    out = {}
    for line in stderr_bytes.decode("utf-8", "replace").splitlines():
        if line.startswith("[GNUPG:] "):
            parts = line[len("[GNUPG:] "):].split(" ", 1)
            key = parts[0]
            rest = parts[1] if len(parts) > 1 else ""
            out.setdefault(key, []).append(rest)
    return out


def ensure_home(home):
    os.makedirs(home, mode=0o700, exist_ok=True)
    try:
        os.chmod(home, 0o700)
    except OSError:
        pass


def generate_key(home, name, comment, email):
    """Generate an ed25519 sign + cv25519 encrypt keypair, empty passphrase.

    Returns the primary key fingerprint.
    """
    ensure_home(home)
    params = (
        "Key-Type: eddsa\n"
        "Key-Curve: ed25519\n"
        "Key-Usage: sign\n"
        "Subkey-Type: ecdh\n"
        "Subkey-Curve: cv25519\n"
        "Subkey-Usage: encr\n"
        f"Name-Real: {name}\n"
        f"Name-Comment: {comment}\n"
        f"Name-Email: {email}\n"
        "Expire-Date: 0\n"
        "%no-protection\n"
        "%commit\n"
    )
    proc = _run(home, ["--gen-key"], data=params.encode(), want_status=True)
    if proc.returncode != 0:
        raise GpgError("key generation failed: " + proc.stderr.decode("utf-8", "replace"))
    # The KEY_CREATED status line names the key this run actually made.
    # Listing the keyring and taking the first fingerprint is wrong once
    # the ring holds any other key (e.g. a retry after a failed register
    # would report the stale first key).
    status = _parse_status(proc.stderr)
    for rest in status.get("KEY_CREATED", []):
        parts = rest.split()
        if parts:
            return parts[-1]
    fps = list_fingerprints(home)
    if not fps:
        raise GpgError("key generation produced no key")
    return fps[0]


def list_fingerprints(home):
    proc = _run(home, ["--with-colons", "--list-keys"])
    fps = []
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        parts = line.split(":")
        if parts[0] == "fpr" and len(parts) > 9 and parts[9]:
            fps.append(parts[9])
    return fps


def has_secret_key(home, fingerprint):
    proc = _run(home, ["--with-colons", "--list-secret-keys"])
    return fingerprint in proc.stdout.decode("utf-8", "replace")


def export_public(home, fingerprint):
    proc = _run(home, ["--armor", "--export", fingerprint])
    if proc.returncode != 0 or b"BEGIN PGP PUBLIC KEY BLOCK" not in proc.stdout:
        raise GpgError("public key export failed for " + fingerprint)
    return proc.stdout.decode()


def import_public(home, armor):
    """Import an armored public key. Returns its fingerprint."""
    proc = _run(home, ["--status-fd", "2", "--import"], data=armor.encode())
    status = _parse_status(proc.stderr)
    fps = []
    for rest in status.get("IMPORT_OK", []):
        parts = rest.split()
        if parts:
            fps.append(parts[-1])
    if fps:
        return fps[0]
    # Already present and unchanged: IMPORT_OK may be absent. Determine
    # the fingerprint via show-keys on the armor itself (no second
    # import; the first one already had its side effects).
    return fingerprint_of_armor(armor)


def fingerprint_of_armor(armor):
    """Fingerprint of an armored public key without importing it."""
    proc = subprocess.run(
        ["gpg", "--batch", "--yes", "--show-keys", "--with-colons",
         "--with-fingerprint"],
        input=armor.encode(), capture_output=True)
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        parts = line.split(":")
        if parts[0] == "fpr" and len(parts) > 9 and parts[9]:
            return parts[9]
    raise GpgError("could not read fingerprint from armored key")


def delete_public(home, fingerprint):
    proc = _run(home, ["--batch", "--yes", "--delete-keys", fingerprint])
    return proc.returncode == 0


def encrypt_sign(home, signer_fp, recipient_fps, data, comment=None):
    """Armor-encrypt + sign `data` (bytes) to recipients. Returns armor str."""
    args = ["--armor", "--trust-model", "always"]
    if comment:
        args += ["--comment", comment]
    args += ["--encrypt", "--sign", "--local-user", signer_fp]
    for fp in recipient_fps:
        args += ["--recipient", fp]
    proc = _run(home, args, data=data)
    if proc.returncode != 0:
        raise GpgError("encrypt/sign failed: " + proc.stderr.decode("utf-8", "replace"))
    return proc.stdout.decode()


def encrypt_only(home, recipient_fps, data, comment=None):
    args = ["--armor", "--trust-model", "always"]
    if comment:
        args += ["--comment", comment]
    args += ["--encrypt"]
    for fp in recipient_fps:
        args += ["--recipient", fp]
    proc = _run(home, args, data=data)
    if proc.returncode != 0:
        raise GpgError("encrypt failed: " + proc.stderr.decode("utf-8", "replace"))
    return proc.stdout.decode()


def clearsign(home, signer_fp, text, comment=None):
    args = ["--armor", "--trust-model", "always"]
    if comment:
        args += ["--comment", comment]
    args += ["--clearsign", "--local-user", signer_fp]
    proc = _run(home, args, data=text.encode())
    if proc.returncode != 0:
        raise GpgError("clearsign failed: " + proc.stderr.decode("utf-8", "replace"))
    return proc.stdout.decode()


def decrypt(home, armor):
    """Decrypt an armored message. Returns (plaintext_bytes, validsig_fp).

    validsig_fp is the fingerprint from the VALIDSIG status line, or None
    if the message was not signed, the signature did not verify, or the
    signer's public key is not in this keyring (gpg then decrypts fine
    but exits non-zero with NO_PUBKEY; DECRYPTION_OKAY is the success
    signal, and callers must check validsig_fp themselves).
    Raises GpgError if decryption itself fails.
    """
    proc = _run(home, ["--decrypt"], data=armor.encode(), want_status=True)
    status = _parse_status(proc.stderr)
    if "DECRYPTION_OKAY" not in status:
        raise GpgError("decryption failed: " + proc.stderr.decode("utf-8", "replace")[:400])
    validsig = None
    if status.get("VALIDSIG"):
        validsig = status["VALIDSIG"][0].split()[0]
    return proc.stdout, validsig


def verify_clearsigned(home, armor):
    """Verify a clearsigned document. Returns (plaintext_str, validsig_fp).

    Raises GpgError if there is no valid signature.
    """
    proc = _run(home, ["--decrypt"], data=armor.encode(), want_status=True)
    status = _parse_status(proc.stderr)
    validsig = None
    if status.get("VALIDSIG"):
        validsig = status["VALIDSIG"][0].split()[0]
    if validsig is None:
        raise GpgError("no valid signature: " + proc.stderr.decode("utf-8", "replace")[:400])
    return proc.stdout.decode("utf-8", "replace"), validsig
