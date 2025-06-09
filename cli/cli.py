"""kairo-krl – Swap.io Key‑Revocation CLI
========================================

A Docker‑friendly command‑line utility for managing the canonical
Key‑Revocation List (KRL) used across Swap.io services.

Commands
--------
* **init‑keypair**            – Generate maintainer key‑pair and write `.env`.
* **generate USERNAME**       – Produce developer key and audit‑log the action.
* **revoke USERNAME|KEY**     – Add key digest to KRL and re‑sign.
* **restore USERNAME|KEY**    – Remove key digest from KRL and re‑sign. *(alias: `unrevoke`)*
* **verify‑krl**              – Validate detached signature `keys.sig`.
* **verify‑key USERNAME|KEY** – Check key ↔ username match; with `--check‑revoked` also fail if key is on the list.
* **check‑revoked USERNAME|KEY** – Exit `1` if the key (or username‑derived key) is present in KRL.

Every state‑changing command appends one line to `.keys.log`:
```
<ISO8601>Z <action> <details>
```
"""
from __future__ import annotations

import hashlib
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Tuple

import base58  # type: ignore
import click  # type: ignore
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

# ──────────────────────────────────────────────────────────────────────────────
# Paths / constants
# ──────────────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parents[1]
KRL_DIR = ROOT / "krl"
KRL_PATH = KRL_DIR / "keys.krl"
SIG_PATH = KRL_DIR / "keys.sig"
LOG_PATH = ROOT / ".keys.log"
ENV_DEFAULT = ROOT / ".env"
B58_SIG_LEN = 88  # truncated base58 sig segment inside developer keys

# ──────────────────────────────────────────────────────────────────────────────
# Helper functions
# ──────────────────────────────────────────────────────────────────────────────

def log_action(action: str, details: str | None = None) -> None:
    """Append an audit entry to .keys.log."""
    ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    line = f"{ts} {action}{(' ' + details) if details else ''}\n"
    with LOG_PATH.open("a", encoding="utf-8") as fp:
        fp.write(line)


def load_signing_key() -> SigningKey:
    key_b58 = os.getenv("KAIRO_SIGNING_KEY")
    if not key_b58:
        click.echo("❌  KAIRO_SIGNING_KEY not set.", err=True)
        raise click.Abort()
    try:
        key_bytes = base58.b58decode(key_b58)
    except ValueError as exc:
        click.echo(f"❌  Invalid base58 in private key: {exc}", err=True)
        raise click.Abort()
    if len(key_bytes) not in (32, 64):
        click.echo("❌  Private key must decode to 32 or 64 bytes.", err=True)
        raise click.Abort()
    return SigningKey(key_bytes[:32])


def public_key_b58(sk: SigningKey | None = None, *, mandatory: bool = False) -> str:
    if sk is not None:
        return base58.b58encode(sk.verify_key.encode()).decode()
    pk = os.getenv("PUBLIC_KEY_BASE58")
    if pk:
        return pk
    if mandatory:
        click.echo("❌  PUBLIC_KEY_BASE58 not set.", err=True)
        raise click.Abort()
    return ""


def calc_key(username: str, sk: SigningKey) -> str:
    sig = sk.sign(username.encode()).signature  # 64 bytes
    sig_b58 = base58.b58encode(sig).decode()
    return f"{username}-{sig_b58}"


def split_key(dev_key: str) -> Tuple[str, str]:
    if "-" not in dev_key:
        raise ValueError("Key must contain '-' separator.")
    return tuple(dev_key.split("-", 1))  # type: ignore[return-value]


def hash_key(dev_key: str) -> str:
    return hashlib.sha256(dev_key.encode()).hexdigest()


def write_sorted(path: Path, lines: List[str]):
    unique_sorted = sorted({l.strip() for l in lines if l.strip()})
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(unique_sorted) + "\n")


def sign_krl(sk: SigningKey):
    sig = sk.sign(KRL_PATH.read_bytes()).signature
    SIG_PATH.write_text(base58.b58encode(sig).decode() + "\n")


def ensure_krl():
    if not KRL_PATH.exists():
        KRL_DIR.mkdir(parents=True, exist_ok=True)
        KRL_PATH.touch()


def is_revoked(dev_key: str) -> bool:
    ensure_krl()
    digest = hash_key(dev_key)
    return digest in {l.strip() for l in KRL_PATH.read_text().splitlines() if l.strip()}

# ──────────────────────────────────────────────────────────────────────────────
# Click CLI definition
# ──────────────────────────────────────────────────────────────────────────────

@click.group()
@click.version_option("1.0.0", prog_name="kairo-krl")
def cli():
    """Manage the canonical Key‑Revocation List (KRL)."""
    os.chdir(ROOT)

# ----- init‑keypair ----------------------------------------------------------

@cli.command("init-keypair")
@click.option("--out", type=click.Path(dir_okay=False, path_type=Path), default=ENV_DEFAULT, show_default=True)
@click.option("--force", is_flag=True, help="Overwrite OUT if it exists.")
def init_keypair(out: Path, force: bool):
    if out.exists() and not force:
        click.echo(f"❌  {out} exists – use --force.", err=True)
        raise click.Abort()
    sk = SigningKey.generate()
    priv = base58.b58encode(sk.encode()).decode()
    pub = base58.b58encode(sk.verify_key.encode()).decode()
    out.write_text(f"KAIRO_SIGNING_KEY={priv}\nPUBLIC_KEY_BASE58={pub}\n")
    click.echo(f"✅  Key‑pair written to {out}.")
    log_action("init-keypair")

# ----- generate --------------------------------------------------------------

@cli.command("generate")
@click.argument("username")
def generate(username):
    sk = load_signing_key()
    key = calc_key(username, sk)
    click.echo(key)
    log_action("generate", f"{username} {key}")

# ----- revoke ---------------------------------------------------------------

@cli.command("revoke")
@click.argument("target")
def revoke(target):
    sk = load_signing_key()
    key = target if "-" in target else calc_key(target, sk)
    digest = hash_key(key)
    ensure_krl()
    lines = KRL_PATH.read_text().splitlines()
    if digest not in lines:
        lines.append(digest)
        write_sorted(KRL_PATH, lines)
        sign_krl(sk)
        click.echo("✅  Key revoked & KRL signed.")
        log_action("revoke", split_key(key)[0])
    else:
        click.echo("ℹ️   Key already revoked.")

# ----- restore (alias: unrevoke) -------------------------------------------

@cli.command("restore")
@click.argument("target")
def restore(target):
    """Remove USERNAME/KEY digest from the KRL."""
    sk = load_signing_key()
    key = target if "-" in target else calc_key(target, sk)
    digest = hash_key(key)
    ensure_krl()
    lines = [l.strip() for l in KRL_PATH.read_text().splitlines() if l.strip()]
    if digest in lines:
        lines.remove(digest)
        write_sorted(KRL_PATH, lines)
        sign_krl(sk)
        click.echo("✅  Key restored & KRL signed.")
        log_action("restore", split_key(key)[0])
    else:
        click.echo("ℹ️   Key not present in KRL.")

# legacy alias
cli.add_command(restore, name="unrevoke")

# ----- verify‑krl -----------------------------------------------------------

@cli.command("verify-krl")
def verify_krl():
    pk_b58 = public_key_b58(mandatory=True)
    vk = VerifyKey(base58.b58decode(pk_b58))
    try:
        vk.verify(KRL_PATH.read_bytes(), base58.b58decode(SIG_PATH.read_text().strip()))
        click.echo("✅  Signature valid – KRL untampered.")
    except (FileNotFoundError, BadSignatureError):
        click.echo("❌  Signature verification failed!", err=True)
        raise click.Abort()

# ----- verify‑key -----------------------------------------------------------

@cli.command("verify-key")
@click.argument("target")
@click.option("--check-revoked", is_flag=True, help="Fail if key is on the KRL.")
def verify_key(target, check_revoked):
    sk = load_signing_key()
    if "-" in target:
        username, _ = split_key(target)
        expected = calc_key(username, sk)
        if expected != target:
            click.echo("❌  Signature mismatch.", err=True)
            raise click.Abort()
        if check_revoked and is_revoked(target):
            click.echo("❌  Key is revoked.", err=True)
            raise click.Abort()
        click.echo("✅  Key valid" + (" and not revoked." if check_revoked else "."))
    else:
        click.echo(calc_key(target, sk))

# ----- check‑revoked --------------------------------------------------------

@cli.command("check-revoked")
@click.argument("target")
def check_revoked(target):
    """Return non-zero exit code if *TARGET* (username or key) is in the KRL."""
    if "-" in target:
        key = target
    else:
        # Need private key to compute expected key from username
        try:
            sk = load_signing_key()
        except click.Abort:
            click.echo("❌  Private key required when only username is provided.", err=True)
            raise
        key = calc_key(target, sk)

    if is_revoked(key):
        click.echo("🚫  Revoked")
        raise click.Abort()
    else:
        click.echo("✅  Not revoked")

# ------------------------- entry -------------------------------------------------------

if __name__ == "__main__":
    cli()
