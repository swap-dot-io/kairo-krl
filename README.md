# kairo-krl

**Canonical Key‑Revocation List for Swap.io**  
Signed, tamper‑evident registry + Dockerised CLI for issuing, revoking and auditing developer API keys.

---

## 🗝️ Key concept

| Item              | Format / rule                                                                                                                     | Purpose                                                             |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| **Developer key** | `username-<sig>` where `<sig>` = Ed25519 signature of `username`, base58‑encoded and trimmed to the first **44** chars (URL‑safe)  | Shared secret presented by clients (e.g. `alice-5feD...ZQh`)        |
| **KRL entry**     | Hex SHA‑256 of the full key string (`username-<sig>`)                                                                              | Keeps usernames private while letting services blacklist keys       |
| **`keys.sig`**    | Ed25519 detached signature of the raw `keys.krl` bytes                                                                             | Lets services verify the file came from Swap.io                     |

The signing/verification key‑pair is stored **only** in your secure ops vault.  
Every service just needs the **public** half to verify `keys.sig`.

For detailed integration steps, see the [Integration Guide](INTEGRATION-GUIDE.md).

---


## 🔧 CLI quickstart (docker compose)

```bash
# 1. Build the image (first time only)
docker compose build

# 2. Generate a maintainer key‑pair (writes .env, git‑ignore this file!)
docker compose run --rm cli init-keypair --out .env

# 3. Create a developer key for Alice & log it
docker compose run --rm cli generate alice

# 4. Revoke Alice later (adds digest to KRL and re‑signs)
docker compose run --rm cli revoke alice
```

Run `docker compose run --rm cli --help` at any time to see the full command list.

---

## 🖥️ CLI reference

| Command & arguments                           | What it does |
| --------------------------------------------- | ------------ |
| `init-keypair [--out .env] [--force]`         | Generate maintainer Ed25519 key‑pair and write an env file. |
| `generate <username>`                         | Print a fresh developer key, log the action to `.keys.log`. |
| `revoke <username\|key>`                      | Add the key’s digest to `krl/keys.krl` (if absent) and re‑sign `keys.sig`. |
| `verify-krl`                                  | Confirm that `keys.krl` matches `keys.sig` using `KAIRO_PUBLIC_KEY` (or private key). |
| `verify-key <username\|key> [--check-revoked]`| Validate the key’s signature; with `--check-revoked` also fail if present in KRL. |
| `check-revoked <username\|key>`               | Exit non‑zero if the key (or the key derived from USERNAME) is in the KRL. |

### Environment variables

| Variable            | Required for…                        | Description |
| ------------------- | ------------------------------------ | ----------- |
| `KAIRO_SIGNING_KEY` | `generate`, `revoke`, `verify-key`, `check-revoked` (when only username is given) | Base58‑encoded Ed25519 private key used to sign the KRL & derive keys. |
| `KAIRO_PUBLIC_KEY` | `verify-krl` (if private key not loaded) | Base58‑encoded public key for readonly signature checks. |


### 🔑 Current Public Key

The currently valid public key for verification is:
```
CQMNCiexRyPz75ro4f82aWS7voSU7328nQgnLwvdHTkm
```
---

## 📜 Local key log

Every command that mutates state appends an audit line to `.keys.log`:

```text
<ISO8601>Z <action> <details>
```

Examples:

```text
2025-06-09T11:52:42Z init-keypair
2025-06-09T11:52:44Z generate alice alice-5feD...
2025-06-09T11:52:47Z revoke alice
```

`.keys.log` is **git‑ignored**—it never leaves your workstation.

---

## 🌐 Propagation to services

Live services pull **only** the `main` branch copy of `krl/keys.krl` & `keys.sig`.  
Be sure to **commit & push** after every revoke; otherwise the change won’t propagate.

---

## 🔒 File formats

### `krl/keys.krl`

```text
# one digest per line
3b9004522e8ae1dd5b541ebed5187d77e183cc6b74b4d1b3a99fc7d588d5d7a9
e6d23f02bb22c3f9b2ab7572c3bc103f72ed32fef93d4fd778de12e3bfd3e2f6
```

*Always sorted*—the CLI enforces ordering to guarantee deterministic diffs.

### `krl/keys.sig`

```text
# base58 Ed25519 signature (~88 chars)
4uU4vYxvYJf3muw4SDWiPEkrLnMJCvNncgXQ5hQ6Qnqed97ugwE3k8uo8jgxEAn5qoBD...
```

---

## 🛡️ Consuming the KRL in code

```python
import base58, nacl.signing, hashlib, requests

PUB = os.environ["KAIRO_PUBLIC_KEY"]
url = "https://raw.githubusercontent.com/swap-dot-io/kairo-krl/main/krl/"

krl  = requests.get(url + "keys.krl").content
sig  = base58.b58decode(requests.get(url + "keys.sig").text.strip())

nacl.signing.VerifyKey(base58.b58decode(PUB)).verify(krl, sig)  # raises if tampered
revoked = {line.strip() for line in krl.splitlines()}

def is_key_revoked(dev_key: str) -> bool:
    return hashlib.sha256(dev_key.encode()).hexdigest() in revoked
```

---

## 🏗️ Development

```bash
# lint, type‑check, unit tests
pip install -r cli/requirements.txt -r requirements-dev.txt
pytest -q
```

---

## 📂 Repo layout

```text
kairo-krl/
├── README.md
├── cli/               # Python package (entry‑point: python -m cli …)
│   ├── __main__.py         # entry point for `python -m cli`
│   ├── requirements.txt    # CLI dependencies
│   └── cli.py
├── krl/
│   ├── keys.krl        # newline‑delimited SHA‑256 digests
│   └── keys.sig        # detached signature of keys.krl
├── .gitignore          # ignore local .env, keys.log, etc.
├── docker-compose.yml  # run everything w/o host Python
├── Dockerfile          # slim Python 3.11 image
├── INTEGRATION-GUIDE.md  # integration guide for services
├── LICENSE
└── README.md           # this file
```

---

## ✍︎ License

MIT © 2025 Swap.io
