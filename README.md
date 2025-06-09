# kairo-krl

**Canonical Key-Revocation List for Swap.io**
Signed, tamper-evident registry + CLI for issuing or revoking developer API keys.

---

## 🗝️ Key concept

| Item              | Format / rule                                                                                                                     | Purpose                                                             |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| **Developer key** | `username-<sig>` where `<sig>` = Ed25519 signature of `username`, base58-encoded and trimmed to the first **44** chars (URL-safe) | Shared secret presented by clients (e.g. `alice-5feD...ZQh`)        |
| **KRL entry**     | Hex SHA‑256 of the entire key string (`username-<sig>`)                                                                           | Keeps usernames private while still letting services blacklist keys |
| **keys.sig**      | Ed25519 detached signature of the raw `keys.krl` bytes                                                                            | Lets services verify the file came from Swap.io                     |

The signing / verification key‑pair is stored **only** in your secure ops vault.
Every service just needs the **public** half to verify `keys.sig`.

---

## 📂 Repo layout

```
kairo-krl/
├── README.md
├── cli/
│   ├── __init__.py
│   └── cli.py
├── krl/
│   ├── keys.krl
│   └── keys.sig
├── Dockerfile
├── docker-compose.yml
└── .github/workflows/ci.yml
```

---

## 🔧 Quick start

```bash
# export the maintainer’s private key (once per shell)
export KAIRO_SIGNING_KEY="<base58 Ed25519 private key>"

# build the image
docker compose build

# generate a key for alice
docker compose run --rm cli generate alice

# revoke the user by adding its key to the KRL
docker compose run --rm cli revoke alice
```

`docker compose run --rm cli --help` shows every sub‑command.

---

## 🖥️ CLI reference

| Command                  | What it does                                                                                       |
| ------------------------ | -------------------------------------------------------------------------------------------------- |
| `generate <username>`    | Prints a fresh key (`username-<sig>`), storing a copy with timestamp in `.keys.log` (git‑ignored). |
| `revoke <username\|key>` | Adds the key’s SHA‑256 hash to `krl/keys.krl` (if absent) and re‑signs the file.                   |
| `verify`                 | Confirms that `keys.krl` matches `keys.sig` using `PUBLIC_KEY_BASE58`.                             |

Env vars:

| Variable            | Required                  | Description                                    |
| ------------------- | ------------------------- | ---------------------------------------------- |
| `KAIRO_SIGNING_KEY` | ✔ for `register`/`revoke` | Base58‑encoded private key that signs the KRL. |
| `PUBLIC_KEY_BASE58` | optional                  | Needed for `verify` in readonly contexts.      |

---

## 📜 Local key log

Each successful `generate` run appends a line in the form

```
<ISO8601‑timestamp> <username> <key>
```

to `.keys.log` in the project root. This file is listed in `.gitignore` so personal histories never leak into the public repository.

---

## 🌐 Propagation to services

The KRL that live services consume is **only** the version on the `main` branch. Be sure to **commit and push** your changes—until then, revocations will not propagate.

---

## 🔒 File formats

### `keys.krl`

```
# one digest per line
3b9004522e8ae1dd5b541ebed5187d77e183cc6b74b4d1b3a99fc7d588d5d7a9
e6d23f02bb22c3f9b2ab7572c3bc103f72ed32fef93d4fd778de12e3bfd3e2f6
```

Always sorted; CLI enforces ordering.

### `keys.sig`

```
# base58 Ed25519 signature (~88 chars)
4uU4vYxvYJf3muw4SDWiPEkrLnMJCvNncgXQ5hQ6Qnqed97ugwE3k8uo8jgxEAn5qoBD...
```

---

## 🛡️ How services consume the list

```python
import base58, nacl.signing, hashlib, requests

pubkey = nacl.signing.VerifyKey(base58.b58decode(PUBLIC_KEY_BASE58))
krl     = requests.get("https://raw.githubusercontent.com/swap-io/kairo-krl/main/krl/keys.krl").content
sig     = base58.b58decode(requests.get("https://raw.githubusercontent.com/swap-io/kairo-krl/main/krl/keys.sig").text.strip())

pubkey.verify(krl, sig)   # raises if tampered
bad_hashes = { line.strip() for line in krl.splitlines() }

def is_key_revoked(dev_key: str) -> bool:
    digest = hashlib.sha256(dev_key.encode()).hexdigest()
    return digest in bad_hashes
```

---

## 🏗️ Development

```bash
poetry install
poe test
```

---

## ✍︎ License

MIT License © 2025 Swap.io
