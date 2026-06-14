# bwpk — Bitwarden passkey CLI

**English** | [日本語](README.ja.md)

`bwpk` is a CLI for **using passkeys (FIDO2 / WebAuthn) stored in Bitwarden from the command line**.

It is based on **static analysis** (reverse engineering) of Bitwarden's passkey feature, and works by
directly decrypting the local Bitwarden desktop app's encrypted store (`data.json`). It is a
self-contained implementation with no dependency on the `bw` CLI, the official SDK, or network access.
The vault can be unlocked with either a **master password** or **TouchID (biometrics)**.

> ⚠️ This tool is intended for unlocking your own vault with your own credentials.

---

## Features

- 🔑 List passkeys in your Bitwarden vault (`list`)
- ✍️ Generate WebAuthn assertions with a passkey (`assert`) — `navigator.credentials.get()`-compatible JSON
- 👆 **TouchID unlock** (via the running desktop app, no master password needed)
- 📦 Self-contained (no external `bw` CLI, no network access)

---

## Install

```bash
go install github.com/sh1ma/bwpk/cmd/bwpk@latest
```

This installs the `bwpk` binary into `$(go env GOBIN)` (or `$(go env GOPATH)/bin`).
Make sure that directory is on your `PATH`.

Or build from a clone:

```bash
go build -o bwpk ./cmd/bwpk
```

Requires Go 1.24+. The CLI is built with [spf13/cobra](https://github.com/spf13/cobra).

---

## Usage

```
bwpk [command] [flags]
```

### Global flags (all commands)

| Flag | Description |
|------|-------------|
| `--data <path>` | Path to `data.json` (defaults to the macOS App Store location) |
| `--biometric` | Unlock with TouchID (default is master password) |
| `--proxy <path>` | Path to `desktop_proxy` (default: `/Applications/Bitwarden.app/Contents/MacOS/desktop_proxy`) |

### `bwpk list` — list passkeys

```bash
bwpk list                      # all passkeys
bwpk list --rpid github.com    # filter by rpId
bwpk list --json               # JSON output
```

Example output:

```
1 passkey(s):

* github.com
    cipher : GitHub (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
    user   : alice  (Alice)
    credId : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    flags  : discoverable=true counter=0
```

### `bwpk assert` — generate a WebAuthn assertion

```bash
bwpk assert --rpid github.com --challenge <base64url-challenge>
```

| Flag | Description |
|------|-------------|
| `--rpid <rpId>` | Target rpId (required) |
| `--challenge <b64url>` | Challenge received from the RP (base64url, required) |
| `--origin <origin>` | Origin (defaults to `https://<rpid>`) |
| `--cred-id <uuid>` | credentialId to use when multiple passkeys match the same rpId |
| `--uv` | Set the User Verified flag (default true) |
| `--counter-bump` | Increment counter by 1 when counter>0 (mirrors Bitwarden; discoverable passkeys are usually counter=0) |

The output is `navigator.credentials.get()`-compatible JSON. `authenticatorData` / `clientDataJSON` /
`signature` / `userHandle` are base64url. Pass it to the RP to complete passkey authentication.

```json
{
  "id": "<base64url-credentialId>",
  "rawId": "<base64url-credentialId>",
  "type": "public-key",
  "response": {
    "authenticatorData": "<base64url>",
    "clientDataJSON": "<base64url>",
    "signature": "<base64url-DER-signature>",
    "userHandle": "<base64url>"
  },
  "authenticatorAttachment": "platform",
  "clientExtensionResults": {}
}
```

---

## Unlock methods

### Master password (default)

Reads the `BW_PASSWORD` environment variable, or prompts interactively if unset.

```bash
BW_PASSWORD='****' bwpk list
# or
bwpk list   # prompts for input
```

It derives the master key from the KDF config (PBKDF2 / Argon2id) in `data.json` and decrypts the UserKey.

### TouchID (`--biometric`)

Asks the running Bitwarden desktop app for a biometric unlock via the same **native messaging**
channel the browser extension uses, and receives the UserKey back.

```bash
bwpk list   --biometric --rpid github.com
bwpk assert --biometric --rpid github.com --challenge <b64url>
```

**Requirements:**
- The Bitwarden desktop app is **running** with biometric unlock enabled
- "Allow browser integration" is ON in the desktop settings (this installs the native messaging host)
- On the first connection, the desktop may show a trust-confirmation (fingerprint phrase) dialog that you must approve

**How it works:** it establishes a secure channel with RSA-2048 (the shared secret is received via
RSA-OAEP-SHA1), then runs the `unlockWithBiometricsForUser` command to trigger TouchID and obtain the
UserKey. The appId is persisted at `~/.config/bwpk/appid` to reuse the trust confirmation.
Set `BWPK_DEBUG=1` to print the IPC frames to stderr.

> Note: this passkey's private key is a software key inside the Bitwarden vault — it is **not** in the
> Secure Enclave. TouchID acts as "unlock the vault (user verification)" and satisfies the WebAuthn
> User Verification (UV) flag.

---

## How it works

This tool is a Go reimplementation based on insights gained from **static analysis** of the
Bitwarden clients (open source).

- Passkeys use Bitwarden's **software FIDO2 authenticator**, fixed to ES256 (-7) / ECDSA P-256.
- The private key is stored as a base64url-encoded pkcs8 string, encrypted per-field as an EncString
  under the vault item's `login.fido2Credentials[]`.
- Decryption chain: `master password` → PBKDF2/Argon2 → MasterKey → HKDF stretch →
  decrypt `masterKeyEncryptedUserKey` → UserKey → decrypt each field.
- Assertion: build `authData = SHA256(rpId) | flags | counter`, then DER-sign
  `ECDSA_P256_SHA256(authData || SHA256(clientDataJSON))`.

---

## Project layout

| Path | Role |
|------|------|
| `cmd/bwpk/` | CLI (cobra). `root.go` / `list.go` / `assert.go` / `pubkey.go` |
| `internal/bwcrypto/` | Key derivation (PBKDF2/Argon2id), HKDF stretch, EncString (type2/0) encrypt/decrypt |
| `internal/vault/` | Read `data.json`, decrypt UserKey, decrypt passkeys |
| `internal/fido2/` | Build authenticatorData, COSE key, ECDSA signing, credentialId conversion |
| `internal/ipc/` | Native messaging (via desktop_proxy) for TouchID biometric unlock |

---

## Tests

```bash
go test ./...
```

- `internal/bwcrypto`: checks KDF / HKDF / EncString decryption against reference values generated with node(crypto).
- `internal/vault`: an E2E test that decrypts a synthetic vault → signs an assertion → verifies with the public key.
  (Reference data is generated by `/tmp/bw_e2e.mjs`; the test is skipped if absent.)

---

## Notes

- This tool is intended for decrypting your own local vault with your own master password / TouchID.
- Advancing `counter` is not written back to the Bitwarden vault (read-only behavior). Bitwarden's
  discoverable passkeys use counter=0 by design, so this is usually a non-issue.
- Currently macOS only (the desktop app paths, Keychain, and socket assume macOS).
</content>
