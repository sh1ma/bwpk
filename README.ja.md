# bwpk — Bitwarden パスキー CLI

[English](README.md) | **日本語**

`bwpk` は、Bitwarden に保存された**パスキー（FIDO2 / WebAuthn）をコマンドラインから使う**ための CLI です。

Bitwarden のパスキー機能を**静的解析**でリバースエンジニアリングし、ローカルの Bitwarden
デスクトップアプリの暗号化ストア（`data.json`）を直接復号して動作します。`bw` CLI・公式 SDK・
ネットワーク通信には依存しない自己完結実装です。Vault のアンロックは**マスターパスワード**または
**TouchID（生体認証）**のどちらでも行えます。

> ⚠️ 自分自身の Vault を自分の資格情報でアンロックして使うことを想定したツールです。

---

## 特長

- 🔑 Bitwarden Vault 内のパスキーを一覧表示（`list`）
- ✍️ パスキーで WebAuthn assertion を生成（`assert`）— `navigator.credentials.get()` 互換 JSON
- 👆 **TouchID アンロック**対応（起動中のデスクトップアプリ経由、マスターパスワード不要）
- 📦 自己完結（外部の `bw` CLI 不要、ネットワーク通信なし）

---

## インストール

```bash
go install github.com/sh1ma/bwpk/cmd/bwpk@latest
```

`bwpk` バイナリが `$(go env GOBIN)`（無ければ `$(go env GOPATH)/bin`）に入ります。
そのディレクトリに `PATH` を通してください。

クローンからビルドする場合:

```bash
go build -o bwpk ./cmd/bwpk
```

Go 1.25+ を想定。CLI フレームワークに [spf13/cobra](https://github.com/spf13/cobra) を使用しています。

---

## 使い方

```
bwpk [command] [flags]
```

### グローバルフラグ（全コマンド共通）

| フラグ | 説明 |
|--------|------|
| `--data <path>` | `data.json` のパス（既定は macOS App Store 版の場所を自動使用） |
| `--biometric` | TouchID でアンロック（既定はマスターパスワード） |
| `--proxy <path>` | `desktop_proxy` のパス（既定: `/Applications/Bitwarden.app/Contents/MacOS/desktop_proxy`） |

### `bwpk list` — パスキー一覧

```bash
bwpk list                      # 全パスキー
bwpk list --rpid github.com    # rpId で絞り込み
bwpk list --json               # JSON 出力
```

出力例:

```
1 件のパスキー:

● github.com
    cipher : GitHub (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
    user   : alice  (Alice)
    credId : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    flags  : discoverable=true counter=0
```

### `bwpk assert` — WebAuthn assertion 生成

```bash
bwpk assert --rpid github.com --challenge <base64url-challenge>
```

| フラグ | 説明 |
|--------|------|
| `--rpid <rpId>` | 対象 rpId（必須） |
| `--challenge <b64url>` | RP から受け取った challenge（base64url, 必須） |
| `--origin <origin>` | origin（省略時 `https://<rpid>`） |
| `--cred-id <uuid>` | 同一 rpId に複数該当する場合に使う credentialId |
| `--uv` | User Verified フラグ（既定 true） |
| `--counter-bump` | counter>0 の時に +1（Bitwarden の挙動再現。通常 discoverable は counter=0） |

出力は `navigator.credentials.get()` の結果互換 JSON。`authenticatorData` / `clientDataJSON` /
`signature` / `userHandle` は base64url。RP に渡せばパスキー認証が成立します。

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

## アンロック方法

### マスターパスワード（既定）

環境変数 `BW_PASSWORD` を読み、無ければ対話入力します。

```bash
BW_PASSWORD='****' bwpk list
# または
bwpk list   # → プロンプトで入力
```

`data.json` 内の KDF 設定（PBKDF2 / Argon2id）からマスターキーを導出し、UserKey を復号します。

### TouchID（`--biometric`）

起動中の Bitwarden デスクトップアプリに、ブラウザ拡張と同じ**ネイティブメッセージング**で
生体アンロックを依頼し、UserKey を受け取ります。

```bash
bwpk list   --biometric --rpid github.com
bwpk assert --biometric --rpid github.com --challenge <b64url>
```

**前提条件:**
- Bitwarden デスクトップアプリが**起動中**で、生体アンロックが有効
- デスクトップ設定で「ブラウザ統合を許可」が ON（ネイティブメッセージングホストが導入される）
- 初回接続時はデスクトップ側に信頼確認（指紋フレーズ）ダイアログが出る場合があり、承認が必要

**仕組み:** RSA-2048 でセキュアチャネルを確立（共有秘密は RSA-OAEP-SHA1 で受信）し、
`unlockWithBiometricsForUser` コマンドで TouchID を起動して UserKey を取得します。
appId は `~/.config/bwpk/appid` に永続化され、信頼確認の再利用に使われます。
`BWPK_DEBUG=1` で IPC の往復フレームを stderr に表示できます。

> 補足: このパスキーの秘密鍵は Bitwarden Vault 内のソフトウェア鍵であり、Secure Enclave には
> 入っていません。TouchID は「Vault のアンロック（本人確認）」として機能し、WebAuthn の
> User Verification(UV) フラグを満たします。

---

## 仕組みの概要

本ツールは Bitwarden クライアント（OSS）の挙動を**静的解析**して得た知見に基づき、Go で再実装したものです。

- パスキーは Bitwarden の**ソフトウェア FIDO2 オーセンティケータ**実装で、ES256(-7) / ECDSA P-256 固定。
- 秘密鍵は pkcs8 を base64url した文字列として、Vault item の `login.fido2Credentials[]` に
  各フィールド個別の EncString で暗号化保存される。
- 復号チェーン: `master password` → PBKDF2/Argon2 → MasterKey → HKDF stretch →
  `masterKeyEncryptedUserKey` 復号 → UserKey → 各フィールド復号。
- assertion: `authData = SHA256(rpId) | flags | counter` を作り、
  `ECDSA_P256_SHA256(authData || SHA256(clientDataJSON))` を DER 署名。

---

## プロジェクト構成

| パス | 役割 |
|------|------|
| `cmd/bwpk/` | CLI 本体（cobra）。`root.go` / `list.go` / `assert.go` / `pubkey.go` |
| `internal/bwcrypto/` | 鍵導出（PBKDF2/Argon2id）、HKDF stretch、EncString(type2/0) の復号・暗号化 |
| `internal/vault/` | `data.json` の読込・UserKey 復号・パスキー復号 |
| `internal/fido2/` | authenticatorData 組み立て、COSE 鍵、ECDSA 署名、credentialId 変換 |
| `internal/ipc/` | ネイティブメッセージング（desktop_proxy 経由）で TouchID 生体アンロック |

---

## テスト

```bash
go test ./...
```

- `internal/bwcrypto`: KDF・HKDF・EncString 復号を node(crypto) 生成の参照値と突き合わせ。
- `internal/vault`: 合成 Vault を復号 → assertion 署名 → 公開鍵で検証する E2E。
  （参照データ生成は `/tmp/bw_e2e.mjs`。未生成時は Skip）

---

## 注意

- 本ツールはローカルの自分の Vault を自分のマスターパスワード/TouchID で復号する用途を想定。
- `counter` を進めても Bitwarden 側 Vault には書き戻さない（読み取り専用動作）。Bitwarden の
  discoverable パスキーは元々 counter=0 運用のため通常問題にならない。
- 現状の対応 OS は macOS（デスクトップアプリのパス・Keychain・ソケットが macOS 前提）。
</content>
