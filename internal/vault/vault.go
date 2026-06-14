// Package vault reads the Bitwarden desktop local store data.json and
// decrypts passkey credentials with the master password.
package vault

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/sh1ma/bwpk/internal/bwcrypto"
)

// DefaultDataJSONPath is the default data.json path for the macOS (App Store) desktop app.
func DefaultDataJSONPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "Containers", "com.bitwarden.desktop",
		"Data", "Library", "Application Support", "Bitwarden", "data.json")
}

// Passkey is a decrypted passkey credential.
type Passkey struct {
	CipherID     string
	CipherName   string
	CredentialID string // UUID string (may have a "b64." prefix)
	RpID         string
	RpName       string
	UserName     string
	UserHandle   string // base64url
	UserDisplay  string
	Counter      int
	Discoverable bool
	KeyValue     string // base64url of the pkcs8 private key
}

// Vault parses data.json and provides decryption operations.
type Vault struct {
	raw    map[string]json.RawMessage
	userID string
	email  string
	kdf    bwcrypto.KdfConfig
}

// Open reads data.json and selects the active user.
func Open(path string) (*Vault, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read data.json: %w", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse data.json: %w", err)
	}
	v := &Vault{raw: raw}

	// determine the active user ID
	if b, ok := raw["global_account_activeAccountId"]; ok {
		_ = json.Unmarshal(b, &v.userID)
	}
	if v.userID == "" {
		v.userID = detectUserID(raw)
	}
	if v.userID == "" {
		return nil, fmt.Errorf("could not determine user ID")
	}

	// email
	if b, ok := raw["global_loginEmail_storedEmail"]; ok {
		_ = json.Unmarshal(b, &v.email)
	}
	if v.email == "" {
		v.email = detectEmail(raw, v.userID)
	}

	// kdfConfig
	if b, ok := raw[v.key("kdfConfig_kdfConfig")]; ok {
		if err := json.Unmarshal(b, &v.kdf); err != nil {
			return nil, fmt.Errorf("failed to parse kdfConfig: %w", err)
		}
	} else {
		return nil, fmt.Errorf("kdfConfig not found")
	}
	return v, nil
}

func (v *Vault) key(suffix string) string { return "user_" + v.userID + "_" + suffix }

// UserID returns the selected user's ID.
func (v *Vault) UserID() string { return v.userID }

// Email returns the selected user's email address.
func (v *Vault) Email() string { return v.email }

// KdfConfig returns the KDF configuration.
func (v *Vault) KdfConfig() bwcrypto.KdfConfig { return v.kdf }

// Unlock derives the UserKey from the master password.
func (v *Vault) Unlock(password string) (*bwcrypto.SymmetricKey, error) {
	masterKey, err := bwcrypto.DeriveMasterKey(password, v.email, v.kdf)
	if err != nil {
		return nil, err
	}
	stretched, err := bwcrypto.StretchKey(masterKey)
	if err != nil {
		return nil, err
	}
	var encUserKey string
	if b, ok := v.raw[v.key("masterPassword_masterKeyEncryptedUserKey")]; ok {
		_ = json.Unmarshal(b, &encUserKey)
	}
	if encUserKey == "" {
		return nil, fmt.Errorf("masterKeyEncryptedUserKey not found")
	}
	userKeyBytes, err := bwcrypto.DecryptString(encUserKey, stretched)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt UserKey (wrong password?): %w", err)
	}
	return bwcrypto.Key([]byte(userKeyBytes))
}

// --- cipher model (only the parts of the encrypted cipher we need) ---

type rawCipher struct {
	ID    string    `json:"id"`
	Name  string    `json:"name"`
	Type  int       `json:"type"`
	Key   *string   `json:"key"`
	Login *rawLogin `json:"login"`
}

type rawLogin struct {
	Fido2Credentials []map[string]any `json:"fido2Credentials"`
}

// Passkeys decrypts and returns all passkeys. If rpIDFilter is non-empty, it filters by rpId.
func (v *Vault) Passkeys(userKey *bwcrypto.SymmetricKey, rpIDFilter string) ([]Passkey, error) {
	b, ok := v.raw[v.key("ciphers_ciphers")]
	if !ok {
		return nil, fmt.Errorf("ciphers not found")
	}
	var ciphers map[string]rawCipher
	if err := json.Unmarshal(b, &ciphers); err != nil {
		return nil, fmt.Errorf("failed to parse ciphers: %w", err)
	}

	var out []Passkey
	for _, c := range ciphers {
		if c.Login == nil || len(c.Login.Fido2Credentials) == 0 {
			continue
		}
		// if the cipher has its own key, decrypt it with the UserKey; otherwise use the UserKey directly
		itemKey := userKey
		if c.Key != nil && *c.Key != "" {
			kb, err := bwcrypto.DecryptString(*c.Key, userKey)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt key of cipher %s: %w", c.ID, err)
			}
			itemKey, err = bwcrypto.Key([]byte(kb))
			if err != nil {
				return nil, err
			}
		}

		name, _ := bwcrypto.DecryptString(c.Name, userKey)
		for _, f := range c.Login.Fido2Credentials {
			pk, err := decryptPasskey(f, itemKey)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt passkey of cipher %s: %w", c.ID, err)
			}
			pk.CipherID = c.ID
			pk.CipherName = name
			if rpIDFilter != "" && pk.RpID != rpIDFilter {
				continue
			}
			out = append(out, pk)
		}
	}
	return out, nil
}

func decryptPasskey(f map[string]any, key *bwcrypto.SymmetricKey) (Passkey, error) {
	get := func(field string) (string, error) {
		raw, ok := f[field]
		if !ok || raw == nil {
			return "", nil
		}
		s, ok := raw.(string)
		if !ok || s == "" {
			return "", nil
		}
		return bwcrypto.DecryptString(s, key)
	}
	var pk Passkey
	var err error
	if pk.CredentialID, err = get("credentialId"); err != nil {
		return pk, fmt.Errorf("credentialId: %w", err)
	}
	if pk.KeyValue, err = get("keyValue"); err != nil {
		return pk, fmt.Errorf("keyValue: %w", err)
	}
	if pk.RpID, err = get("rpId"); err != nil {
		return pk, fmt.Errorf("rpId: %w", err)
	}
	pk.RpName, _ = get("rpName")
	pk.UserName, _ = get("userName")
	pk.UserHandle, _ = get("userHandle")
	pk.UserDisplay, _ = get("userDisplayName")
	if cs, _ := get("counter"); cs != "" {
		pk.Counter, _ = strconv.Atoi(strings.TrimSpace(cs))
	}
	if ds, _ := get("discoverable"); ds != "" {
		pk.Discoverable = strings.EqualFold(strings.TrimSpace(ds), "true")
	}
	return pk, nil
}

// DecodeKeyValue converts keyValue (base64url) into pkcs8 DER bytes.
func DecodeKeyValue(keyValue string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(keyValue, "="))
}

// --- helpers: infer user ID / email ---

var userKeyRe = regexp.MustCompile(`^user_([0-9a-fA-F-]{36})_`)

func detectUserID(raw map[string]json.RawMessage) string {
	for k := range raw {
		if m := userKeyRe.FindStringSubmatch(k); m != nil {
			return m[1]
		}
	}
	return ""
}

func detectEmail(raw map[string]json.RawMessage, userID string) string {
	// global_account_accounts: { "<uid>": { "email": "...", "name": "..." } }
	if b, ok := raw["global_account_accounts"]; ok {
		var accounts map[string]struct {
			Email string `json:"email"`
		}
		if json.Unmarshal(b, &accounts) == nil {
			if a, ok := accounts[userID]; ok {
				return a.Email
			}
		}
	}
	return ""
}
