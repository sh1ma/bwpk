// Package bwcrypto implements Bitwarden key derivation and EncString encryption/decryption.
// Based on static analysis of the Bitwarden clients.
package bwcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// KDF types (matching data.json's kdfType).
const (
	KdfPBKDF2   = 0
	KdfArgon2id = 1
)

// KdfConfig represents data.json's kdfConfig.
type KdfConfig struct {
	KdfType     int `json:"kdfType"`
	Iterations  int `json:"iterations"`
	Memory      int `json:"memory"`      // Argon2: MiB
	Parallelism int `json:"parallelism"` // Argon2: number of threads
}

// EncString represents a Bitwarden encrypted string "type.iv|ct|mac".
type EncString struct {
	Type int
	IV   []byte
	CT   []byte
	MAC  []byte
}

// ParseEncString parses the "2.<iv>|<ct>|<mac>" form.
func ParseEncString(s string) (*EncString, error) {
	if s == "" {
		return nil, errors.New("empty enc string")
	}
	dot := strings.IndexByte(s, '.')
	if dot < 0 {
		return nil, fmt.Errorf("enc string has no type prefix: %q", short(s))
	}
	t, err := strconv.Atoi(s[:dot])
	if err != nil {
		return nil, fmt.Errorf("invalid enc type: %w", err)
	}
	body := s[dot+1:]
	parts := strings.Split(body, "|")

	es := &EncString{Type: t}
	switch t {
	case 2: // AesCbc256_HmacSha256_B64: iv|ct|mac
		if len(parts) != 3 {
			return nil, fmt.Errorf("type2 requires 3 segments (got %d)", len(parts))
		}
		if es.IV, err = base64.StdEncoding.DecodeString(parts[0]); err != nil {
			return nil, fmt.Errorf("iv decode: %w", err)
		}
		if es.CT, err = base64.StdEncoding.DecodeString(parts[1]); err != nil {
			return nil, fmt.Errorf("ct decode: %w", err)
		}
		if es.MAC, err = base64.StdEncoding.DecodeString(parts[2]); err != nil {
			return nil, fmt.Errorf("mac decode: %w", err)
		}
	case 0: // AesCbc256_B64: iv|ct (no MAC)
		if len(parts) != 2 {
			return nil, fmt.Errorf("type0 requires 2 segments (got %d)", len(parts))
		}
		if es.IV, err = base64.StdEncoding.DecodeString(parts[0]); err != nil {
			return nil, fmt.Errorf("iv decode: %w", err)
		}
		if es.CT, err = base64.StdEncoding.DecodeString(parts[1]); err != nil {
			return nil, fmt.Errorf("ct decode: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported enc type: %d", t)
	}
	return es, nil
}

// SymmetricKey holds a 32-byte encryption key plus a 32-byte MAC key.
// It can also represent a 32-byte key without a MAC key (e.g. a pre-stretch MasterKey).
type SymmetricKey struct {
	Enc []byte // 32 bytes
	Mac []byte // 32 bytes (nil if absent)
}

// Key builds a SymmetricKey from a 32-byte or 64-byte slice.
func Key(b []byte) (*SymmetricKey, error) {
	switch len(b) {
	case 32:
		return &SymmetricKey{Enc: b}, nil
	case 64:
		return &SymmetricKey{Enc: b[:32], Mac: b[32:]}, nil
	default:
		return nil, fmt.Errorf("invalid key length: %d bytes", len(b))
	}
}

// Bytes returns the concatenated key bytes.
func (k *SymmetricKey) Bytes() []byte {
	if k.Mac == nil {
		return k.Enc
	}
	return append(append([]byte{}, k.Enc...), k.Mac...)
}

// DeriveMasterKey derives a 32-byte MasterKey from the master password.
func DeriveMasterKey(password, email string, cfg KdfConfig) (*SymmetricKey, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	switch cfg.KdfType {
	case KdfPBKDF2:
		mk := pbkdf2.Key([]byte(password), []byte(email), cfg.Iterations, 32, sha256.New)
		return &SymmetricKey{Enc: mk}, nil
	case KdfArgon2id:
		salt := sha256.Sum256([]byte(email))
		mk := argon2.IDKey([]byte(password), salt[:], uint32(cfg.Iterations), uint32(cfg.Memory*1024), uint8(cfg.Parallelism), 32)
		return &SymmetricKey{Enc: mk}, nil
	default:
		return nil, fmt.Errorf("unsupported KDF type: %d", cfg.KdfType)
	}
}

// StretchKey expands a 32-byte key into 64 bytes (enc||mac) via HKDF-Expand(SHA256).
func StretchKey(k *SymmetricKey) (*SymmetricKey, error) {
	if len(k.Enc) != 32 || k.Mac != nil {
		return nil, errors.New("stretchKey requires a 32-byte key")
	}
	enc := make([]byte, 32)
	mac := make([]byte, 32)
	if _, err := hkdf.Expand(sha256.New, k.Enc, []byte("enc")).Read(enc); err != nil {
		return nil, err
	}
	if _, err := hkdf.Expand(sha256.New, k.Enc, []byte("mac")).Read(mac); err != nil {
		return nil, err
	}
	return &SymmetricKey{Enc: enc, Mac: mac}, nil
}

// Decrypt decrypts an EncString with the key and returns the plaintext bytes.
func Decrypt(es *EncString, k *SymmetricKey) ([]byte, error) {
	switch es.Type {
	case 2:
		if k.Mac == nil {
			return nil, errors.New("type2 decryption requires a MAC key")
		}
		// MAC check: HMAC-SHA256(macKey, iv||ct)
		mac := hmac.New(sha256.New, k.Mac)
		mac.Write(es.IV)
		mac.Write(es.CT)
		if subtle.ConstantTimeCompare(mac.Sum(nil), es.MAC) != 1 {
			return nil, errors.New("MAC verification failed (wrong key or corrupted data)")
		}
		return aesCbcDecrypt(k.Enc, es.IV, es.CT)
	case 0:
		return aesCbcDecrypt(k.Enc, es.IV, es.CT)
	default:
		return nil, fmt.Errorf("unsupported enc type: %d", es.Type)
	}
}

// DecryptString decrypts an EncString and returns the plaintext string.
func DecryptString(s string, k *SymmetricKey) (string, error) {
	es, err := ParseEncString(s)
	if err != nil {
		return "", err
	}
	b, err := Decrypt(es, k)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Encrypt encrypts plaintext as type2 (AesCbc256_HmacSha256_B64) and returns an EncString.
// Used for sending over the native-messaging secure channel.
func Encrypt(plaintext []byte, k *SymmetricKey, iv []byte) (*EncString, error) {
	if k.Mac == nil {
		return nil, errors.New("type2 encryption requires a MAC key")
	}
	if len(iv) != aes.BlockSize {
		return nil, errors.New("IV must be 16 bytes")
	}
	block, err := aes.NewCipher(k.Enc)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plaintext)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

	mac := hmac.New(sha256.New, k.Mac)
	mac.Write(iv)
	mac.Write(ct)
	return &EncString{Type: 2, IV: iv, CT: ct, MAC: mac.Sum(nil)}, nil
}

// String returns the EncString in "2.<iv>|<ct>|<mac>" form.
func (es *EncString) String() string {
	switch es.Type {
	case 2:
		return "2." + b64(es.IV) + "|" + b64(es.CT) + "|" + b64(es.MAC)
	case 0:
		return "0." + b64(es.IV) + "|" + b64(es.CT)
	default:
		return ""
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func pkcs7Pad(b []byte) []byte {
	pad := aes.BlockSize - len(b)%aes.BlockSize
	out := make([]byte, len(b)+pad)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

func aesCbcDecrypt(key, iv, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ct)%aes.BlockSize != 0 || len(ct) == 0 {
		return nil, errors.New("invalid ciphertext length")
	}
	if len(iv) != aes.BlockSize {
		return nil, errors.New("invalid IV length")
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ct)
	return pkcs7Unpad(out)
}

func pkcs7Unpad(b []byte) ([]byte, error) {
	n := len(b)
	if n == 0 {
		return nil, errors.New("empty plaintext")
	}
	pad := int(b[n-1])
	if pad == 0 || pad > aes.BlockSize || pad > n {
		return nil, errors.New("invalid PKCS7 padding")
	}
	for _, c := range b[n-pad:] {
		if int(c) != pad {
			return nil, errors.New("invalid PKCS7 padding")
		}
	}
	return b[:n-pad], nil
}

func short(s string) string {
	if len(s) > 16 {
		return s[:16] + "..."
	}
	return s
}
