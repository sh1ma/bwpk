// Package fido2 reimplements Bitwarden's software FIDO2 authenticator in Go.
// Corresponds to Bitwarden's generateAuthData / generateSignature.
package fido2

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
)

// AAGUID is Bitwarden's fixed AAGUID (d548826e-79b4-db40-a3d8-11116f7e8349).
var AAGUID = []byte{
	0xd5, 0x48, 0x82, 0x6e, 0x79, 0xb4, 0xdb, 0x40,
	0xa3, 0xd8, 0x11, 0x11, 0x6f, 0x7e, 0x83, 0x49,
}

// authData flags (W3C WebAuthn).
const (
	flagUP = 0x01 // User Present
	flagUV = 0x04 // User Verified
	flagBE = 0x08 // Backup Eligible
	flagBS = 0x10 // Backup State
	flagAT = 0x40 // includes attested credential data
)

// AuthDataParams holds parameters for building authenticatorData.
type AuthDataParams struct {
	RpID         string
	Counter      uint32
	UserPresence bool
	UserVerified bool
	// If PublicKey is non-nil, attestedCredentialData is appended (for makeCredential).
	PublicKey    *ecdsa.PublicKey
	CredentialID []byte // raw credentialId for attestedCredentialData
}

// GenerateAuthData builds the authenticatorData.
func GenerateAuthData(p AuthDataParams) ([]byte, error) {
	rpHash := sha256.Sum256([]byte(p.RpID))
	buf := make([]byte, 0, 37+len(p.CredentialID)+100)
	buf = append(buf, rpHash[:]...)

	// flags: BE/BS are always true in Bitwarden (credentials are synced)
	var flags byte = flagBE | flagBS
	if p.UserPresence {
		flags |= flagUP
	}
	if p.UserVerified {
		flags |= flagUV
	}
	if p.PublicKey != nil {
		flags |= flagAT
	}
	buf = append(buf, flags)

	var counter [4]byte
	binary.BigEndian.PutUint32(counter[:], p.Counter)
	buf = append(buf, counter[:]...)

	if p.PublicKey != nil {
		buf = append(buf, AAGUID...)
		var credLen [2]byte
		binary.BigEndian.PutUint16(credLen[:], uint16(len(p.CredentialID)))
		buf = append(buf, credLen[:]...)
		buf = append(buf, p.CredentialID...)
		cose, err := coseEC2Key(p.PublicKey)
		if err != nil {
			return nil, err
		}
		buf = append(buf, cose...)
	}
	return buf, nil
}

// coseEC2Key encodes an EC P-256 public key as a CTAP2 canonical CBOR COSE_Key
// (the same hand-built 77-byte format as Bitwarden).
func coseEC2Key(pub *ecdsa.PublicKey) ([]byte, error) {
	x := pub.X.Bytes()
	y := pub.Y.Bytes()
	if len(x) > 32 || len(y) > 32 {
		return nil, errors.New("P-256 coordinate exceeds 32 bytes")
	}
	out := make([]byte, 77)
	// A5 01 02 03 26 20 01 21 58 20 | X(32) | 22 58 20 | Y(32)
	copy(out[0:], []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20})
	copy(out[10+(32-len(x)):], x) // left zero-pad
	copy(out[42:], []byte{0x22, 0x58, 0x20})
	copy(out[45+(32-len(y)):], y)
	return out, nil
}

// ParsePKCS8ECDSA extracts an ECDSA private key from pkcs8 DER.
func ParsePKCS8ECDSA(der []byte) (*ecdsa.PrivateKey, error) {
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pkcs8: %w", err)
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA key: %T", k)
	}
	return ec, nil
}

// AssertionResult is the result of a get-assertion.
type AssertionResult struct {
	AuthenticatorData []byte
	Signature         []byte // ASN.1 DER
	CredentialIDRaw   []byte
	UserHandle        []byte
}

// Sign produces an ECDSA P-256/SHA-256 signature (DER) over (authData || clientDataHash).
func Sign(authData, clientDataHash []byte, priv *ecdsa.PrivateKey) ([]byte, error) {
	sigBase := append(append([]byte{}, authData...), clientDataHash...)
	digest := sha256.Sum256(sigBase)
	// ecdsa.SignASN1 returns the ASN.1 DER signature WebAuthn expects (no p1363ToDer needed).
	return ecdsa.SignASN1(rand.Reader, priv, digest[:])
}

// helper: base64url (no padding) encoding.
func B64URL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
