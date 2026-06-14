package fido2

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// ParseCredentialID converts a Bitwarden credentialId string into raw bytes.
// A "b64." prefix means base64url; otherwise it is parsed as a standard UUID (16 bytes).
func ParseCredentialID(s string) ([]byte, error) {
	if strings.HasPrefix(s, "b64.") {
		return base64.RawURLEncoding.DecodeString(strings.TrimRight(s[4:], "="))
	}
	return guidToRaw(s)
}

func guidToRaw(guid string) ([]byte, error) {
	h := strings.ReplaceAll(guid, "-", "")
	if len(h) != 32 {
		return nil, fmt.Errorf("invalid UUID: %q", guid)
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("failed to decode UUID: %w", err)
	}
	return b, nil
}
