package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sh1ma/bwpk/internal/fido2"
	"github.com/sh1ma/bwpk/internal/vault"
)

var (
	assertRpID         string
	assertChallenge    string
	assertOrigin       string
	assertCredID       string
	assertUV           bool
	assertBump         bool
	assertWithPubliKey bool
)

var assertCmd = &cobra.Command{
	Use:   "assert",
	Short: "Generate a WebAuthn assertion with a passkey",
	Long: `Generates a WebAuthn assertion (navigator.credentials.get()-compatible JSON) for the given rpId.
authenticatorData / clientDataJSON / signature / userHandle in the output are base64url.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		challenge, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(assertChallenge, "="))
		if err != nil {
			return fmt.Errorf("challenge must be base64url: %w", err)
		}
		origin := assertOrigin
		if origin == "" {
			origin = "https://" + assertRpID
		}

		v, userKey, err := openAndUnlock()
		if err != nil {
			return err
		}
		pks, err := v.Passkeys(userKey, assertRpID)
		if err != nil {
			return err
		}
		if len(pks) == 0 {
			return fmt.Errorf("no passkey matching rpId=%s", assertRpID)
		}

		// pick by credentialId if given, otherwise use the first match
		pk := pks[0]
		if assertCredID != "" {
			found := false
			for _, p := range pks {
				if strings.EqualFold(p.CredentialID, assertCredID) {
					pk, found = p, true
					break
				}
			}
			if !found {
				return fmt.Errorf("credentialId=%s not found", assertCredID)
			}
		} else if len(pks) > 1 {
			fmt.Fprintf(os.Stderr, "warning: %d matches. Using the first one (%s). Use --cred-id to choose.\n", len(pks), pk.CredentialID)
		}

		// build clientDataJSON
		clientData := map[string]any{
			"type":      "webauthn.get",
			"challenge": base64.RawURLEncoding.EncodeToString(challenge),
			"origin":    origin,
		}
		clientDataJSON, _ := json.Marshal(clientData)
		clientDataHash := sha256.Sum256(clientDataJSON)

		// extract the private key
		der, err := vault.DecodeKeyValue(pk.KeyValue)
		if err != nil {
			return fmt.Errorf("failed to decode keyValue: %w", err)
		}
		priv, err := fido2.ParsePKCS8ECDSA(der)
		if err != nil {
			return err
		}

		counter := uint32(pk.Counter)
		if assertBump && counter > 0 {
			counter++
		}

		authData, err := fido2.GenerateAuthData(fido2.AuthDataParams{
			RpID:         pk.RpID,
			Counter:      counter,
			UserPresence: true,
			UserVerified: assertUV,
		})
		if err != nil {
			return err
		}
		sig, err := fido2.Sign(authData, clientDataHash[:], priv)
		if err != nil {
			return err
		}
		rawID, err := fido2.ParseCredentialID(pk.CredentialID)
		if err != nil {
			return err
		}
		userHandle, _ := base64.RawURLEncoding.DecodeString(strings.TrimRight(pk.UserHandle, "="))

		// output navigator.credentials.get()-compatible JSON
		result := map[string]any{
			"id":    fido2.B64URL(rawID),
			"rawId": fido2.B64URL(rawID),
			"type":  "public-key",
			"response": map[string]any{
				"authenticatorData": fido2.B64URL(authData),
				"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientDataJSON),
				"signature":         fido2.B64URL(sig),
				"userHandle":        fido2.B64URL(userHandle),
			},
			"authenticatorAttachment": "platform",
			"clientExtensionResults":  map[string]any{},
		}
		// include the public key (PEM) for verification demos (a non-standard extra field)
		if assertWithPubliKey {
			spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
			if err != nil {
				return err
			}
			pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})
			result["publicKeyPem"] = string(pemBytes)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	},
}

func init() {
	f := assertCmd.Flags()
	f.StringVar(&assertRpID, "rpid", "", "target rpId (required)")
	f.StringVar(&assertChallenge, "challenge", "", "challenge (base64url, required)")
	f.StringVar(&assertOrigin, "origin", "", "origin (default https://<rpid>)")
	f.StringVar(&assertCredID, "cred-id", "", "credentialId (UUID) to use when multiple match")
	f.BoolVar(&assertUV, "uv", true, "set the User Verified flag")
	f.BoolVar(&assertBump, "counter-bump", false, "increment counter by 1 when counter>0 (mirrors Bitwarden behavior)")
	f.BoolVar(&assertWithPubliKey, "with-public-key", false, "include publicKeyPem in the output JSON (for verification demos)")
	_ = assertCmd.MarkFlagRequired("rpid")
	_ = assertCmd.MarkFlagRequired("challenge")
}
