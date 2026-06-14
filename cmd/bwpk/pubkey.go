package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sh1ma/bwpk/internal/fido2"
	"github.com/sh1ma/bwpk/internal/vault"
)

var (
	pubkeyRpID   string
	pubkeyCredID string
)

var pubkeyCmd = &cobra.Command{
	Use:   "pubkey",
	Short: "Print a passkey's public key (PEM/SPKI), e.g. for verification demos",
	Long: `Prints the public key (PEM/SPKI) of the passkey for the given rpId to stdout.
This corresponds to the public key the RP stores at registration and can be used
to verify signatures produced by 'assert'. (The public key is not secret.)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		v, userKey, err := openAndUnlock()
		if err != nil {
			return err
		}
		pks, err := v.Passkeys(userKey, pubkeyRpID)
		if err != nil {
			return err
		}
		if len(pks) == 0 {
			return fmt.Errorf("no passkey matching rpId=%s", pubkeyRpID)
		}
		pk := pks[0]
		if pubkeyCredID != "" {
			found := false
			for _, p := range pks {
				if strings.EqualFold(p.CredentialID, pubkeyCredID) {
					pk, found = p, true
					break
				}
			}
			if !found {
				return fmt.Errorf("credentialId=%s not found", pubkeyCredID)
			}
		}

		der, err := vault.DecodeKeyValue(pk.KeyValue)
		if err != nil {
			return fmt.Errorf("failed to decode keyValue: %w", err)
		}
		priv, err := fido2.ParsePKCS8ECDSA(der)
		if err != nil {
			return err
		}
		spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if err != nil {
			return err
		}
		return pem.Encode(os.Stdout, &pem.Block{Type: "PUBLIC KEY", Bytes: spki})
	},
}

func init() {
	f := pubkeyCmd.Flags()
	f.StringVar(&pubkeyRpID, "rpid", "", "target rpId (required)")
	f.StringVar(&pubkeyCredID, "cred-id", "", "credentialId (UUID) to use when multiple match")
	_ = pubkeyCmd.MarkFlagRequired("rpid")
}
