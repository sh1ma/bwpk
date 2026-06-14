package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/sh1ma/bwpk/internal/bwcrypto"
	"github.com/sh1ma/bwpk/internal/ipc"
	"github.com/sh1ma/bwpk/internal/vault"
	"golang.org/x/term"
)

// Unlock flags shared by all subcommands.
var (
	flagData      string
	flagBiometric bool
	flagProxy     string
)

var rootCmd = &cobra.Command{
	Use:   "bwpk",
	Short: "Bitwarden passkey CLI",
	Long: `bwpk reads passkeys (FIDO2/WebAuthn) stored in your local Bitwarden vault
and generates WebAuthn assertions from the command line.

Unlock methods:
  default      master password (env BW_PASSWORD, otherwise prompted)
  --biometric  TouchID (asks the running desktop app via native messaging)
               requires: desktop app running, biometric unlock enabled, browser integration ON`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func init() {
	pf := rootCmd.PersistentFlags()
	pf.StringVar(&flagData, "data", "", "path to data.json (default: "+vault.DefaultDataJSONPath()+")")
	pf.BoolVar(&flagBiometric, "biometric", false, "unlock with TouchID (via the desktop app)")
	pf.StringVar(&flagProxy, "proxy", "", "path to desktop_proxy")

	rootCmd.AddCommand(listCmd, assertCmd, pubkeyCmd)
}

// openAndUnlock opens the vault and obtains the UserKey (via password or TouchID).
func openAndUnlock() (*vault.Vault, *bwcrypto.SymmetricKey, error) {
	dataPath := flagData
	if dataPath == "" {
		dataPath = vault.DefaultDataJSONPath()
	}
	v, err := vault.Open(dataPath)
	if err != nil {
		return nil, nil, err
	}

	if flagBiometric {
		// TouchID: ask the running desktop app via native messaging
		client := ipc.New(flagProxy, v.UserID())
		if err := client.Start(); err != nil {
			return nil, nil, fmt.Errorf("failed to establish biometric channel: %w", err)
		}
		defer client.Close()
		fmt.Fprintln(os.Stderr, "-> Authenticate with TouchID (a prompt appears on the desktop app)...")
		userKey, err := client.UnlockWithBiometrics(v.UserID())
		if err != nil {
			return nil, nil, err
		}
		return v, userKey, nil
	}

	pw := os.Getenv("BW_PASSWORD")
	if pw == "" {
		fmt.Fprintf(os.Stderr, "Master password (%s): ", v.Email())
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read password: %w", err)
		}
		pw = string(b)
	}
	userKey, err := v.Unlock(pw)
	if err != nil {
		return nil, nil, err
	}
	return v, userKey, nil
}
