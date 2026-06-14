package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	listRpID   string
	listAsJSON bool
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List stored passkeys",
	RunE: func(cmd *cobra.Command, args []string) error {
		v, userKey, err := openAndUnlock()
		if err != nil {
			return err
		}
		pks, err := v.Passkeys(userKey, listRpID)
		if err != nil {
			return err
		}

		if listAsJSON {
			type out struct {
				CipherID, CipherName, CredentialID, RpID, RpName, UserName, UserHandle, UserDisplay string
				Counter                                                                             int
				Discoverable                                                                        bool
			}
			list := make([]out, 0, len(pks))
			for _, p := range pks {
				list = append(list, out{p.CipherID, p.CipherName, p.CredentialID, p.RpID, p.RpName, p.UserName, p.UserHandle, p.UserDisplay, p.Counter, p.Discoverable})
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(list)
		}

		if len(pks) == 0 {
			fmt.Println("No passkeys found.")
			return nil
		}
		fmt.Printf("%d passkey(s):\n\n", len(pks))
		for _, p := range pks {
			fmt.Printf("* %s\n", p.RpID)
			fmt.Printf("    cipher : %s (%s)\n", p.CipherName, p.CipherID)
			fmt.Printf("    user   : %s  %s\n", p.UserName, dim(p.UserDisplay))
			fmt.Printf("    credId : %s\n", p.CredentialID)
			fmt.Printf("    flags  : discoverable=%v counter=%d\n\n", p.Discoverable, p.Counter)
		}
		return nil
	},
}

func init() {
	f := listCmd.Flags()
	f.StringVar(&listRpID, "rpid", "", "filter by rpId")
	f.BoolVar(&listAsJSON, "json", false, "output as JSON")
}

func dim(s string) string {
	if s == "" {
		return ""
	}
	return "(" + s + ")"
}
