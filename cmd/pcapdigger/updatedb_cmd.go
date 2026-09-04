package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"pcapdigger/internal/config"
	"pcapdigger/internal/enrich/updatedb"
)

func newUpdateDBCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update-db",
		Short: "Download/refresh the MaxMind GeoLite2 City+ASN databases",
		Long: "Downloads the GeoLite2-City and GeoLite2-ASN databases into ~/.config/pcapdigger/data\n" +
			"using the account_id/license_key from config (set via `pcapdigger config set`).\n" +
			"This is the only command that reaches out to the network on its own initiative.",
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := resolvePaths()
			if err != nil {
				return err
			}
			cfg, err := config.Load(p)
			if err != nil {
				return err
			}
			opts := updatedb.Options{
				DataDir:      p.DataDir,
				ManifestPath: p.ManifestPath(),
				Editions:     []string{"GeoLite2-City", "GeoLite2-ASN"},
			}
			creds := updatedb.Credentials{AccountID: cfg.MaxMind.AccountID, LicenseKey: cfg.MaxMind.LicenseKey}
			return updatedb.Update(creds, opts, func(s string) { fmt.Println(s) })
		},
	}
}
