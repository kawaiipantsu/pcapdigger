// Command pcapdigger loads a pcap/pcapng file, analyzes it, and produces
// network-engineering, security-architect, and executive reports in
// JSON/CSV/Markdown, plus an SVG flow diagram.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"pcapdigger/internal/config"
)

func main() {
	root := newRootCmd()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "pcapdigger",
		Short:         "Analyze PCAP/PCAPNG files and generate multi-audience reports",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(newAnalyzeCmd())
	cmd.AddCommand(newConfigCmd())
	cmd.AddCommand(newUpdateDBCmd())
	cmd.AddCommand(newVersionCmd())
	return cmd
}

// resolvePaths is a small shared helper so every subcommand resolves and
// creates the ~/.config/pcapdigger tree the same way.
func resolvePaths() (config.Paths, error) {
	p, err := config.ResolvePaths()
	if err != nil {
		return config.Paths{}, err
	}
	if err := p.EnsureDirs(); err != nil {
		return config.Paths{}, err
	}
	return p, nil
}
