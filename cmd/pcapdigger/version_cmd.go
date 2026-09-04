package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"pcapdigger/internal/version"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the pcapdigger version",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println(version.String())
			return nil
		},
	}
}
