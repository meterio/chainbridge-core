// Copyright 2021 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package cmd

import (
	evmCLI "github.com/meterio/chainbridge-core/chains/evm/cli"
	"github.com/meterio/chainbridge-core/chains/evm/cli/local"
	"github.com/meterio/chainbridge-core/e2e/evm-evm/example/app"
	"github.com/meterio/chainbridge-core/flags"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	rootCMD = &cobra.Command{
		Use: "",
	}
	runCMD = &cobra.Command{
		Use:   "run",
		Short: "Run example app",
		Long:  "Run example app",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := app.Run(); err != nil {
				return err
			}
			return nil
		},
	}
)

func init() {
	flags.BindFlags(runCMD)
}

func Execute() {
	rootCMD.AddCommand(runCMD, evmCLI.EvmRootCLI, local.LocalSetupCmd)
	if err := rootCMD.Execute(); err != nil {
		log.Fatal().Err(err).Msg("failed to execute root cmd")
	}
}
