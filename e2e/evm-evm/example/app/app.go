// Copyright 2021 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package app

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/meterio/chainbridge-core/chains/evm"
	"github.com/meterio/chainbridge-core/chains/evm/calls/evmtransaction"
	"github.com/meterio/chainbridge-core/config"
	"github.com/meterio/chainbridge-core/flags"
	"github.com/meterio/chainbridge-core/lvldb"
	"github.com/meterio/chainbridge-core/opentelemetry"
	"github.com/meterio/chainbridge-core/relayer"
	"github.com/meterio/chainbridge-core/store"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

func Run() error {
	configuration, err := config.GetConfig(viper.GetString(flags.ConfigFlagName))
	if err != nil {
		panic(err)
	}

	db, err := lvldb.NewLvlDB(viper.GetString(flags.BlockstoreFlagName))
	if err != nil {
		panic(err)
	}
	blockstore := store.NewBlockStore(db)

	var openTelemetryInst *opentelemetry.OpenTelemetry

	metricsCollectorURL := viper.GetString(flags.MetricUrlFlagName)
	if metricsCollectorURL != "" {
		openTelemetryInst, err = opentelemetry.NewOpenTelemetry(metricsCollectorURL)
		if err != nil {
			panic(err)
		}
	}

	chains := []relayer.RelayedChain{}
	for _, chainConfig := range configuration.ChainConfigs {
		switch chainConfig["type"] {
		case "evm":
			{
				chain, err := evm.SetupDefaultEVMChain(openTelemetryInst, chainConfig, evmtransaction.NewTransaction, blockstore)
				if err != nil {
					panic(err)
				}

				chains = append(chains, chain)
			}
		default:
			panic(fmt.Errorf("Type '%s' not recognized", chainConfig["type"]))
		}
	}

	r := relayer.NewRelayer(
		chains,
		&opentelemetry.ConsoleTelemetry{},
	)

	errChn := make(chan error)
	stopChn := make(chan struct{})
	go r.Start(stopChn, errChn)

	sysErr := make(chan os.Signal, 1)
	signal.Notify(sysErr,
		syscall.SIGTERM,
		syscall.SIGINT,
		syscall.SIGHUP,
		syscall.SIGQUIT)

	select {
	case err := <-errChn:
		log.Error().Err(err).Msg("failed to listen and serve")
		close(stopChn)
		return err
	case sig := <-sysErr:
		log.Info().Msgf("terminating got ` [%v] signal", sig)
		return nil
	}
}
