package config

import (
	"fmt"
	"github.com/meterio/chainbridge-core/flags"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"math/big"
	"os"
	"time"

	"github.com/meterio/chainbridge-core/config/relayer"
	"github.com/spf13/viper"
)

type Config struct {
	RelayerConfig relayer.RelayerConfig
	ChainConfigs  []map[string]interface{}
}

type RawConfig struct {
	RelayerConfig relayer.RawRelayerConfig `mapstructure:"relayer" json:"relayer"`
	ChainConfigs  []map[string]interface{} `mapstructure:"chains" json:"chains"`
}

// GetConfig reads config from file, validates it and parses
// it into config suitable for application
func GetConfig(path string) (Config, error) {
	rawConfig := RawConfig{}
	config := Config{}

	viper.SetConfigFile(path)
	viper.SetConfigType("json")

	err := viper.ReadInConfig()
	if err != nil {
		return config, err
	}

	err = viper.Unmarshal(&rawConfig)
	if err != nil {
		return config, err
	}

	relayerConfig, err := relayer.NewRelayerConfig(rawConfig.RelayerConfig)
	if err != nil {
		return config, err
	}
	for _, chain := range rawConfig.ChainConfigs {
		if chain["type"] == "" || chain["type"] == nil {
			return config, fmt.Errorf("Chain 'type' must be provided for every configured chain")
		}
	}

	config.RelayerConfig = relayerConfig
	config.ChainConfigs = rawConfig.ChainConfigs

	logLevel := viper.GetString(flags.LogLevelFlagName)
	setGlobalLevel(logLevel)

	return config, nil
}

func setGlobalLevel(logLevel string) {
	switch logLevel {
	case "panic":
		zerolog.SetGlobalLevel(zerolog.PanicLevel) // 5
	case "fatal":
		zerolog.SetGlobalLevel(zerolog.FatalLevel) // 4
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel) // 3
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel) // 2
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel) // 1
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel) // 0
	case "trace":
		zerolog.SetGlobalLevel(zerolog.TraceLevel) // -1
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.Stamp})
}

var AirDropErc20Amount = big.NewInt(5e17)

const BlockDiff = int64(50)
