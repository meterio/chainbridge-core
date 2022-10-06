package chain

import (
	"fmt"
	"github.com/ChainSafe/chainbridge-core/flags"
	"github.com/ChainSafe/chainbridge-core/util"
	"github.com/spf13/viper"
)

type GeneralChainConfig struct {
	Name           string `mapstructure:"name"`
	Id             *uint8 `mapstructure:"id"`
	RelayId        *uint8 `mapstructure:"relayId"`
	Endpoint       string `mapstructure:"endpoint"`
	Replica        string `mapstructure:"replica"`
	From           string `mapstructure:"from"`
	Type           string `mapstructure:"type"`
	KeystorePath   string
	Insecure       bool
	BlockstorePath string
	FreshStart     bool
	FreshDomain    uint
	LatestBlock    bool
}

func (c *GeneralChainConfig) Validate() error {
	// viper defaults to 0 for not specified ints
	if c.Id == nil {
		return fmt.Errorf("required field domain.Id empty for chain %v", c.Id)
	}
	if c.Endpoint == "" {
		return fmt.Errorf("required field chain.Endpoint empty for chain %v", *c.Id)
	}
	if c.Name == "" {
		return fmt.Errorf("required field chain.Name empty for chain %v", *c.Id)
	}
	if c.From == "" {
		return fmt.Errorf("required field chain.From empty for chain %v", *c.Id)
	}
	return nil
}

func (c *GeneralChainConfig) ParseFlags() {
	if path := viper.GetString(flags.TestKeyFlagName); path != "" {
		c.KeystorePath = path
		c.Insecure = true
	} else {
		c.KeystorePath = viper.GetString(flags.KeystoreFlagName)
	}
	c.BlockstorePath = viper.GetString(flags.BlockstoreFlagName)
	c.FreshStart = viper.GetBool(flags.FreshStartFlagName)
	c.FreshDomain = viper.GetUint(flags.FreshDomainFlagName)
	c.LatestBlock = viper.GetBool(flags.LatestBlockFlagName)
}

func (c *GeneralChainConfig) DomainIdToName() {
	domainId := *c.Id

	if _, ok := util.DomainIdToName[domainId]; !ok {
		util.DomainIdToName[domainId] = c.Name
	}
}
