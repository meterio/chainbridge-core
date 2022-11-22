package chain

import (
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/consts"
	"github.com/mitchellh/mapstructure"
)

type EVMConfig struct {
	GeneralChainConfig GeneralChainConfig
	Bridge             string
	Erc20Handler       string
	Erc721Handler      string
	GenericHandler     string
	MaxGasPrice        *big.Int
	GasMultiplier      *big.Float
	GasLimit           *big.Int
	StartBlock         *big.Int
	BlockConfirmations *big.Int
	BlockRetryInterval time.Duration

	AirDropAmount        *big.Int
	AirDropErc20Contract common.Address
	AirDropErc20Amount   *big.Int
	MoonbeamFinality     bool // blocks are needed to implicitly confirm the finality
	PolygonGasStation    bool

	SignatureContract common.Address
	SignatureSubmit   bool
}

type RawEVMConfig struct {
	GeneralChainConfig `mapstructure:",squash"`
	Bridge             string  `mapstructure:"bridge"`
	Erc20Handler       string  `mapstructure:"erc20Handler"`
	Erc721Handler      string  `mapstructure:"erc721Handler"`
	GenericHandler     string  `mapstructure:"genericHandler"`
	MaxGasPrice        int64   `mapstructure:"maxGasPrice"`
	GasMultiplier      float64 `mapstructure:"gasMultiplier"`
	GasLimit           int64   `mapstructure:"gasLimit"`
	StartBlock         int64   `mapstructure:"startBlock"`
	BlockConfirmations int64   `mapstructure:"blockConfirmations"`
	BlockRetryInterval uint64  `mapstructure:"blockRetryInterval"`

	AirDropAmountOpt        int64  `mapstructure:"airDropAmount"`
	AirDropErc20ContractOpt string `mapstructure:"airDropErc20Contract"`
	AirDropErc20AmountOpt   int64  `mapstructure:"airDropErc20Amount"`
	MoonbeamFinalityOpt     bool   `mapstructure:"moonbeamFinality"`
	PolygonGasStationOpt    bool   `mapstructure:"polygonGasStation"`

	SignatureContractOpt string `mapstructure:"signatureContract"`
	SignatureSubmit      bool   `mapstructure:"signatureSubmit"`
}

func (c *RawEVMConfig) Validate() error {
	if err := c.GeneralChainConfig.Validate(); err != nil {
		return err
	}

	if c.SignatureContractOpt == "" && c.Bridge == "" {
		return fmt.Errorf("required field chain.Bridge empty for chain %v", *c.Id)
	}
	if c.BlockConfirmations != 0 && c.BlockConfirmations < 1 {
		return fmt.Errorf("blockConfirmations has to be >=1")
	}

	return nil
}

// NewEVMConfig decodes and validates an instance of an EVMConfig from
// raw chain config
func NewEVMConfig(chainConfig map[string]interface{}) (*EVMConfig, error) {
	var c RawEVMConfig
	err := mapstructure.Decode(chainConfig, &c)
	if err != nil {
		return nil, err
	}

	err = c.Validate()
	if err != nil {
		return nil, err
	}

	c.GeneralChainConfig.ParseFlags()
	c.GeneralChainConfig.DomainIdToName()
	config := &EVMConfig{
		GeneralChainConfig: c.GeneralChainConfig,
		Erc20Handler:       c.Erc20Handler,
		Erc721Handler:      c.Erc721Handler,
		GenericHandler:     c.GenericHandler,
		Bridge:             c.Bridge,
		BlockRetryInterval: consts.DefaultBlockRetryInterval,
		GasLimit:           big.NewInt(consts.DefaultGasLimit),
		MaxGasPrice:        big.NewInt(consts.DefaultGasPrice),
		GasMultiplier:      big.NewFloat(consts.DefaultGasMultiplier),
		StartBlock:         big.NewInt(c.StartBlock),
		BlockConfirmations: big.NewInt(consts.DefaultBlockConfirmations),

		AirDropAmount:        big.NewInt(0),
		AirDropErc20Contract: common.Address{},
		AirDropErc20Amount:   big.NewInt(0),
		MoonbeamFinality:     false,
		PolygonGasStation:    false,

		SignatureContract: common.Address{},
		SignatureSubmit:   c.SignatureSubmit,
	}

	if c.GasLimit != 0 {
		config.GasLimit = big.NewInt(c.GasLimit)
	}

	if c.MaxGasPrice != 0 {
		config.MaxGasPrice = big.NewInt(c.MaxGasPrice)
	}

	if c.GasMultiplier != 0 {
		config.GasMultiplier = big.NewFloat(c.GasMultiplier)
	}

	if c.BlockConfirmations != 0 {
		config.BlockConfirmations = big.NewInt(c.BlockConfirmations)
	}

	if c.BlockRetryInterval != 0 {
		config.BlockRetryInterval = time.Duration(c.BlockRetryInterval) * time.Second
	}

	if c.AirDropAmountOpt != 0 {
		config.AirDropAmount = big.NewInt(c.AirDropAmountOpt)
	}

	if c.AirDropErc20ContractOpt != "" {
		config.AirDropErc20Contract = common.HexToAddress(c.AirDropErc20ContractOpt)
	}

	if c.AirDropErc20AmountOpt != 0 {
		config.AirDropErc20Amount = big.NewInt(c.AirDropErc20AmountOpt)
	}

	if c.MoonbeamFinalityOpt {
		config.MoonbeamFinality = c.MoonbeamFinalityOpt
	}

	if c.PolygonGasStationOpt {
		config.PolygonGasStation = c.PolygonGasStationOpt
	}

	if c.SignatureContractOpt != "" {
		config.SignatureContract = common.HexToAddress(c.SignatureContractOpt)
	}

	return config, nil
}

func (c *EVMConfig) RelayId() uint8 {
	if c.GeneralChainConfig.RelayId == nil {
		return 0
	}
	return *c.GeneralChainConfig.RelayId
}
