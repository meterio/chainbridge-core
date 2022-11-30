package admin

import (
	"fmt"

	"github.com/meterio/chainbridge-core/chains/evm/calls/contracts/bridge"
	"github.com/meterio/chainbridge-core/chains/evm/calls/evmtransaction"
	"github.com/meterio/chainbridge-core/chains/evm/cli/initialize"
	"github.com/meterio/chainbridge-core/util"

	"github.com/ethereum/go-ethereum/common"
	"github.com/meterio/chainbridge-core/chains/evm/cli/flags"
	"github.com/meterio/chainbridge-core/chains/evm/cli/logger"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var getDomainCmd = &cobra.Command{
	Use:   "get-domain-id",
	Short: "Get the relayer domain",
	Long:  "The get-domain-id subcommand returns the relayer domain id",
	PreRun: func(cmd *cobra.Command, args []string) {
		logger.LoggerMetadata(cmd.Name(), cmd.Flags())
	},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return util.CallPersistentPreRun(cmd, args)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := initialize.InitializeClient(url, senderKeyPair)
		if err != nil {
			return err
		}
		t, err := initialize.InitializeTransactor(gasPrice, evmtransaction.NewTransaction, c, prepare)
		if err != nil {
			return err
		}
		return GetDomainCMD(cmd, args, bridge.NewBridgeContract(c, BridgeAddr, t))
	},
	Args: func(cmd *cobra.Command, args []string) error {
		err := ValidateGetDomainFlags(cmd, args)
		if err != nil {
			return err
		}

		ProcessGetDomainFlags(cmd, args)
		return nil
	},
}

func BindGetDomainFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&Bridge, "bridge", "", "Bridge contract address")
	flags.MarkFlagsAsRequired(cmd, "bridge")
}

func init() {
	BindGetDomainFlags(getDomainCmd)
}

func ValidateGetDomainFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Bridge) {
		return fmt.Errorf("invalid bridge address %s", Bridge)
	}
	return nil
}

func ProcessGetDomainFlags(cmd *cobra.Command, args []string) {
	BridgeAddr = common.HexToAddress(Bridge)
}

func GetDomainCMD(cmd *cobra.Command, args []string, contract *bridge.BridgeContract) error {
	log.Debug().Msgf(`
Getting domain
Bridge address: %s`, Bridge)
	threshold, err := contract.GetDomainID()
	if err != nil {
		log.Error().Err(fmt.Errorf("transact error: %v", err))
		return err
	}
	log.Info().Msgf("Relayer domain for the bridge %v is %v", Bridge, threshold)
	return nil
}
