package bridge

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/meterio/chainbridge-core/chains/evm/calls/contracts/bridge"
	"github.com/meterio/chainbridge-core/chains/evm/calls/evmtransaction"
	"github.com/meterio/chainbridge-core/chains/evm/calls/transactor"
	"github.com/meterio/chainbridge-core/chains/evm/cli/flags"
	"github.com/meterio/chainbridge-core/chains/evm/cli/initialize"
	"github.com/meterio/chainbridge-core/chains/evm/cli/logger"
	"github.com/meterio/chainbridge-core/util"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var removeNativeResourceCmd = &cobra.Command{
	Use:   "remove-native-resource",
	Short: "Remove native resource",
	Long:  "The remove-native-resource subcommand remove native resource for a contract address",
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
		return RemoveNativeResourceCmd(cmd, args, bridge.NewBridgeContract(c, BridgeAddr, t))
	},
	Args: func(cmd *cobra.Command, args []string) error {
		err := ValidateRemoveNativeResourceFlags(cmd, args)
		if err != nil {
			return err
		}

		err = ProcessRemoveNativeResourceFlags(cmd, args)
		return err
	},
}

func BindRemoveNativeResourceFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&Bridge, "bridge", "", "Bridge contract address")
	flags.MarkFlagsAsRequired(cmd, "bridge")
}

func init() {
	BindRemoveNativeResourceFlags(removeNativeResourceCmd)
}

func ValidateRemoveNativeResourceFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Bridge) {
		return fmt.Errorf("invalid bridge address %s", Bridge)
	}
	return nil
}

func ProcessRemoveNativeResourceFlags(cmd *cobra.Command, args []string) error {
	var err error
	BridgeAddr = common.HexToAddress(Bridge)

	return err
}

func RemoveNativeResourceCmd(cmd *cobra.Command, args []string, contract *bridge.BridgeContract) error {
	log.Debug().Msgf(`
Remove native resource
Bridge address: %s
`, Bridge)
	h, err := contract.AdminRemoveNativeResourceId(
		transactor.TransactOptions{GasLimit: gasLimit},
	)
	if err != nil {
		log.Error().Err(err)
		return err
	}

	log.Info().Msgf("Native resource removed with transaction: %s", h.Hex())
	return nil
}
