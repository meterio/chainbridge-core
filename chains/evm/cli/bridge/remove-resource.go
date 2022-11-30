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

var removeResourceCmd = &cobra.Command{
	Use:   "remove-resource",
	Short: "Remove a resource ID",
	Long:  "The remove-resource subcommand remove a resource ID for a contract address",
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
		return RemoveResourceCmd(cmd, args, bridge.NewBridgeContract(c, BridgeAddr, t))
	},
	Args: func(cmd *cobra.Command, args []string) error {
		err := ValidateRemoveResourceFlags(cmd, args)
		if err != nil {
			return err
		}

		err = ProcessRemoveResourceFlags(cmd, args)
		return err
	},
}

func BindRemoveResourceFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&Bridge, "bridge", "", "Bridge contract address")
	cmd.Flags().StringVar(&Target, "target", "", "Contract address to be removed")
	cmd.Flags().StringVar(&ResourceID, "resource", "", "Resource ID to be removed")
	cmd.Flags().BoolVar(&Native, "native", false, "is Native")
	flags.MarkFlagsAsRequired(cmd, "bridge", "target", "resource")
}

func init() {
	BindRemoveResourceFlags(removeResourceCmd)
}

func ValidateRemoveResourceFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Target) {
		return fmt.Errorf("invalid target address %s", Target)
	}
	if !common.IsHexAddress(Bridge) {
		return fmt.Errorf("invalid bridge address %s", Bridge)
	}
	return nil
}

func ProcessRemoveResourceFlags(cmd *cobra.Command, args []string) error {
	var err error
	TargetContractAddr = common.HexToAddress(Target)
	BridgeAddr = common.HexToAddress(Bridge)

	ResourceIdBytesArr, err = flags.ProcessResourceID(ResourceID)
	return err
}

func RemoveResourceCmd(cmd *cobra.Command, args []string, contract *bridge.BridgeContract) error {
	log.Debug().Msgf(`
Remove resource
Resource ID: %s
Target address: %s
Native: %v
Bridge address: %s
`, ResourceID, Target, Bridge)
	h, err := contract.AdminRemoveResource(
		ResourceIdBytesArr, TargetContractAddr, Native, transactor.TransactOptions{GasLimit: gasLimit},
	)
	if err != nil {
		log.Error().Err(err)
		return err
	}

	log.Info().Msgf("Resource removed with transaction: %s", h.Hex())
	return nil
}
