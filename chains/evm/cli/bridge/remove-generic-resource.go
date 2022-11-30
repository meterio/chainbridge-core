package bridge

import (
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	callsUtil "github.com/meterio/chainbridge-core/chains/evm/calls"
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

var removeGenericResourceCmd = &cobra.Command{
	Use:   "remove-generic-resource",
	Short: "Remove a generic resource ID",
	Long:  "The remove-generic-resource subcommand remove a resource ID with a contract address for a generic handler",
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
		return RemoveGenericResource(cmd, args, bridge.NewBridgeContract(c, BridgeAddr, t))
	},
	Args: func(cmd *cobra.Command, args []string) error {
		err := ValidateRemoveGenericResourceFlags(cmd, args)
		if err != nil {
			return err
		}

		err = ProcessRemoveGenericResourceFlags(cmd, args)
		if err != nil {
			return err
		}

		return nil
	},
}

func BindRemoveGenericResourceFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&ResourceID, "resource", "", "Resource ID to query")
	cmd.Flags().StringVar(&Bridge, "bridge", "", "Bridge contract address")
	cmd.Flags().StringVar(&Target, "target", "", "Contract address or hash storage to be removed")
	flags.MarkFlagsAsRequired(cmd, "resource", "bridge", "target")
}

func init() {
	BindRemoveGenericResourceFlags(removeGenericResourceCmd)
}

func ValidateRemoveGenericResourceFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Target) {
		return fmt.Errorf("invalid target address %s", Target)
	}

	if !common.IsHexAddress(Bridge) {
		return fmt.Errorf("invalid bridge address %s", Target)
	}

	return nil
}

func ProcessRemoveGenericResourceFlags(cmd *cobra.Command, args []string) error {
	TargetContractAddr = common.HexToAddress(Target)
	BridgeAddr = common.HexToAddress(Bridge)

	if ResourceID[0:2] == "0x" {
		ResourceID = ResourceID[2:]
	}

	resourceIdBytes, err := hex.DecodeString(ResourceID)
	if err != nil {
		return err
	}

	ResourceIdBytesArr = callsUtil.SliceTo32Bytes(resourceIdBytes)

	return nil
}

func RemoveGenericResource(cmd *cobra.Command, args []string, contract *bridge.BridgeContract) error {
	log.Info().Msgf("Remove contract %s with resource ID %s", TargetContractAddr, ResourceID)

	h, err := contract.AdminRemoveGenericResource(
		ResourceIdBytesArr,
		TargetContractAddr,
		transactor.TransactOptions{GasLimit: gasLimit},
	)
	if err != nil {
		log.Error().Err(err)
		return err
	}

	log.Info().Msgf("Remove resource removed with transaction: %s", h.Hex())
	return nil
}
