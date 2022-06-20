package bridge

import (
	"encoding/hex"
	"fmt"
	callsUtil "github.com/ChainSafe/chainbridge-core/chains/evm/calls"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/contracts/bridge"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/evmtransaction"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/transactor"
	"github.com/ChainSafe/chainbridge-core/chains/evm/cli/flags"
	"github.com/ChainSafe/chainbridge-core/chains/evm/cli/initialize"
	"github.com/ChainSafe/chainbridge-core/chains/evm/cli/logger"
	"github.com/ChainSafe/chainbridge-core/util"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var registerNativeResourceCmd = &cobra.Command{
	Use:   "register-native-resource",
	Short: "Register a native resource ID",
	Long:  "The register-native-resource subcommand registers a resource ID with a contract address for a generic handler",
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
		return RegisterNativeResource(cmd, args, bridge.NewBridgeContract(c, BridgeAddr, t))
	},
	Args: func(cmd *cobra.Command, args []string) error {
		err := ValidateRegisterNativeResourceFlags(cmd, args)
		if err != nil {
			return err
		}

		err = ProcessRegisterNativeResourceFlags(cmd, args)
		if err != nil {
			return err
		}

		return nil
	},
}

func BindRegisterNativeResourceFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&Handler, "handler", "", "Handler contract address")
	cmd.Flags().StringVar(&ResourceID, "resource", "", "Resource ID to query")
	cmd.Flags().StringVar(&Bridge, "bridge", "", "Bridge contract address")
	cmd.Flags().StringVar(&Target, "target", "", "Contract address or hash storage to be registered")
	cmd.Flags().StringVar(&Deposit, "deposit", "0x00000000", "Deposit function signature")
	cmd.Flags().StringVar(&Execute, "execute", "0x00000000", "Execute proposal function signature")
	cmd.Flags().BoolVar(&Hash, "hash", false, "Treat signature inputs as function prototype strings, hash and take the first 4 bytes")
	flags.MarkFlagsAsRequired(cmd, "handler", "resource", "bridge", "target")
}

func init() {
	BindRegisterNativeResourceFlags(registerNativeResourceCmd)
}

func ValidateRegisterNativeResourceFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Handler) {
		return fmt.Errorf("invalid handler address %s", Handler)
	}

	if !common.IsHexAddress(Target) {
		return fmt.Errorf("invalid target address %s", Target)
	}

	if !common.IsHexAddress(Bridge) {
		return fmt.Errorf("invalid bridge address %s", Target)
	}

	return nil
}

func ProcessRegisterNativeResourceFlags(cmd *cobra.Command, args []string) error {
	HandlerAddr = common.HexToAddress(Handler)
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

	if Hash {
		DepositSigBytes = callsUtil.GetSolidityFunctionSig([]byte(Deposit))
		ExecuteSigBytes = callsUtil.GetSolidityFunctionSig([]byte(Execute))
	} else {
		copy(DepositSigBytes[:], []byte(Deposit)[:])
		copy(ExecuteSigBytes[:], []byte(Execute)[:])
	}

	return nil
}

func RegisterNativeResource(cmd *cobra.Command, args []string, contract *bridge.BridgeContract) error {
	log.Info().Msgf("Registering contract %s with resource ID %s on handler %s", TargetContractAddr, ResourceID, HandlerAddr)

	hSetResource, err := contract.AdminSetResource(
		HandlerAddr, ResourceIdBytesArr, TargetContractAddr, transactor.TransactOptions{GasLimit: gasLimit},
	)
	if err != nil {
		log.Error().Err(err)
		return err
	}
	log.Info().Msgf("AdminSetResource with transaction: %s", hSetResource.Hex())

	hSetWtoken, err := contract.AdminSetWtoken(
		ResourceIdBytesArr, TargetContractAddr, transactor.TransactOptions{GasLimit: gasLimit},
	)
	if err != nil {
		log.Error().Err(err)
		return err
	}
	log.Info().Msgf("AdminSetWtoken with transaction: %s", hSetWtoken.Hex())

	return nil
}
