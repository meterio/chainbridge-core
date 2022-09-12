package bridge

import (
	"bytes"
	_ "encoding/hex"
	"fmt"
	callsUtil "github.com/ChainSafe/chainbridge-core/chains/evm/calls"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/contracts/bridge"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/contracts/erc20"
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
		return RegisterNativeResource(cmd, args, bridge.NewBridgeContract(c, BridgeAddr, t), erc20.NewERC20HandlerContract(c, HandlerAddr, t))
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
	cmd.Flags().StringVar(&Handler, "handler", "", "Handler contract address, like erc20Handler")
	cmd.Flags().StringVar(&Bridge, "bridge", "", "Bridge contract address")
	cmd.Flags().Uint8Var(&DomainID, "domain", 0, "Domain ID of proposal to cancel")
	flags.MarkFlagsAsRequired(cmd, "handler", "bridge", "domain")
}

func init() {
	BindRegisterNativeResourceFlags(registerNativeResourceCmd)
}

func ValidateRegisterNativeResourceFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Handler) {
		return fmt.Errorf("invalid handler address %s", Handler)
	}

	if !common.IsHexAddress(Bridge) {
		return fmt.Errorf("invalid bridge address %s", Target)
	}

	return nil
}

func ProcessRegisterNativeResourceFlags(cmd *cobra.Command, args []string) error {
	HandlerAddr = common.HexToAddress(Handler)
	BridgeAddr = common.HexToAddress(Bridge)

	zeroAddr := util.ZeroAddress
	addrBytes := zeroAddr.Bytes()
	copy(addrBytes[len(addrBytes)-1:], []byte{DomainID})
	TargetContractAddr = common.BytesToAddress(addrBytes)

	resourceIdBytes := append(addrBytes, DomainID)
	resid := common.LeftPadBytes(resourceIdBytes, 32)
	ResourceIdBytesArr = callsUtil.SliceTo32Bytes(resid)

	return nil
}

func RegisterNativeResource(cmd *cobra.Command, args []string, contract *bridge.BridgeContract, handlerContract *erc20.ERC20HandlerContract) error {
	log.Info().Msgf("Registering contract %s with resource ID %s on handler %s", TargetContractAddr, ResourceID, HandlerAddr)

	getHandlerArr, err := contract.GetHandlerAddressForResourceID(ResourceIdBytesArr)
	if err != nil {
		log.Error().Err(err)
		return err
	}

	if !bytes.Equal(getHandlerArr[:], HandlerAddr[:]) {
		hSetResource, err := contract.AdminSetResource(
			HandlerAddr, ResourceIdBytesArr, TargetContractAddr, transactor.TransactOptions{GasLimit: gasLimit},
		)
		if err != nil {
			log.Error().Err(err)
			return err
		}
		log.Info().Msgf("AdminSetResource with transaction: %s", hSetResource.Hex())
	}

	isNative, err := handlerContract.IsNative(TargetContractAddr)
	if err != nil {
		log.Error().Err(err)
		return err
	}

	if !isNative {
		hSetWtoken, err := contract.AdminSetWtoken(
			ResourceIdBytesArr, TargetContractAddr, transactor.TransactOptions{GasLimit: gasLimit},
		)
		if err != nil {
			log.Error().Err(err)
			return err
		}
		log.Info().Msgf("AdminSetWtoken with transaction: %s", hSetWtoken.Hex())
	}
	return nil
}
