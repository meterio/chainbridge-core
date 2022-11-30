package admin

import (
	"fmt"

	"github.com/meterio/chainbridge-core/chains/evm/calls/contracts/bridge"
	"github.com/meterio/chainbridge-core/chains/evm/calls/evmtransaction"
	"github.com/meterio/chainbridge-core/chains/evm/calls/transactor"
	"github.com/meterio/chainbridge-core/util"

	"github.com/ethereum/go-ethereum/common"
	"github.com/meterio/chainbridge-core/chains/evm/cli/flags"
	"github.com/meterio/chainbridge-core/chains/evm/cli/initialize"
	"github.com/meterio/chainbridge-core/chains/evm/cli/logger"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var renounceAdminCmd = &cobra.Command{
	Use:   "renounce-admin",
	Short: "Removes admin role from currentAdmin and grants it to newAdmin.",
	Long:  "The renounce-admin subcommand sets an address as a bridge admin",
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
		return RenounceAdminEVMCMD(cmd, args, bridge.NewBridgeContract(c, BridgeAddr, t))
	},
	Args: func(cmd *cobra.Command, args []string) error {
		err := ValidateRenounceAdminFlags(cmd, args)
		if err != nil {
			return err
		}

		ProcessRenounceAdminFlags(cmd, args)
		return nil
	},
}

func BindRenounceAdminFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&Admin, "admin", "", "Address to renounce")
	cmd.Flags().StringVar(&Bridge, "bridge", "", "Bridge contract address")
	flags.MarkFlagsAsRequired(cmd, "admin", "bridge")
}

func init() {
	BindRenounceAdminFlags(renounceAdminCmd)
}

func ValidateRenounceAdminFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Admin) {
		return fmt.Errorf("invalid admin address %s", Admin)
	}
	if !common.IsHexAddress(Bridge) {
		return fmt.Errorf("invalid bridge address %s", Bridge)
	}
	return nil
}

func ProcessRenounceAdminFlags(cmd *cobra.Command, args []string) {
	AdminAddr = common.HexToAddress(Admin)
	BridgeAddr = common.HexToAddress(Bridge)
}

func RenounceAdminEVMCMD(cmd *cobra.Command, args []string, contract *bridge.BridgeContract) error {
	log.Debug().Msgf(`
Renounce admin
Admin address: %s
Bridge address: %s`, Admin, Bridge)
	_, err := contract.RenounceAdmin(AdminAddr, transactor.TransactOptions{GasLimit: gasLimit})
	return err
}
