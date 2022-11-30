package admin

import (
	"fmt"
	"github.com/meterio/chainbridge-core/chains/evm/calls/contracts/bridge"
	"github.com/meterio/chainbridge-core/chains/evm/calls/evmtransaction"
	"github.com/meterio/chainbridge-core/chains/evm/calls/transactor"
	"github.com/meterio/chainbridge-core/chains/evm/cli/initialize"

	"github.com/ethereum/go-ethereum/common"
	"github.com/meterio/chainbridge-core/chains/evm/cli/flags"
	"github.com/meterio/chainbridge-core/chains/evm/cli/logger"
	"github.com/meterio/chainbridge-core/util"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var addAdminCmd = &cobra.Command{
	Use:   "add-admin",
	Short: "Add a new admin",
	Long:  "The add-admin subcommand sets an address as a bridge admin",
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
		return AddAdminCMD(cmd, args, bridge.NewBridgeContract(c, BridgeAddr, t))
	},
	Args: func(cmd *cobra.Command, args []string) error {
		err := ValidateAddAdminFlags(cmd, args)
		if err != nil {
			return err
		}

		ProcessAddAdminFlags(cmd, args)
		return nil
	},
}

func BindAddAdminFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&Admin, "admin", "", "Address to add")
	cmd.Flags().StringVar(&Bridge, "bridge", "", "Bridge contract address")
	flags.MarkFlagsAsRequired(cmd, "admin", "bridge")
}

func init() {
	BindAddAdminFlags(addAdminCmd)
}

func ValidateAddAdminFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Admin) {
		return fmt.Errorf("invalid admin address %s", Admin)
	}
	if !common.IsHexAddress(Bridge) {
		return fmt.Errorf("invalid bridge address %s", Bridge)
	}
	return nil
}

func ProcessAddAdminFlags(cmd *cobra.Command, args []string) {
	AdminAddr = common.HexToAddress(Admin)
	BridgeAddr = common.HexToAddress(Bridge)
}

func AddAdminCMD(cmd *cobra.Command, args []string, contract *bridge.BridgeContract) error {
	log.Debug().Msgf(`
Adding admin
Admin address: %s
Bridge address: %s`, Admin, Bridge)
	role, err := contract.DefaultAdminRole()
	if err != nil {
		log.Error().Err(fmt.Errorf("failed contract call error: %v", err))
		return err
	}

	_, err = contract.GrantRole(role, AdminAddr, transactor.TransactOptions{GasLimit: gasLimit})

	return err
}

/*
func addAdmin(cctx *cli.Context) error {
	url := cctx.String("url")
	gasLimit := cctx.Uint64("gasLimit")
	gasPrice := cctx.Uint64("gasPrice")
	sender, err := cliutils.DefineSender(cctx)
	if err != nil {
		return err
	}
	bridgeAddress, err := cliutils.DefineBridgeAddress(cctx)
	if err != nil {
		return err
	}
	admin := cctx.String("admin")
	if !common.IsHexAddress(admin) {
		return fmt.Errorf("invalid admin address %s", admin)
	}
	adminAddress := common.HexToAddress(admin)
	ethClient, err := client.NewClient(url, false, sender, big.NewInt(0).SetUint64(gasLimit), big.NewInt(0).SetUint64(gasPrice), big.NewFloat(1))
	if err != nil {
		return err
	}
	err = utils.AdminAddAdmin(ethClient, bridgeAddress, adminAddress)
	if err != nil {
		return err
	}
	log.Info().Msgf("Address %s is set to admin", adminAddress.String())
	return nil
}
*/
