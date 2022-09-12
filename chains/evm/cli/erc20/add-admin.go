package erc20

import (
	"fmt"

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

var addAdminCmd = &cobra.Command{
	Use:   "add-admin",
	Short: "Add a new ERC20 admin",
	Long:  "The add-admin subcommand adds a admin to an ERC20 mintable contract",
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
		return AddAdminCmd(cmd, args, erc20.NewERC20Contract(c, Erc20Addr, t))
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
	cmd.Flags().StringVar(&Erc20Address, "contract", "", "ERC20 contract address")
	cmd.Flags().StringVar(&Minter, "admin", "", "Admin address")
	flags.MarkFlagsAsRequired(cmd, "contract", "admin")
}

func init() {
	BindAddAdminFlags(addAdminCmd)
}

func ValidateAddAdminFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Erc20Address) {
		return fmt.Errorf("invalid ERC20 contract address: %s", Erc20Address)
	}
	if !common.IsHexAddress(Minter) {
		return fmt.Errorf("invalid admin address: %s", Minter)
	}
	return nil
}

func ProcessAddAdminFlags(cmd *cobra.Command, args []string) {
	Erc20Addr = common.HexToAddress(Erc20Address)
	MinterAddr = common.HexToAddress(Minter)
}

func AddAdminCmd(cmd *cobra.Command, args []string, contract *erc20.ERC20Contract) error {
	_, err := contract.AddAdmin(MinterAddr, transactor.TransactOptions{GasLimit: gasLimit})
	if err != nil {
		log.Error().Err(err)
		return err
	}

	log.Info().Msgf("%s account granted admin roles", MinterAddr.String())
	return nil
}
