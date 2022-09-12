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

var removeMinterCmd = &cobra.Command{
	Use:   "remove-minter",
	Short: "Remove an ERC20 minter",
	Long:  "The remove-minter subcommand remove a minter from an ERC20 mintable contract",
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
		return RemoveMinterCmd(cmd, args, erc20.NewERC20Contract(c, Erc20Addr, t))
	},
	Args: func(cmd *cobra.Command, args []string) error {
		err := ValidateRemoveMinterFlags(cmd, args)
		if err != nil {
			return err
		}
		ProcessRemoveMinterFlags(cmd, args)
		return nil
	},
}

func BindRemoveMinterFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&Erc20Address, "contract", "", "ERC20 contract address")
	cmd.Flags().StringVar(&Minter, "minter", "", "Minter address")
	flags.MarkFlagsAsRequired(cmd, "contract", "minter")
}

func init() {
	BindRemoveMinterFlags(removeMinterCmd)
}

func ValidateRemoveMinterFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Erc20Address) {
		return fmt.Errorf("invalid ERC20 contract address: %s", Erc20Address)
	}
	if !common.IsHexAddress(Minter) {
		return fmt.Errorf("invalid minter address: %s", Minter)
	}
	return nil
}

func ProcessRemoveMinterFlags(cmd *cobra.Command, args []string) {
	Erc20Addr = common.HexToAddress(Erc20Address)
	MinterAddr = common.HexToAddress(Minter)
}

func RemoveMinterCmd(cmd *cobra.Command, args []string, contract *erc20.ERC20Contract) error {
	_, err := contract.RemoveMinter(MinterAddr, transactor.TransactOptions{GasLimit: gasLimit})
	if err != nil {
		log.Error().Err(err)
		return err
	}

	log.Info().Msgf("%s account revoke minter roles", MinterAddr.String())
	return nil
}
