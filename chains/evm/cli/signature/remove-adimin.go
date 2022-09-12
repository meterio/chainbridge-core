package signature

import (
	"fmt"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/contracts/signatures"

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

var removeAdminCmd = &cobra.Command{
	Use:   "remove-admin",
	Short: "Remove an Signature admin",
	Long:  "The remove-admin subcommand remove an admin from an Signature contract",
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
		return RemoveAdminCmd(cmd, args, signatures.NewSignaturesContract(c, SignatureAddr, t))
	},
	Args: func(cmd *cobra.Command, args []string) error {
		err := ValidateRemoveAdminFlags(cmd, args)
		if err != nil {
			return err
		}
		ProcessRemoveAdminFlags(cmd, args)
		return nil
	},
}

func BindRemoveAdminFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&Signature, "signature", "", "Signature contract address")
	cmd.Flags().StringVar(&Admin, "admin", "", "Admin address")
	flags.MarkFlagsAsRequired(cmd, "signature", "admin")
}

func init() {
	BindRemoveAdminFlags(removeAdminCmd)
}

func ValidateRemoveAdminFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Signature) {
		return fmt.Errorf("invalid Signature contract address: %s", Signature)
	}
	if !common.IsHexAddress(Admin) {
		return fmt.Errorf("invalid admin address: %s", Admin)
	}
	return nil
}

func ProcessRemoveAdminFlags(cmd *cobra.Command, args []string) {
	SignatureAddr = common.HexToAddress(Signature)
	AdminAddr = common.HexToAddress(Admin)
}

func RemoveAdminCmd(cmd *cobra.Command, args []string, contract *signatures.SignaturesContract) error {
	_, err := contract.RemoveAdmin(AdminAddr, transactor.TransactOptions{GasLimit: gasLimit})
	if err != nil {
		log.Error().Err(err)
		return err
	}

	log.Info().Msgf("%s account revoke admin roles", AdminAddr.String())
	return nil
}
