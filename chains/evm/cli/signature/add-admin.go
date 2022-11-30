package signature

import (
	"fmt"
	"github.com/meterio/chainbridge-core/chains/evm/calls/contracts/signatures"

	"github.com/ethereum/go-ethereum/common"
	"github.com/meterio/chainbridge-core/chains/evm/calls/evmtransaction"
	"github.com/meterio/chainbridge-core/chains/evm/calls/transactor"
	"github.com/meterio/chainbridge-core/chains/evm/cli/flags"
	"github.com/meterio/chainbridge-core/chains/evm/cli/initialize"
	"github.com/meterio/chainbridge-core/chains/evm/cli/logger"
	"github.com/meterio/chainbridge-core/util"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var addAdminCmd = &cobra.Command{
	Use:   "add-admin",
	Short: "Add a new Signature admin",
	Long:  "The add-admin subcommand adds a admin to a Signature contract",
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
		return AddAdminCmd(cmd, args, signatures.NewSignaturesContract(c, SignatureAddr, t))
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
	cmd.Flags().StringVar(&Signature, "signature", "", "Signature contract address")
	cmd.Flags().StringVar(&Admin, "admin", "", "Admin address")
	flags.MarkFlagsAsRequired(cmd, "signature", "admin")
}

func init() {
	BindAddAdminFlags(addAdminCmd)
}

func ValidateAddAdminFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Signature) {
		return fmt.Errorf("invalid Signature contract address: %s", Signature)
	}
	if !common.IsHexAddress(Admin) {
		return fmt.Errorf("invalid admin address: %s", Admin)
	}
	return nil
}

func ProcessAddAdminFlags(cmd *cobra.Command, args []string) {
	SignatureAddr = common.HexToAddress(Signature)
	AdminAddr = common.HexToAddress(Admin)
}

func AddAdminCmd(cmd *cobra.Command, args []string, contract *signatures.SignaturesContract) error {
	_, err := contract.AddAdmin(AdminAddr, transactor.TransactOptions{GasLimit: gasLimit})
	if err != nil {
		log.Error().Err(err)
		return err
	}

	log.Info().Msgf("%s account granted admin roles", AdminAddr.String())
	return nil
}
