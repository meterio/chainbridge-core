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

var removeRelayerCmd = &cobra.Command{
	Use:   "remove-relayer",
	Short: "Remove a Signature relayer",
	Long:  "The remove-relayer subcommand remove a relayer from an Signature contract",
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
		return RemoveRelayerCmd(cmd, args, signatures.NewSignaturesContract(c, SignatureAddr, t))
	},
	Args: func(cmd *cobra.Command, args []string) error {
		err := ValidateRemoveRelayerFlags(cmd, args)
		if err != nil {
			return err
		}
		ProcessRemoveRelayerFlags(cmd, args)
		return nil
	},
}

func BindRemoveRelayerFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&Signature, "signature", "", "Signature contract address")
	cmd.Flags().StringVar(&Relayer, "relayer", "", "Relayer address")
	flags.MarkFlagsAsRequired(cmd, "signature", "relayer")
}

func init() {
	BindRemoveRelayerFlags(removeRelayerCmd)
}

func ValidateRemoveRelayerFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Signature) {
		return fmt.Errorf("invalid Signature contract address: %s", Signature)
	}
	if !common.IsHexAddress(Relayer) {
		return fmt.Errorf("invalid relayer address: %s", Relayer)
	}
	return nil
}

func ProcessRemoveRelayerFlags(cmd *cobra.Command, args []string) {
	SignatureAddr = common.HexToAddress(Signature)
	RelayerAddr = common.HexToAddress(Relayer)
}

func RemoveRelayerCmd(cmd *cobra.Command, args []string, contract *signatures.SignaturesContract) error {
	_, err := contract.RemoveRelayer(RelayerAddr, transactor.TransactOptions{GasLimit: gasLimit})
	if err != nil {
		log.Error().Err(err)
		return err
	}

	log.Info().Msgf("%s account revoke relayer roles", RelayerAddr.String())
	return nil
}
