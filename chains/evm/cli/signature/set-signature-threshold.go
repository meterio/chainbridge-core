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

var setSignatureThresholdCmd = &cobra.Command{
	Use:   "set-threshold",
	Short: "Set a new signature vote threshold",
	Long:  "The set-threshold subcommand sets a new relayer vote threshold",
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
		return SetSignatureThresholdCMD(cmd, args, signatures.NewSignaturesContract(c, SignatureAddr, t))
	},
	Args: func(cmd *cobra.Command, args []string) error {
		err := ValidateSetSignatureThresholdFlags(cmd, args)
		if err != nil {
			return err
		}

		ProcessSetSignatureThresholdFlags(cmd, args)
		return nil
	},
}

func BindSetSignatureThresholdFlags(cmd *cobra.Command) {
	cmd.Flags().Uint8Var(&DomainID, "domain", 0, "Domain ID of chain")
	cmd.Flags().Uint64Var(&SignatureThreshold, "threshold", 0, "New relayer threshold")
	cmd.Flags().StringVar(&Signature, "signature", "", "Signature contract address")
	flags.MarkFlagsAsRequired(cmd, "threshold", "signature", "domain")
}

func init() {
	BindSetSignatureThresholdFlags(setSignatureThresholdCmd)
}

func ValidateSetSignatureThresholdFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Signature) {
		return fmt.Errorf("invalid signature address %s", Signature)
	}
	return nil
}

func ProcessSetSignatureThresholdFlags(cmd *cobra.Command, args []string) {
	SignatureAddr = common.HexToAddress(Signature)
}

func SetSignatureThresholdCMD(cmd *cobra.Command, args []string, contract *signatures.SignaturesContract) error {
	log.Debug().Msgf(`
Setting new threshold
Threshold: %d
Signature address: %s`, SignatureThreshold, Signature)
	_, err := contract.SetThresholdInput(DomainID, SignatureThreshold, transactor.TransactOptions{GasLimit: gasLimit})
	if err != nil {
		return err
	}
	return nil
}
