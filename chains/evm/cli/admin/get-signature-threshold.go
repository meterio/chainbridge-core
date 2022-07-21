package admin

import (
	"fmt"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/contracts/signatures"

	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/evmtransaction"
	"github.com/ChainSafe/chainbridge-core/chains/evm/cli/initialize"
	"github.com/ChainSafe/chainbridge-core/util"

	"github.com/ChainSafe/chainbridge-core/chains/evm/cli/flags"
	"github.com/ChainSafe/chainbridge-core/chains/evm/cli/logger"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var getSignatureThresholdCmd = &cobra.Command{
	Use:   "get-signature-threshold",
	Short: "Get the relayer vote threshold",
	Long:  "The get-signature-threshold subcommand returns the relayer vote threshold",
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
		return GetSignatureThresholdCMD(cmd, args, signatures.NewSignaturesContract(c, SignatureAddr, t))
	},
	Args: func(cmd *cobra.Command, args []string) error {
		err := ValidateGetSignatureThresholdFlags(cmd, args)
		if err != nil {
			return err
		}

		ProcessGetSignatureThresholdFlags(cmd, args)
		return nil
	},
}

func BindGetSignatureThresholdFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&Signature, "signature", "", "Signature contract address")
	cmd.Flags().Uint8Var(&DomainID, "domain", 0, "Domain ID of chain")
	flags.MarkFlagsAsRequired(cmd, "signature")
}
func init() {
	BindGetSignatureThresholdFlags(getSignatureThresholdCmd)
}

func ValidateGetSignatureThresholdFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Signature) {
		return fmt.Errorf("invalid signature address %s", Signature)
	}
	return nil
}

func ProcessGetSignatureThresholdFlags(cmd *cobra.Command, args []string) {
	SignatureAddr = common.HexToAddress(Signature)
}

func GetSignatureThresholdCMD(cmd *cobra.Command, args []string, contract *signatures.SignaturesContract) error {
	log.Debug().Msgf(`
getting threshold
Signature address: %s`, Signature)
	threshold, err := contract.GetThreshold(DomainID)
	if err != nil {
		log.Error().Err(fmt.Errorf("transact error: %v", err))
		return err
	}
	log.Info().Msgf("Relayer threshold for the signature %v is %v", Signature, threshold)
	return nil
}
