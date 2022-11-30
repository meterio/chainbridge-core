package admin

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/meterio/chainbridge-core/chains/evm/calls/contracts/signatures"
	"github.com/meterio/chainbridge-core/chains/evm/calls/evmtransaction"
	"github.com/meterio/chainbridge-core/chains/evm/cli/flags"
	"github.com/meterio/chainbridge-core/chains/evm/cli/initialize"
	"github.com/meterio/chainbridge-core/chains/evm/cli/logger"
	"github.com/meterio/chainbridge-core/util"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var getDestChainIdCmd = &cobra.Command{
	Use:   "get-dest-chain-id",
	Short: "Mapping dest DomainID to ChainID",
	Long:  "The get-dest-chain-id subcommand get dest chainID of domainID",
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
		return GetDestChainIdCMD(cmd, args, signatures.NewSignaturesContract(c, SignatureAddr, t))
	},
	Args: func(cmd *cobra.Command, args []string) error {
		err := ValidateGetDestChainIdFlags(cmd, args)
		if err != nil {
			return err
		}

		ProcessGetDestChainIdFlags(cmd, args)
		return nil
	},
}

func BindGetDestChainIdFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&Signature, "signature", "", "Signature contract address")
	cmd.Flags().Uint8Var(&DomainID, "domain", 0, "Domain ID of Dest")
	flags.MarkFlagsAsRequired(cmd, "signature", "domain")
}

func init() {
	BindGetDestChainIdFlags(getDestChainIdCmd)
}
func ValidateGetDestChainIdFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Signature) {
		return fmt.Errorf("invalid bridge address %s", Signature)
	}
	return nil
}

func ProcessGetDestChainIdFlags(cmd *cobra.Command, args []string) {
	SignatureAddr = common.HexToAddress(Signature)
}

func GetDestChainIdCMD(cmd *cobra.Command, args []string, contract *signatures.SignaturesContract) error {
	log.Debug().Msgf(`
Get dest ChainID
DomainID: %v
Signature address: %s`, DomainID, Signature)

	chainID, err := contract.GetDestChainId(DomainID)
	if err != nil {
		return err
	}

	log.Info().Msgf("ChainID for the Signature %v is %v", Signature, chainID)

	return nil
}
