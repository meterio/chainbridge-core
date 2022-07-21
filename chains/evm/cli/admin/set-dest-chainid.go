package admin

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

var setDestChainIdCmd = &cobra.Command{
	Use:   "set-dest-chain-id",
	Short: "Mapping dest DomainID to ChainID",
	Long:  "The set-dest-chain-id subcommand mapping dest domainID to chainID",
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
		return SetDestChainIdCMD(cmd, args, signatures.NewSignaturesContract(c, SignatureAddr, t))
	},
	Args: func(cmd *cobra.Command, args []string) error {
		err := ValidateSetDestChainIdFlags(cmd, args)
		if err != nil {
			return err
		}

		ProcessSetDestChainIdFlags(cmd, args)
		return nil
	},
}

func BindSetDestChainIdFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&Signature, "signature", "", "Signature contract address")
	cmd.Flags().Uint8Var(&DomainID, "domain", 0, "Domain ID of Dest")
	cmd.Flags().Uint8Var(&ChainID, "chainId", 0, "Chain ID of Dest")
	flags.MarkFlagsAsRequired(cmd, "signature", "domain", "chainId")
}

func init() {
	BindSetDestChainIdFlags(setDestChainIdCmd)
}
func ValidateSetDestChainIdFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Signature) {
		return fmt.Errorf("invalid bridge address %s", Signature)
	}
	return nil
}

func ProcessSetDestChainIdFlags(cmd *cobra.Command, args []string) {
	SignatureAddr = common.HexToAddress(Signature)
}

func SetDestChainIdCMD(cmd *cobra.Command, args []string, contract *signatures.SignaturesContract) error {
	log.Debug().Msgf(`
Setting dest ChainID
DomainID: %v
ChainID: %v
Signature address: %s`, DomainID, ChainID, Signature)

	_, err := contract.AdminSetDestChainId(DomainID, ChainID, transactor.TransactOptions{GasLimit: gasLimit})
	if err != nil {
		return err
	}

	return nil
}
