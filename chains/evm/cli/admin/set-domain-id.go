package admin

import (
	"fmt"

	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/contracts/bridge"
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

var setDomainCmd = &cobra.Command{
	Use:   "set-domain-id",
	Short: "Set a new relayer domain",
	Long:  "The set-domain-id subcommand sets a new relayer domain",
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
		return SetDomainCMD(cmd, args, bridge.NewBridgeContract(c, BridgeAddr, t))
	},
	Args: func(cmd *cobra.Command, args []string) error {
		err := ValidateSetDomainFlags(cmd, args)
		if err != nil {
			return err
		}

		ProcessSetDomainFlags(cmd, args)
		return nil
	},
}

func BindSetDomainFlags(cmd *cobra.Command) {
	cmd.Flags().Uint8Var(&DomainID, "domain", 0, "New relayer domain")
	cmd.Flags().StringVar(&Bridge, "bridge", "", "Bridge contract address")
	flags.MarkFlagsAsRequired(cmd, "domain", "bridge")
}

func init() {
	BindSetDomainFlags(setDomainCmd)
}

func ValidateSetDomainFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Bridge) {
		return fmt.Errorf("invalid bridge address %s", Bridge)
	}
	return nil
}

func ProcessSetDomainFlags(cmd *cobra.Command, args []string) {
	BridgeAddr = common.HexToAddress(Bridge)
}

func SetDomainCMD(cmd *cobra.Command, args []string, contract *bridge.BridgeContract) error {
	log.Debug().Msgf(`
Setting new domain
DomainID: %d
Bridge address: %s`, DomainID, Bridge)
	_, err := contract.AdminSetDomainId(DomainID, transactor.TransactOptions{GasLimit: gasLimit})
	if err != nil {
		return err
	}
	return nil
}
