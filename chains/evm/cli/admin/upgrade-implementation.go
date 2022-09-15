package admin

import (
	"fmt"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/contracts/proxy"

	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/evmtransaction"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/transactor"
	"github.com/ChainSafe/chainbridge-core/util"

	"github.com/ChainSafe/chainbridge-core/chains/evm/cli/flags"
	"github.com/ChainSafe/chainbridge-core/chains/evm/cli/initialize"
	"github.com/ChainSafe/chainbridge-core/chains/evm/cli/logger"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var upgradeImplementationCmd = &cobra.Command{
	Use:   "upgrade-implementation",
	Short: "Upgrade the implementation of the proxy.",
	Long:  "The upgrade-implementation subcommand Upgrade the implementation of the proxy.",
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
		return UpgradeImplementationEVMCMD(cmd, args, proxy.NewProxyContract(c, ProxyAddr, t))
	},
	Args: func(cmd *cobra.Command, args []string) error {
		err := ValidateUpgradeImplementationFlags(cmd, args)
		if err != nil {
			return err
		}

		ProcessUpgradeImplementationFlags(cmd, args)
		return nil
	},
}

func BindUpgradeImplementationFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&Implementation, "implementation", "", "Address of implementation")
	cmd.Flags().StringVar(&Proxy, "proxy", "", "Proxy contract address")
	flags.MarkFlagsAsRequired(cmd, "implementation", "proxy")
}

func init() {
	BindUpgradeImplementationFlags(changeAdminCmd)
}

func ValidateUpgradeImplementationFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Implementation) {
		return fmt.Errorf("invalid implementation address %s", Implementation)
	}
	if !common.IsHexAddress(Proxy) {
		return fmt.Errorf("invalid proxy address %s", Proxy)
	}
	return nil
}

func ProcessUpgradeImplementationFlags(cmd *cobra.Command, args []string) {
	ImplementationAddr = common.HexToAddress(Implementation)
	ProxyAddr = common.HexToAddress(Proxy)
}

func UpgradeImplementationEVMCMD(cmd *cobra.Command, args []string, contract *proxy.ProxyContract) error {
	log.Debug().Msgf(`
Upgrade To
Implementation address: %s
Proxy address: %s
`, Admin, Proxy)
	_, err := contract.UpgradeTo(ImplementationAddr, transactor.TransactOptions{GasLimit: gasLimit})
	return err
}
