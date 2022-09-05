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

var changeAdminCmd = &cobra.Command{
	Use:   "change-admin",
	Short: "Change admin role from currentAdmin and grants it to newAdmin.",
	Long:  "The change-admin subcommand sets an address as a proxy admin",
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
		return ChangeAdminEVMCMD(cmd, args, proxy.NewProxyContract(c, ProxyAddr, t))
	},
	Args: func(cmd *cobra.Command, args []string) error {
		err := ValidateChangeAdminFlags(cmd, args)
		if err != nil {
			return err
		}

		ProcessChangeAdminFlags(cmd, args)
		return nil
	},
}

func BindChangeAdminFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&Admin, "admin", "", "Address to be admin")
	cmd.Flags().StringVar(&Proxy, "proxy", "", "Proxy contract address")
	flags.MarkFlagsAsRequired(cmd, "admin", "proxy")
}

func init() {
	BindChangeAdminFlags(changeAdminCmd)
}

func ValidateChangeAdminFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Admin) {
		return fmt.Errorf("invalid admin address %s", Admin)
	}
	if !common.IsHexAddress(Proxy) {
		return fmt.Errorf("invalid proxy address %s", Proxy)
	}
	return nil
}

func ProcessChangeAdminFlags(cmd *cobra.Command, args []string) {
	AdminAddr = common.HexToAddress(Admin)
	ProxyAddr = common.HexToAddress(Proxy)
}

func ChangeAdminEVMCMD(cmd *cobra.Command, args []string, contract *proxy.ProxyContract) error {
	log.Debug().Msgf(`
Change admin
Admin address: %s
Proxy address: %s
`, Admin, Proxy)
	_, err := contract.ChangeAdmin(AdminAddr, transactor.TransactOptions{GasLimit: gasLimit})
	return err
}
