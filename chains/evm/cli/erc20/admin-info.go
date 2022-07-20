package erc20

import (
	"fmt"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/contracts/erc20"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/evmtransaction"
	"github.com/ChainSafe/chainbridge-core/chains/evm/cli/flags"
	"github.com/ChainSafe/chainbridge-core/chains/evm/cli/initialize"
	"github.com/ChainSafe/chainbridge-core/chains/evm/cli/logger"
	"github.com/ChainSafe/chainbridge-core/util"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var adminInfoCmd = &cobra.Command{
	Use:   "admin-info",
	Short: "Check admin role info",
	Long:  "Check admin role info in an ERC20 contract",
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
		return AdminInfoCmd(cmd, args, erc20.NewERC20Contract(c, Erc20Addr, t))
	},
	Args: func(cmd *cobra.Command, args []string) error {
		err := ValidateAdminInfoFlags(cmd, args)
		if err != nil {
			return err
		}

		ProcessAdminInfoFlags(cmd, args)
		return nil
	},
}

func BindAdminInfoFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&Erc20Address, "contract", "", "ERC20 contract address")
	flags.MarkFlagsAsRequired(cmd, "contract")
}

func init() {
	BindAdminInfoFlags(adminInfoCmd)
}

func ValidateAdminInfoFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Erc20Address) {
		return fmt.Errorf("invalid recipient address %s", Recipient)
	}
	return nil
}

func ProcessAdminInfoFlags(cmd *cobra.Command, args []string) {
	Erc20Addr = common.HexToAddress(Erc20Address)
}

func AdminInfoCmd(cmd *cobra.Command, args []string, contract *erc20.ERC20Contract) error {
	role, err := contract.DefaultAdminRole()
	if err != nil {
		log.Error().Err(fmt.Errorf("failed contract call error: %v", err))
		return err
	}

	count, err := contract.GetRoleMemberCount(role)
	if err != nil {
		log.Error().Err(fmt.Errorf("failed contract call error: %v", err))
		return err
	}

	log.Info().Msgf("[erc20 %x] has %v admin(s).", Erc20Address, count)

	var index int64
	for index = 0; index < count.Int64(); index++ {
		addr, err := contract.GetRoleMember(role, index)
		if err != nil {
			log.Error().Err(fmt.Errorf("failed contract call error: %v", err))
			return err
		}
		log.Info().Msgf("%v: %x", index, addr)
	}

	return nil
}
