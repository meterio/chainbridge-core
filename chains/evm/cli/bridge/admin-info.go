package bridge

import (
	"fmt"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/contracts/bridge"
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
		return AdminInfoCmd(cmd, args, bridge.NewBridgeContract(c, BridgeAddr, t))
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
	cmd.Flags().StringVar(&Bridge, "bridge", "", "Bridge contract address")
	flags.MarkFlagsAsRequired(cmd, "bridge")
}

func init() {
	BindAdminInfoFlags(adminInfoCmd)
}

func ValidateAdminInfoFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Bridge) {
		return fmt.Errorf("invalid Bridge address %s", Bridge)
	}
	return nil
}

func ProcessAdminInfoFlags(cmd *cobra.Command, args []string) {
	BridgeAddr = common.HexToAddress(Bridge)
}

func AdminInfoCmd(cmd *cobra.Command, args []string, contract *bridge.BridgeContract) error {
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

	log.Info().Msgf("[Bridge %x] has %v admin(s).", Bridge, count)

	var index int64
	for index = 0; index < count.Int64(); index++ {
		addr, err := contract.GetRoleMember(role, index)
		if err != nil {
			log.Error().Err(fmt.Errorf("failed contract call error: %v", err))
			return err
		}
		log.Info().Msgf("%v: %#x", index, addr)
	}

	return nil
}
