package admin

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/meterio/chainbridge-core/chains/evm/calls/consts"
	"github.com/meterio/chainbridge-core/chains/evm/calls/contracts/bridge"
	"github.com/meterio/chainbridge-core/chains/evm/calls/contracts/signatures"
	"github.com/meterio/chainbridge-core/chains/evm/calls/evmclient"
	"github.com/meterio/chainbridge-core/chains/evm/calls/evmtransaction"
	"github.com/meterio/chainbridge-core/chains/evm/calls/transactor"
	"github.com/meterio/chainbridge-core/chains/evm/cli/flags"
	"github.com/meterio/chainbridge-core/chains/evm/cli/initialize"
	"github.com/meterio/chainbridge-core/chains/evm/cli/logger"
	"github.com/meterio/chainbridge-core/relayer/message"
	"github.com/meterio/chainbridge-core/util"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var processProposalCmd = &cobra.Command{
	Use:   "process-proposal",
	Short: "Process the proposal",
	Long:  "The process-proposal subcommand get proposal from src/relay chain, and submit to dest chain",
	PreRun: func(cmd *cobra.Command, args []string) {
		logger.LoggerMetadata(cmd.Name(), cmd.Flags())
	},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return util.CallPersistentPreRun(cmd, args)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		srcClient, err := initialize.InitializeClient(SrcUrl, senderKeyPair)
		if err != nil {
			return err
		}
		srcTransactor, err := initialize.InitializeTransactor(gasPrice, evmtransaction.NewTransaction, srcClient, prepare)
		if err != nil {
			return err
		}

		relayClient, err := initialize.InitializeClient(RelayUrl, senderKeyPair)
		if err != nil {
			return err
		}
		relayTransactor, err := initialize.InitializeTransactor(gasPrice, evmtransaction.NewTransaction, relayClient, prepare)
		if err != nil {
			return err
		}

		destClient, err := initialize.InitializeClient(DestUrl, senderKeyPair)
		if err != nil {
			return err
		}
		destTransactor, err := initialize.InitializeTransactor(gasPrice, evmtransaction.NewTransaction, destClient, prepare)
		if err != nil {
			return err
		}

		return ProcessProposalCMD(cmd, args, srcClient, bridge.NewBridgeContract(srcClient, SrcBridgeAddr, srcTransactor), signatures.NewSignaturesContract(relayClient, SignatureAddr, relayTransactor), bridge.NewBridgeContract(destClient, DestBridgeAddr, destTransactor))
	},
	Args: func(cmd *cobra.Command, args []string) error {
		err := ValidateProcessProposalFlags(cmd, args)
		if err != nil {
			return err
		}

		ProcessProcessProposalFlags(cmd, args)
		return nil
	},
}

func BindProposalLogicFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&SrcBridge, "src-bridge", "", "Src Bridge contract address")
	cmd.Flags().StringVar(&DestBridge, "dest-bridge", "", "Dest Bridge contract address")
	cmd.Flags().StringVar(&Signature, "signature", "", "Relay Signature contract address")

	cmd.Flags().StringVar(&SrcUrl, "src-url", "", "src rpc url")
	cmd.Flags().StringVar(&DestUrl, "dest-url", "", "dest rpc url")
	cmd.Flags().StringVar(&RelayUrl, "relay-url", "", "relay rpc url")

	cmd.Flags().Uint8Var(&DomainID, "domain", 0, "Src domainID")
	cmd.Flags().StringVar(&TxID, "txid", "", "Src TxID")
	cmd.Flags().BoolVar(&Submit, "submit", false, "submit relayChain signatures to destChain")

	flags.MarkFlagsAsRequired(cmd, "src-bridge", "dest-bridge", "signature", "src-url", "dest-url", "relay-url", "domain", "txid")
}

func init() {
	BindProposalLogicFlags(processProposalCmd)
}

func ValidateProcessProposalFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(SrcBridge) {
		return fmt.Errorf("invalid bridge address %s", SrcBridge)
	}
	if !common.IsHexAddress(DestBridge) {
		return fmt.Errorf("invalid bridge address %s", DestBridge)
	}
	if !common.IsHexAddress(Signature) {
		return fmt.Errorf("invalid bridge address %s", Signature)
	}
	return nil
}

func ProcessProcessProposalFlags(cmd *cobra.Command, args []string) {
	SrcBridgeAddr = common.HexToAddress(SrcBridge)
	DestBridgeAddr = common.HexToAddress(DestBridge)
	SignatureAddr = common.HexToAddress(Signature)

	TxHash = common.HexToHash(TxID)
}

func ProcessProposalCMD(cmd *cobra.Command, args []string, srcClient *evmclient.EVMClient, _ *bridge.BridgeContract, relayContract *signatures.SignaturesContract, destContract *bridge.BridgeContract) error {
	//client := srcContract.Client()
	log.Info().Msg("hello")
	receipt, err := srcClient.WaitAndReturnTxReceipt(TxHash)
	if err != nil {
		log.Error().Err(err)
		log.Info().Msg("2222222222222")
		return err
	}

	tx, _, err := srcClient.TransactionByHash(context.Background(), receipt.TxHash)
	if err != nil {
		log.Info().Msg("3333333333")
		log.Error().Err(err)
		return err
	}

	toAddr := tx.To()
	if strings.ToLower(toAddr.String()) != strings.ToLower(SrcBridge) {
		log.Info().Msg("4444")
		log.Warn().Err(errors.New("src-bridge not match tx to addr"))
		return nil
	}

	abiInst, err := abi.JSON(strings.NewReader(consts.BridgeABI))
	if err != nil {
		log.Info().Msg("555555555555555")
		log.Error().Err(err)
		return err
	}

	for _, l := range receipt.Logs {
		dl, err := UnpackDepositEventLog(abiInst, l.Data)
		if err != nil {
			log.Info().Msg("6666666666")
			log.Error().Err(err)

			continue
		}
		log.Debug().Msgf("Found deposit log in block: %d, TxHash: %s, contractAddress: %s", l.BlockNumber, l.TxHash, l.Address)

		DestDomainID := dl.DestinationDomainID
		ResourceIdBytesArr := dl.ResourceID
		DepositNonce = dl.DepositNonce
		DataBytes := dl.Data

		signaturesArr, err := relayContract.GetSignatures(DomainID, DestDomainID, DepositNonce, ResourceIdBytesArr, DataBytes)
		if err != nil {
			log.Info().Msg("777777777777")
			log.Error().Err(err)
			return err
		}
		log.Info().Msg("Signatures:")
		for _, signature := range signaturesArr {
			log.Info().Msgf("%#x", signature)
		}

		threshold, err := relayContract.GetThreshold(DestDomainID)
		if err != nil {
			log.Error().Err(err)
			log.Info().Msg("8888888888")
			return err
		}
		log.Info().Msgf("Threshold: %v", threshold)

		if len(signaturesArr) >= int(threshold) {
			pps, err := destContract.GetProposal(DomainID, DepositNonce, ResourceIdBytesArr, DataBytes)
			if err != nil {
				log.Error().Err(err)
				return err
			}
			log.Info().Msgf("Proposal status: %v", message.StatusMap[pps.Status])

			if Submit {
				if pps.Status != message.ProposalStatusInactive && pps.Status != message.ProposalStatusActive {
					log.Warn().Msgf("status %v can not VoteProposals, skipped", message.StatusMap[pps.Status])
					continue
				}

				h, err := destContract.VoteProposals(DomainID, DepositNonce, ResourceIdBytesArr, DataBytes, signaturesArr, transactor.TransactOptions{})
				if err != nil {
					log.Error().Err(err)
					return err
				}
				log.Info().Msgf("txHash %v", h.String())
			}
		}
	}

	return nil
}

func UnpackDepositEventLog(abi abi.ABI, data []byte) (*evmclient.DepositLogs, error) {
	var dl evmclient.DepositLogs

	err := abi.UnpackIntoInterface(&dl, "Deposit", data)
	if err != nil {
		return &evmclient.DepositLogs{}, err
	}

	return &dl, nil
}
