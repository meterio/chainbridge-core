package evmclient

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/meterio/chainbridge-core/chains/evm/calls/consts"
	"github.com/meterio/chainbridge-core/config/chain"
	"github.com/meterio/chainbridge-core/crypto/secp256k1"
	"github.com/meterio/chainbridge-core/keystore"
	"github.com/meterio/chainbridge-core/util"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/ethclient/gethclient"
	"github.com/ethereum/go-ethereum/rpc"
	bridgeTypes "github.com/meterio/chainbridge-core/types"
	"github.com/rs/zerolog/log"
)

type EVMClient struct {
	*ethclient.Client
	kp         *secp256k1.Keypair
	gethClient *gethclient.Client
	rpClient   *rpc.Client
	nonce      *big.Int
	nonceLock  sync.Mutex
	endpointMu sync.RWMutex

	moonbeamFinality  bool
	polygonGasStation bool
	endpoint          string
	replica           string
}

const (
	endpointDialTimeout = 10 * time.Second
	defaultRPCTimeout   = 30 * time.Second
)

func rpcTimeoutContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	if _, ok := parent.Deadline(); ok {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, defaultRPCTimeout)
}

func (c *EVMClient) endpointURL() string {
	c.endpointMu.RLock()
	defer c.endpointMu.RUnlock()

	if c.endpoint == "" {
		return "<unknown>"
	}
	return c.endpoint
}

func (c *EVMClient) rpcError(method string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		endpoint := c.endpointURL()
		log.Warn().Str("rpc", method).Str("endpoint", endpoint).Err(err).Msg("RPC request timed out")
		return fmt.Errorf("RPC %s timed out endpoint=%s: %w", method, endpoint, err)
	}
	return err
}

// DepositLogs struct holds event data with all necessary parameters and a handler response
// https://github.com/ChainSafe/chainbridge-solidity/blob/develop/contracts/Bridge.sol#L47
type DepositLogs struct {
	// ID of chain deposit will be bridged to
	DestinationDomainID uint8
	// ResourceID used to find address of handler to be used for deposit
	ResourceID bridgeTypes.ResourceID
	// Nonce of deposit
	DepositNonce uint64
	// Address of sender (msg.sender: user)
	SenderAddress common.Address
	// Additional data to be passed to specified handler
	Data []byte
	// ERC20Handler: responds with empty data
	// ERC721Handler: responds with deposited token metadata acquired by calling a tokenURI method in the token contract
	// GenericHandler: responds with the raw bytes returned from the call to the target contract
	HandlerResponse []byte

	BlockHash   common.Hash
	BlockNumber uint64
}

type ProposalEvents struct {
	OriginDomainID uint8
	DepositNonce   uint64
	Status         uint8 // ProposalStatus
	DataHash       [32]byte
}

type SignaturePass struct {
	OriginDomainID      uint8
	DestinationDomainID uint8
	DepositNonce        uint64
	ResourceID          [32]byte
	Data                []byte
	Signature           []byte
}

func (s SignaturePass) String() string {
	return fmt.Sprintf("SignaturePass(%v->%v:%v) resourceID:%x",
		s.OriginDomainID, s.DestinationDomainID, s.DepositNonce, hex.EncodeToString(s.ResourceID[:]))
}

type CommonTransaction interface {
	// Hash returns the transaction hash.
	Hash() common.Hash

	// RawWithSignature Returns signed transaction by provided private key
	RawWithSignature(key *ecdsa.PrivateKey, domainID *big.Int) ([]byte, error)
}

// NewEVMClientFromParams creates a client for EVMChain with provided
// private key.
func NewEVMClientFromParams(url string, privateKey *ecdsa.PrivateKey) (*EVMClient, error) {
	ctx, cancel := context.WithTimeout(context.Background(), endpointDialTimeout)
	defer cancel()

	rpcClient, err := rpc.DialContext(ctx, url)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("RPC dial timed out after %s endpoint=%s: %w", endpointDialTimeout, url, err)
		}
		return nil, err
	}
	c := &EVMClient{}
	c.Client = ethclient.NewClient(rpcClient)
	c.gethClient = gethclient.New(rpcClient)
	c.rpClient = rpcClient
	c.kp = secp256k1.NewKeypair(*privateKey)
	c.endpoint = url
	return c, nil
}

// NewEVMClient creates a client for EVM chain configured with specified config.
// Private key is chosen by 'from' param in chain config that matches filename inside keystore path.
func NewEVMClient(cfg *chain.EVMConfig) (*EVMClient, error) {
	c := &EVMClient{}
	generalConfig := cfg.GeneralChainConfig

	kp, err := keystore.KeypairFromAddress(generalConfig.From, keystore.EthChain, generalConfig.KeystorePath, generalConfig.Insecure)
	if err != nil {
		return c, err
	}
	krp := kp.(*secp256k1.Keypair)
	c.kp = krp

	ctx, cancel := context.WithTimeout(context.Background(), endpointDialTimeout)
	defer cancel()

	rpcClient, err := rpc.DialContext(ctx, generalConfig.Endpoint)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return c, fmt.Errorf("RPC dial timed out after %s endpoint=%s: %w", endpointDialTimeout, generalConfig.Endpoint, err)
		}
		return c, err
	}
	c.Client = ethclient.NewClient(rpcClient)
	c.rpClient = rpcClient
	c.gethClient = gethclient.New(rpcClient)
	c.endpoint = generalConfig.Endpoint
	c.replica = generalConfig.Replica
	c.moonbeamFinality = cfg.MoonbeamFinality
	c.polygonGasStation = cfg.PolygonGasStation

	return c, nil
}

func (c *EVMClient) UpdateEndpoint() (string, error) {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()

	if c.replica == "" {
		return c.endpoint, errors.New("replica no configuration")
	}

	endpoint := c.replica
	replica := c.endpoint

	ctx, cancel := context.WithTimeout(context.Background(), endpointDialTimeout)
	defer cancel()

	rpcClient, err := rpc.DialContext(ctx, endpoint)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return replica, fmt.Errorf("RPC dial timed out after %s endpoint=%s: %w", endpointDialTimeout, endpoint, err)
		}
		return replica, err
	}
	c.Client = ethclient.NewClient(rpcClient)
	c.rpClient = rpcClient
	c.gethClient = gethclient.New(rpcClient)

	c.endpoint = endpoint
	c.replica = replica

	return endpoint, err
}

func (c *EVMClient) SubscribePendingTransactions(ctx context.Context, ch chan<- common.Hash) (*rpc.ClientSubscription, error) {
	return c.gethClient.SubscribePendingTransactions(ctx, ch)
}

// LatestBlock returns the latest block from the current chain
func (c *EVMClient) LatestBlock() (*big.Int, error) {
	if c.moonbeamFinality == true {
		return c.LatestFinalizedBlock()
	}

	var head *headerNumber
	ctx, cancel := rpcTimeoutContext(context.Background())
	defer cancel()

	err := c.rpClient.CallContext(ctx, &head, "eth_getBlockByNumber", toBlockNumArg(nil), false)
	if err == nil && head == nil {
		err = ethereum.NotFound
	}
	if err != nil {
		return nil, c.rpcError("eth_getBlockByNumber", err)
	}
	return head.Number, nil
}

func (c *EVMClient) LatestFinalizedBlock() (*big.Int, error) {
	var raw json.RawMessage
	ctx, cancel := rpcTimeoutContext(context.Background())
	defer cancel()

	err := c.rpClient.CallContext(ctx, &raw, "chain_getFinalizedHead")
	if err != nil {
		return nil, c.rpcError("chain_getFinalizedHead", err)
	}

	// The hash is with double quote "", should remove
	var blockHash string = string(raw)
	blockHash = blockHash[1 : len(blockHash)-1]
	//fmt.Println(blockHash)
	err = c.rpClient.CallContext(ctx, &raw, "chain_getHeader", blockHash)
	if err != nil {
		return nil, c.rpcError("chain_getHeader", err)
	}

	var m map[string]interface{}
	if err = json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("body: empty body")
	}

	/***
	for k, v := range m {
		fmt.Println("decoding", k, v)
	}
	***/
	number := m["number"].(string)
	// remove 0x
	number = number[2:]
	num, ok := new(big.Int).SetString(number, 16)
	if ok != true {
		return nil, err
	}
	return num, nil
}

type headerNumber struct {
	Number *big.Int `json:"number"           gencodec:"required"`
}

func (h *headerNumber) UnmarshalJSON(input []byte) error {
	type headerNumber struct {
		Number *hexutil.Big `json:"number" gencodec:"required"`
	}
	var dec headerNumber
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if dec.Number == nil {
		return errors.New("missing required field 'number' for Header")
	}
	h.Number = (*big.Int)(dec.Number)
	return nil
}

func (c *EVMClient) WaitAndReturnTxReceipt(h common.Hash) (*types.Receipt, error) {
	retry := 50
	for retry > 0 {
		if retry < 50 {
			fmt.Printf(`retry #%d to fetch tx receipt: %v
`, 50-retry, h)
		}
		ctx, cancel := rpcTimeoutContext(context.Background())
		receipt, err := c.Client.TransactionReceipt(ctx, h)
		cancel()
		if err != nil {
			err = c.rpcError("eth_getTransactionReceipt", err)
			retry--
			fmt.Printf(`error fetching tx receipt: %v, %v, sleep for 5s
`, h, err)
			time.Sleep(5 * time.Second)
			continue
		}
		if receipt.Status != 1 {
			return receipt, fmt.Errorf("transaction failed on chain. Receipt status %v", receipt.Status)
		}
		return receipt, nil
	}
	return nil, errors.New("tx did not appear")
}

func (c *EVMClient) UpdateNonce() {
	c.LockNonce()
	defer c.UnlockNonce()

	ctx, cancel := rpcTimeoutContext(context.Background())
	defer cancel()

	nonce, err := c.PendingNonceAt(ctx, c.kp.CommonAddress())
	if err != nil {
		log.Warn().Err(c.rpcError("eth_getTransactionCount", err)).Msg("Unable to update nonce")
		return
	}

	c.nonce.SetUint64(nonce)
}

func (c *EVMClient) GetTransactionByHash(h common.Hash) (tx *types.Transaction, isPending bool, err error) {
	ctx, cancel := rpcTimeoutContext(context.Background())
	defer cancel()

	tx, isPending, err = c.Client.TransactionByHash(ctx, h)
	return tx, isPending, c.rpcError("eth_getTransactionByHash", err)
}

func (c *EVMClient) FetchDepositLogs(ctx context.Context, contractAddress common.Address, startBlock *big.Int, endBlock *big.Int) ([]*DepositLogs, error) {
	ctx, cancel := rpcTimeoutContext(ctx)
	defer cancel()

	logs, err := c.FilterLogs(ctx, buildQuery(contractAddress, string(util.Deposit), startBlock, endBlock))
	if err != nil {
		return nil, c.rpcError("eth_getLogs", err)
	}
	depositLogs := make([]*DepositLogs, 0)

	abi, err := abi.JSON(strings.NewReader(consts.BridgeABI))
	if err != nil {
		return nil, err
	}

	for _, l := range logs {
		dl, err := c.UnpackDepositEventLog(abi, l.Data)
		dl.BlockNumber = l.BlockNumber
		dl.BlockHash = l.BlockHash
		if err != nil {
			log.Error().Msgf("failed unpacking deposit event log: %v", err)
			continue
		}
		log.Debug().Msgf("Found deposit log in block: %d, TxHash: %s, contractAddress: %s, sender: %s", l.BlockNumber, l.TxHash, l.Address, dl.SenderAddress)

		depositLogs = append(depositLogs, dl)
	}

	return depositLogs, nil
}

func (c *EVMClient) UnpackDepositEventLog(abi abi.ABI, data []byte) (*DepositLogs, error) {
	var dl DepositLogs

	err := abi.UnpackIntoInterface(&dl, "Deposit", data)
	if err != nil {
		return &DepositLogs{}, err
	}

	return &dl, nil
}

func (c *EVMClient) FetchEventLogs(ctx context.Context, contractAddress common.Address, event string, startBlock *big.Int, endBlock *big.Int) ([]types.Log, error) {
	ctx, cancel := rpcTimeoutContext(ctx)
	defer cancel()

	logs, err := c.FilterLogs(ctx, buildQuery(contractAddress, event, startBlock, endBlock))
	return logs, c.rpcError("eth_getLogs", err)
}

// SendRawTransaction accepts rlp-encode of signed transaction and sends it via RPC call
func (c *EVMClient) SendRawTransaction(ctx context.Context, tx []byte) error {
	ctx, cancel := rpcTimeoutContext(ctx)
	defer cancel()

	err := c.rpClient.CallContext(ctx, nil, "eth_sendRawTransaction", hexutil.Encode(tx))
	return c.rpcError("eth_sendRawTransaction", err)
}

func (c *EVMClient) CallContract(ctx context.Context, callArgs map[string]interface{}, blockNumber *big.Int) ([]byte, error) {
	ctx, cancel := rpcTimeoutContext(ctx)
	defer cancel()

	var hex hexutil.Bytes
	err := c.rpClient.CallContext(ctx, &hex, "eth_call", callArgs, toBlockNumArg(blockNumber))
	if err != nil {
		return nil, c.rpcError("eth_call", err)
	}
	return hex, nil
}

func (c *EVMClient) CallContext(ctx context.Context, target interface{}, rpcMethod string, args ...interface{}) error {
	ctx, cancel := rpcTimeoutContext(ctx)
	defer cancel()

	err := c.rpClient.CallContext(ctx, target, rpcMethod, args...)
	if err != nil {
		return c.rpcError(rpcMethod, err)
	}
	return nil
}

func (c *EVMClient) PendingCallContract(ctx context.Context, callArgs map[string]interface{}) ([]byte, error) {
	ctx, cancel := rpcTimeoutContext(ctx)
	defer cancel()

	var hex hexutil.Bytes
	err := c.rpClient.CallContext(ctx, &hex, "eth_call", callArgs, "pending")
	if err != nil {
		return nil, c.rpcError("eth_call", err)
	}
	return hex, nil
}

func (c *EVMClient) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	ctx, cancel := rpcTimeoutContext(ctx)
	defer cancel()

	price, err := c.Client.SuggestGasPrice(ctx)
	return price, c.rpcError("eth_gasPrice", err)
}

func (c *EVMClient) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	ctx, cancel := rpcTimeoutContext(ctx)
	defer cancel()

	tipCap, err := c.Client.SuggestGasTipCap(ctx)
	return tipCap, c.rpcError("eth_maxPriorityFeePerGas", err)
}

func (c *EVMClient) CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error) {
	ctx, cancel := rpcTimeoutContext(ctx)
	defer cancel()

	code, err := c.Client.CodeAt(ctx, account, blockNumber)
	return code, c.rpcError("eth_getCode", err)
}

func (c *EVMClient) From() common.Address {
	return c.kp.CommonAddress()
}

func (c *EVMClient) SignAndSendTransaction(ctx context.Context, tx CommonTransaction) (common.Hash, error) {
	ctx, cancel := rpcTimeoutContext(ctx)
	defer cancel()

	id, err := c.ChainID(ctx)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return common.Hash{}, c.rpcError("eth_chainId", err)
		}
		//panic(err)
		// Probably chain does not support chainID eg. CELO
		id = nil
	}
	rawTx, err := tx.RawWithSignature(c.kp.PrivateKey(), id)
	if err != nil {
		return common.Hash{}, err
	}
	chainID := "<nil>"
	if id != nil {
		chainID = id.String()
	}
	log.Debug().Str("chain", chainID).Str("signer", c.kp.Address()).Msgf("build tx hash %v", tx.Hash())

	err = c.SendRawTransaction(ctx, rawTx)
	if err != nil {
		return common.Hash{}, err
	}
	return tx.Hash(), nil
}

func (c *EVMClient) Sign(byteData []byte) ([]byte, error) {
	log.Debug().Msgf("EVMClient instance PublicKey %v do Sign %x", c.kp.PublicKey(), byteData)
	return crypto.Sign(byteData, c.kp.PrivateKey())
}

func (c *EVMClient) RelayerAddress() common.Address {
	return c.kp.CommonAddress()
}

func (c *EVMClient) LockNonce() {
	c.nonceLock.Lock()
}

func (c *EVMClient) UnlockNonce() {
	c.nonceLock.Unlock()
}

func (c *EVMClient) UnsafeNonce() (*big.Int, error) {
	var err error
	for i := 0; i <= 10; i++ {
		//if c.nonce == nil {
		ctx, cancel := rpcTimeoutContext(context.Background())
		nonce, err := c.PendingNonceAt(ctx, c.kp.CommonAddress())
		cancel()
		if err != nil {
			err = c.rpcError("eth_getTransactionCount", err)
			time.Sleep(1 * time.Second)
			continue
		}
		c.nonce = big.NewInt(0).SetUint64(nonce)
		return c.nonce, nil
		//}
		//return c.nonce, nil
	}
	return nil, err
}

func (c *EVMClient) UnsafeIncreaseNonce() error {
	nonce, err := c.UnsafeNonce()
	if err != nil {
		return err
	}
	c.nonce = nonce.Add(nonce, big.NewInt(1))
	return nil
}

func (c *EVMClient) BaseFee() (*big.Int, error) {
	ctx, cancel := rpcTimeoutContext(context.Background())
	defer cancel()

	head, err := c.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, c.rpcError("eth_getBlockByNumber", err)
	}
	return head.BaseFee, nil
}

func (c *EVMClient) PolygonGasStation() bool {
	return c.polygonGasStation
}

func toBlockNumArg(number *big.Int) string {
	if number == nil {
		return "latest"
	}
	return hexutil.EncodeBig(number)
}

// buildQuery constructs a query for the bridgeContract by hashing sig to get the event topic
func buildQuery(contract common.Address, sig string, startBlock *big.Int, endBlock *big.Int) ethereum.FilterQuery {
	query := ethereum.FilterQuery{
		FromBlock: startBlock,
		ToBlock:   endBlock,
		Addresses: []common.Address{contract},
		Topics: [][]common.Hash{
			{crypto.Keccak256Hash([]byte(sig))},
		},
	}
	return query
}

// EnsureHasBytecode asserts if contract code exists at the specified address
func (c *EVMClient) EnsureHasBytecode(addr common.Address) error {
	ctx, cancel := rpcTimeoutContext(context.Background())
	defer cancel()

	code, err := c.CodeAt(ctx, addr, nil)
	if err != nil {
		return err
	}

	if len(code) == 0 {
		return fmt.Errorf("no bytecode found at %s", addr.Hex())
	}
	return nil
}

var (
	DomainIdMappingEVMClient = make(map[uint8]*EVMClient)
	errCounterMu             sync.Mutex
)

func RegisterEVMClient(domainID uint8, client *EVMClient) {
	errCounterMu.Lock()
	defer errCounterMu.Unlock()

	DomainIdMappingEVMClient[domainID] = client
}

func (c *EVMClient) PrivateKey() *ecdsa.PrivateKey {
	return c.kp.PrivateKey()
}

func ErrCounterLogic(errStr string, domainId uint8) {
	if strings.Contains(errStr, consts.ErrNonceTooLow) || strings.Contains(errStr, consts.ErrTxUnderpriced) {
		return
	}

	timeNow := time.Now().Unix()
	var newErrCounterArr [consts.DefaultEndpointTries]int64
	var evmClient *EVMClient
	shouldSwitch := false

	errCounterMu.Lock()

	if errCounterArr, ok := util.DomainIdMappingErrCounter[domainId]; ok {
		errCounterSlice := append(errCounterArr[1:], timeNow)
		copy(newErrCounterArr[:], errCounterSlice[:])

		util.DomainIdMappingErrCounter[domainId] = newErrCounterArr

		fiveMinutesAgo := timeNow - 5*60
		if newErrCounterArr[0] >= fiveMinutesAgo {
			evmClient = DomainIdMappingEVMClient[domainId]
			util.DomainIdMappingErrCounter[domainId] = [consts.DefaultEndpointTries]int64{}
			shouldSwitch = true
		}
	} else {
		newErrCounterArr[consts.DefaultEndpointTries-1] = timeNow
		util.DomainIdMappingErrCounter[domainId] = newErrCounterArr
	}
	errCounterMu.Unlock()

	if !shouldSwitch {
		return
	}
	if evmClient == nil {
		log.Warn().Str("chain", util.DomainIdToName[domainId]).Uint8("domainID", domainId).Msg("Unable to switch endpoint: EVM client is not registered")
		return
	}

	if endpoint, err := evmClient.UpdateEndpoint(); err != nil {
		log.Warn().Str("chain", util.DomainIdToName[domainId]).Str("endpoint", endpoint).Err(err).Msg("Switch replica")
	} else {
		log.Info().Str("chain", util.DomainIdToName[domainId]).Msgf("Switch endpoint to %v", endpoint)
	}
}
