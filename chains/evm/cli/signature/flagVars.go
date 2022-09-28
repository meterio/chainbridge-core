package signature

import (
	"math/big"

	"github.com/ChainSafe/chainbridge-core/crypto/secp256k1"
	"github.com/ChainSafe/chainbridge-core/types"
	"github.com/ethereum/go-ethereum/common"
)

//flag vars
var (
	Bridge             string
	Signature          string
	DataHash           string
	DomainID           uint8
	DestDomainID       uint8
	Data               string
	DepositNonce       uint64
	Handler            string
	ResourceID         string
	Target             string
	Deposit            string
	DepositerOffset    uint64
	Execute            string
	Hash               bool
	TokenContract      string
	Relayer            string
	Admin              string
	SignatureThreshold uint64
	ChainID            uint64
)

//processed flag vars
var (
	BridgeAddr         common.Address
	SignatureAddr      common.Address
	ResourceIdBytesArr types.ResourceID
	HandlerAddr        common.Address
	TargetContractAddr common.Address
	TokenContractAddr  common.Address
	DepositSigBytes    [4]byte
	ExecuteSigBytes    [4]byte
	DataBytes          []byte
	RelayerAddr        common.Address
	AdminAddr          common.Address
	DepositHash        [32]byte
)

// global flags
var (
	url           string
	gasLimit      uint64
	gasPrice      *big.Int
	senderKeyPair *secp256k1.Keypair
	prepare       bool
)
